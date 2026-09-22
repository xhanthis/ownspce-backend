// Package linkpreview fetches the title, description and images a web page
// advertises about itself, so a pasted link can be drawn as a card.
//
// The server fetches on the client's behalf because a browser cannot read
// another origin's HTML. That makes this the one place the API is asked to
// open an address a user typed, and everything below is shaped by that: the
// address is never logged or stored, only http(s) on the default ports is
// dialled, every connection is checked against the resolved IP at dial time so
// a hostname that points at this network — or changes its mind between lookup
// and connect — never reaches it, and the response is read only as far as the
// page's head needs.
package linkpreview

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
	"time"
	"unicode"

	"golang.org/x/net/html"
	"golang.org/x/net/html/charset"
)

// Preview is what a page says about itself, resolved to absolute addresses.
// Empty strings mean the page did not say.
type Preview struct {
	URL         string `json:"url"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Image       string `json:"image"`
	SiteName    string `json:"siteName"`
	Icon        string `json:"icon"`
}

var (
	// ErrBadURL: the address is not an http(s) URL this fetcher will open.
	ErrBadURL = errors.New("linkpreview: not a fetchable http(s) url")
	// ErrBlockedHost: the address resolves somewhere this server must not reach.
	ErrBlockedHost = errors.New("linkpreview: host is not public")
	// ErrNotHTML: the address answered, but not with a web page.
	ErrNotHTML = errors.New("linkpreview: response is not html")
	// ErrUnreachable: the address did not answer, or answered with an error.
	ErrUnreachable = errors.New("linkpreview: page could not be fetched")
)

const (
	// maxBody bounds how much of a page is read: metadata lives in the head,
	// and a page whose head is bigger than this is not worth a card.
	maxBody = 512 << 10
	// maxRedirects is generous enough for a short link that bounces through a
	// tracker to its destination, and no more.
	maxRedirects   = 3
	maxTitle       = 200
	maxDescription = 500
	maxURLLength   = 2048
	userAgent      = "Mozilla/5.0 (compatible; Ownspce/1.0; +https://ownspce.com)"
)

// Fetcher opens pages on behalf of signed-in users. One per server.
type Fetcher struct {
	client *http.Client
	// allowLocal lets tests reach a loopback server on a random port. It is
	// never set in production, where the address policy is the whole point.
	allowLocal bool
}

// New builds a fetcher with the production address policy.
func New() *Fetcher {
	return newFetcher(false)
}

// NewUnsafeForTests builds a fetcher that will dial loopback on any port, so a
// test can stand up httptest servers. Nothing outside a _test file may call it.
func NewUnsafeForTests() *Fetcher {
	return newFetcher(true)
}

func newFetcher(allowLocal bool) *Fetcher {
	f := &Fetcher{allowLocal: allowLocal}
	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
		Control: f.vetDial,
	}
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            dialer.DialContext,
		TLSHandshakeTimeout:    5 * time.Second,
		ResponseHeaderTimeout:  5 * time.Second,
		MaxResponseHeaderBytes: 64 << 10,
		DisableKeepAlives:      true,
		ForceAttemptHTTP2:      true,
	}
	f.client = &http.Client{
		Transport: transport,
		Timeout:   8 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > maxRedirects {
				return ErrUnreachable
			}
			if err := checkURL(req.URL, allowLocal); err != nil {
				return err
			}
			return nil
		},
	}
	return f
}

// Fetch reads the page at raw and returns what it advertises about itself.
// Args: ctx, raw (the address as the user typed it)
// Returns: the preview, or ErrBadURL, ErrBlockedHost, ErrNotHTML, ErrUnreachable
// Handles: bare "www.example.com" (given https), redirects (each hop vetted),
// relative image and icon addresses, legacy charsets, oversized pages
func (f *Fetcher) Fetch(ctx context.Context, raw string) (*Preview, error) {
	target, err := parseTarget(raw, f.allowLocal)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, ErrBadURL
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1")
	req.Header.Set("Accept-Language", "en")

	resp, err := f.client.Do(req)
	if err != nil {
		if errors.Is(err, ErrBlockedHost) || errors.Is(err, ErrBadURL) {
			return nil, ErrBlockedHost
		}
		return nil, ErrUnreachable
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, ErrUnreachable
	}
	contentType := resp.Header.Get("Content-Type")
	mediaType := strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	if mediaType != "text/html" && mediaType != "application/xhtml+xml" {
		return nil, ErrNotHTML
	}

	body, err := charset.NewReader(io.LimitReader(resp.Body, maxBody), contentType)
	if err != nil {
		return nil, ErrNotHTML
	}

	final := resp.Request.URL
	preview := extract(body, final)
	preview.URL = target.String()
	return preview, nil
}

// parseTarget turns typed text into the URL that will be fetched.
// Args: raw, allowLocal
// Returns: the URL, or ErrBadURL / ErrBlockedHost
// Handles: missing scheme (https assumed), surrounding whitespace, and the
// fragment, which is dropped because a server never sees it anyway
func parseTarget(raw string, allowLocal bool) (*url.URL, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || len(trimmed) > maxURLLength || strings.ContainsAny(trimmed, " \t\r\n") {
		return nil, ErrBadURL
	}
	if !strings.Contains(trimmed, "://") {
		trimmed = "https://" + trimmed
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return nil, ErrBadURL
	}
	parsed.Fragment = ""
	if err := checkURL(parsed, allowLocal); err != nil {
		return nil, err
	}
	return parsed, nil
}

// checkURL applies the address policy to a URL before it is dialled: http(s)
// only, a hostname, no credentials, and only the default ports.
func checkURL(u *url.URL, allowLocal bool) error {
	if u.Scheme != "http" && u.Scheme != "https" {
		return ErrBadURL
	}
	if u.User != nil || u.Hostname() == "" {
		return ErrBadURL
	}
	if allowLocal {
		return nil
	}
	if port := u.Port(); port != "" && port != "80" && port != "443" {
		return ErrBlockedHost
	}
	if ip, err := netip.ParseAddr(strings.Trim(u.Hostname(), "[]")); err == nil && !publicAddr(ip) {
		return ErrBlockedHost
	}
	if host := strings.ToLower(u.Hostname()); host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal") {
		return ErrBlockedHost
	}
	return nil
}

// vetDial runs after DNS resolution and before the socket connects, with the
// literal address about to be dialled. Checking here rather than at parse time
// is what defeats a name that resolves to a public address once and a private
// one the next time.
func (f *Fetcher) vetDial(network, address string, _ syscall.RawConn) error {
	if f.allowLocal {
		return nil
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return ErrBlockedHost
	}
	if port != "80" && port != "443" {
		return ErrBlockedHost
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !publicAddr(ip) {
		return ErrBlockedHost
	}
	return nil
}

var blockedV4 = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

var blockedV6 = []netip.Prefix{
	netip.MustParsePrefix("::/96"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("2001::/32"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
}

// publicAddr reports whether an address is one a link preview may connect to:
// globally routable, and not this machine, this network, or any range that
// carries an IPv4 address inside an IPv6 one.
func publicAddr(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() || ip.IsMulticast() {
		return false
	}
	ranges := blockedV6
	if ip.Is4() {
		ranges = blockedV4
	}
	for _, prefix := range ranges {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}

// extract reads the head of a page for the fields a card is drawn from.
// Args: body (decoded to UTF-8), base (the page's final address, for relative links)
// Returns: a preview with every address absolute; icon falls back to /favicon.ico
// Handles: Open Graph over Twitter over plain <title>/<meta description>, an
// <icon> before an apple-touch-icon, and reading stops at <body>
func extract(body io.Reader, base *url.URL) *Preview {
	var (
		ogTitle, twTitle, plainTitle, ogDesc, twDesc, plainDesc string
		ogImage, twImage, siteName, icon, appleIcon             string
	)
	z := html.NewTokenizer(body)
	for {
		switch z.Next() {
		case html.ErrorToken:
			return assemble(base, first(ogTitle, twTitle, plainTitle), first(ogDesc, twDesc, plainDesc), first(ogImage, twImage), siteName, first(icon, appleIcon))
		case html.StartTagToken, html.SelfClosingTagToken:
			name, hasAttr := z.TagName()
			switch string(name) {
			case "body":
				return assemble(base, first(ogTitle, twTitle, plainTitle), first(ogDesc, twDesc, plainDesc), first(ogImage, twImage), siteName, first(icon, appleIcon))
			case "title":
				if z.Next() == html.TextToken {
					plainTitle = first(plainTitle, string(z.Text()))
				}
			case "meta":
				if !hasAttr {
					continue
				}
				attrs := attributes(z)
				key := strings.ToLower(first(attrs["property"], attrs["name"]))
				content := attrs["content"]
				if content == "" {
					continue
				}
				switch key {
				case "og:title":
					ogTitle = first(ogTitle, content)
				case "twitter:title":
					twTitle = first(twTitle, content)
				case "og:description":
					ogDesc = first(ogDesc, content)
				case "twitter:description":
					twDesc = first(twDesc, content)
				case "description":
					plainDesc = first(plainDesc, content)
				case "og:image", "og:image:secure_url", "og:image:url":
					ogImage = first(ogImage, content)
				case "twitter:image", "twitter:image:src":
					twImage = first(twImage, content)
				case "og:site_name":
					siteName = first(siteName, content)
				}
			case "link":
				if !hasAttr {
					continue
				}
				attrs := attributes(z)
				href := attrs["href"]
				if href == "" {
					continue
				}
				for _, rel := range strings.Fields(strings.ToLower(attrs["rel"])) {
					switch rel {
					case "icon":
						icon = first(icon, href)
					case "apple-touch-icon", "apple-touch-icon-precomposed":
						appleIcon = first(appleIcon, href)
					}
				}
			}
		}
	}
}

func attributes(z *html.Tokenizer) map[string]string {
	attrs := map[string]string{}
	for {
		key, value, more := z.TagAttr()
		attrs[strings.ToLower(string(key))] = strings.TrimSpace(string(value))
		if !more {
			return attrs
		}
	}
}

func assemble(base *url.URL, title, description, image, siteName, icon string) *Preview {
	preview := &Preview{
		Title:       clean(title, maxTitle),
		Description: clean(description, maxDescription),
		SiteName:    clean(siteName, maxTitle),
		Image:       absolute(base, image),
		Icon:        absolute(base, icon),
	}
	if preview.Icon == "" {
		preview.Icon = base.Scheme + "://" + base.Host + "/favicon.ico"
	}
	return preview
}

// absolute resolves a page-relative address against the page and keeps it only
// when the result is somewhere a browser may load an image from.
func absolute(base *url.URL, raw string) string {
	if raw == "" || len(raw) > maxURLLength {
		return ""
	}
	ref, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	resolved := base.ResolveReference(ref)
	if resolved.Scheme != "http" && resolved.Scheme != "https" {
		return ""
	}
	if resolved.Host == "" {
		return ""
	}
	return resolved.String()
}

// clean collapses whitespace, drops control characters and caps the length, so
// what a page says about itself cannot smuggle line breaks or terminal noise
// into a card.
func clean(raw string, limit int) string {
	var b strings.Builder
	space := false
	for _, r := range raw {
		if unicode.IsSpace(r) {
			space = true
			continue
		}
		if unicode.IsControl(r) || !unicode.IsPrint(r) {
			continue
		}
		if space && b.Len() > 0 {
			b.WriteByte(' ')
		}
		space = false
		b.WriteRune(r)
	}
	out := []rune(b.String())
	if len(out) > limit {
		return strings.TrimSpace(string(out[:limit-1])) + "…"
	}
	return string(out)
}

func first(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
