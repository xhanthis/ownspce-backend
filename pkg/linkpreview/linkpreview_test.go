package linkpreview

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
)

func TestPublicAddrBlocksEverythingThatIsNotTheOpenInternet(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "127.8.8.8", "10.0.0.1", "172.16.5.5", "172.31.255.255", "192.168.1.1",
		"169.254.169.254", "100.64.0.1", "100.127.255.254", "0.0.0.0", "0.1.2.3",
		"224.0.0.1", "240.0.0.1", "255.255.255.255", "192.0.0.1", "198.18.0.1", "192.0.2.1",
		"::1", "::", "fe80::1", "fc00::1", "fd12::1", "ff02::1",
		"::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:169.254.169.254", "::7f00:1",
		"64:ff9b::7f00:1", "2002:7f00:1::1", "2001:0:abcd::1", "2001:db8::1",
	}
	for _, raw := range blocked {
		if publicAddr(netip.MustParseAddr(raw)) {
			t.Errorf("%s should be blocked", raw)
		}
	}
	allowed := []string{"8.8.8.8", "1.1.1.1", "142.250.72.14", "2606:4700::1111", "2a00:1450:4009:81f::200e"}
	for _, raw := range allowed {
		if !publicAddr(netip.MustParseAddr(raw)) {
			t.Errorf("%s should be allowed", raw)
		}
	}
}

func TestParseTargetRejectsWhatMustNeverBeDialled(t *testing.T) {
	cases := map[string]error{
		"":                                    ErrBadURL,
		"   ":                                 ErrBadURL,
		"javascript:alert(1)":                 ErrBadURL,
		"file:///etc/passwd":                  ErrBadURL,
		"ftp://example.com/x":                 ErrBadURL,
		"https://user:pw@example.com/":        ErrBadURL,
		"https://":                            ErrBadURL,
		"https://example.com/a b":             ErrBadURL,
		"http://localhost/":                   ErrBlockedHost,
		"http://api.localhost/":               ErrBlockedHost,
		"http://printer.local/":               ErrBlockedHost,
		"http://db.internal/":                 ErrBlockedHost,
		"http://127.0.0.1/":                   ErrBlockedHost,
		"http://[::1]/":                       ErrBlockedHost,
		"http://169.254.169.254/latest/meta":  ErrBlockedHost,
		"http://example.com:8080/":            ErrBlockedHost,
		"https://example.com:8443/":           ErrBlockedHost,
		"http://[fe80::1%25eth0]/":            ErrBlockedHost,
		"http://" + strings.Repeat("a", 2100): ErrBadURL,
	}
	for raw, want := range cases {
		_, err := parseTarget(raw, false)
		if !errors.Is(err, want) {
			t.Errorf("%q: got %v, want %v", raw, err, want)
		}
	}

	ok := []string{"https://example.com/post?x=1#frag", "example.com", "www.example.com/a/b", "http://example.com:80/", "https://example.com:443/"}
	for _, raw := range ok {
		target, err := parseTarget(raw, false)
		if err != nil {
			t.Errorf("%q: unexpected %v", raw, err)
			continue
		}
		if target.Fragment != "" {
			t.Errorf("%q: fragment should be dropped", raw)
		}
	}
	if target, _ := parseTarget("example.com", false); target.String() != "https://example.com" {
		t.Errorf("bare host should get https, got %s", target)
	}
}

func serve(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return server
}

func page(head string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, "<!doctype html><html><head>%s</head><body><p>hello</p><meta property=\"og:title\" content=\"in the body, ignored\"></body></html>", head)
	}
}

func TestFetchReadsOpenGraphAndResolvesRelativeAddresses(t *testing.T) {
	server := serve(t, page(`
		<title>Plain title</title>
		<meta name="description" content="plain description">
		<meta property="og:title" content="  OG   title &amp; more  ">
		<meta property="og:description" content="OG description">
		<meta property="og:image" content="/images/cover.png">
		<meta property="og:site_name" content="Example">
		<link rel="apple-touch-icon" href="/apple.png">
		<link rel="shortcut icon" href="icons/favicon.png">
	`))

	preview, err := NewUnsafeForTests().Fetch(context.Background(), server.URL+"/posts/one#top")
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	want := Preview{
		URL:         server.URL + "/posts/one",
		Title:       "OG title & more",
		Description: "OG description",
		Image:       server.URL + "/images/cover.png",
		SiteName:    "Example",
		Icon:        server.URL + "/posts/icons/favicon.png",
	}
	if *preview != want {
		t.Errorf("preview = %+v, want %+v", *preview, want)
	}
}

func TestFetchFallsBackToTitleDescriptionAndFavicon(t *testing.T) {
	server := serve(t, page(`<title>Just a title</title><meta name="description" content="from the meta tag">`))

	preview, err := NewUnsafeForTests().Fetch(context.Background(), server.URL+"/")
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if preview.Title != "Just a title" || preview.Description != "from the meta tag" {
		t.Errorf("title/description = %q/%q", preview.Title, preview.Description)
	}
	if preview.Icon != server.URL+"/favicon.ico" {
		t.Errorf("icon = %q, want the site favicon", preview.Icon)
	}
	if preview.Image != "" || preview.SiteName != "" {
		t.Errorf("image/site should be empty, got %q/%q", preview.Image, preview.SiteName)
	}
}

func TestFetchPrefersTwitterCardOverPlainTags(t *testing.T) {
	server := serve(t, page(`
		<title>Plain</title>
		<meta name="twitter:title" content="Twitter title">
		<meta name="twitter:image" content="https://cdn.example.com/card.jpg">
	`))

	preview, err := NewUnsafeForTests().Fetch(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if preview.Title != "Twitter title" || preview.Image != "https://cdn.example.com/card.jpg" {
		t.Errorf("got %+v", *preview)
	}
}

func TestFetchRefusesLoopbackUnderTheProductionPolicy(t *testing.T) {
	server := serve(t, page(`<title>secret admin</title>`))

	_, err := New().Fetch(context.Background(), server.URL)
	if !errors.Is(err, ErrBlockedHost) {
		t.Fatalf("got %v, want ErrBlockedHost", err)
	}
}

func TestFetchRefusesARedirectIntoThisNetwork(t *testing.T) {
	inside := serve(t, page(`<title>metadata</title>`))
	// The first hop is vetted by the test policy; the redirect is checked by the
	// same CheckRedirect production uses, which must still refuse the port.
	bouncer := serve(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, inside.URL+"/latest/meta-data", http.StatusFound)
	})

	f := NewUnsafeForTests()
	f.client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return checkURL(req.URL, false)
	}
	_, err := f.Fetch(context.Background(), bouncer.URL)
	if !errors.Is(err, ErrBlockedHost) {
		t.Fatalf("got %v, want ErrBlockedHost", err)
	}
}

func TestFetchFollowsRedirectsAndResolvesAgainstTheFinalPage(t *testing.T) {
	server := serve(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/short":
			http.Redirect(w, r, "/long/article", http.StatusMovedPermanently)
		case "/long/article":
			page(`<meta property="og:image" content="cover.jpg"><title>Long</title>`)(w, r)
		default:
			http.NotFound(w, r)
		}
	})

	preview, err := NewUnsafeForTests().Fetch(context.Background(), server.URL+"/short")
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if preview.URL != server.URL+"/short" {
		t.Errorf("url should stay what was typed, got %s", preview.URL)
	}
	if preview.Image != server.URL+"/long/cover.jpg" {
		t.Errorf("image = %s, want it resolved against the final page", preview.Image)
	}
}

func TestFetchGivesUpOnARedirectLoop(t *testing.T) {
	server := serve(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/again", http.StatusFound)
	})
	_, err := NewUnsafeForTests().Fetch(context.Background(), server.URL)
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("got %v, want ErrUnreachable", err)
	}
}

func TestFetchRejectsPagesThatAreNotHTMLOrNotOK(t *testing.T) {
	server := serve(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/json":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"title":"nope"}`)
		case "/missing":
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, "<title>Not found</title>")
		}
	})
	if _, err := NewUnsafeForTests().Fetch(context.Background(), server.URL+"/json"); !errors.Is(err, ErrNotHTML) {
		t.Errorf("json: got %v, want ErrNotHTML", err)
	}
	if _, err := NewUnsafeForTests().Fetch(context.Background(), server.URL+"/missing"); !errors.Is(err, ErrUnreachable) {
		t.Errorf("404: got %v, want ErrUnreachable", err)
	}
}

func TestFetchStopsReadingAtTheBodyCapAndCleansWhatItKeeps(t *testing.T) {
	filler := strings.Repeat("<p>padding padding padding</p>\n", 200000)
	longTitle := strings.Repeat("word ", 100)
	server := serve(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><head><title>%s</title><meta name=\"description\" content=\"line one\n\tline\ttwo \x07bell\"></head><body>%s</body></html>", longTitle, filler)
	})

	preview, err := NewUnsafeForTests().Fetch(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if len([]rune(preview.Title)) > maxTitle || !strings.HasSuffix(preview.Title, "…") {
		t.Errorf("title should be capped with an ellipsis, got %d runes", len([]rune(preview.Title)))
	}
	if preview.Description != "line one line two bell" {
		t.Errorf("description = %q, want whitespace collapsed and controls dropped", preview.Description)
	}
}

func TestFetchDecodesALegacyCharset(t *testing.T) {
	server := serve(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=iso-8859-1")
		w.Write([]byte("<html><head><title>caf\xe9</title></head><body></body></html>"))
	})
	preview, err := NewUnsafeForTests().Fetch(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if preview.Title != "café" {
		t.Errorf("title = %q, want café", preview.Title)
	}
}

func TestAbsoluteKeepsOnlyWebAddresses(t *testing.T) {
	base, _ := url.Parse("https://example.com/blog/post")
	cases := map[string]string{
		"":                                  "",
		"cover.png":                         "https://example.com/blog/cover.png",
		"/cover.png":                        "https://example.com/cover.png",
		"//cdn.example.net/c.png":           "https://cdn.example.net/c.png",
		"https://cdn.example.net/c.png":     "https://cdn.example.net/c.png",
		"data:image/png;base64,AAAA":        "",
		"javascript:alert(1)":               "",
		"ftp://example.com/x.png":           "",
		strings.Repeat("a", maxURLLength+1): "",
	}
	for raw, want := range cases {
		if got := absolute(base, raw); got != want {
			t.Errorf("absolute(%q) = %q, want %q", raw, got, want)
		}
	}
}
