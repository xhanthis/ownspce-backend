// Command e2e drives a full encrypted sync cycle against a running deployment and
// reports whether the API behaves as a content-blind relay end to end.
//
// It provisions a throwaway user and device directly in the database, mints a
// session token with the deployment's signing key, then exercises the real HTTP
// surface: create space, append sealed changes, poll them back, write the sealed
// workspace document, compact, and confirm a lagging poller is told to resync.
// The user and everything cascading from it are deleted afterwards.
//
// Usage:
//
//	OWNSPCE_API=https://api.ownspce.com/v1 JWT_PRIVATE_KEY=... DATABASE_URL=... go run ./cmd/e2e
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/ownspce/backend/pkg/auth"
	"github.com/ownspce/backend/pkg/dotenv"
	"github.com/ownspce/backend/pkg/seal"
	"github.com/ownspce/backend/pkg/store"
)

type client struct {
	base  string
	token string
	http  *http.Client
}

// call performs one API request and returns the decoded body plus status.
func (c *client) call(method, path string, body any) (int, map[string]any) {
	var payload io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			log.Fatalf("encode %s %s: %v", method, path, err)
		}
		payload = bytes.NewReader(encoded)
	}

	req, err := http.NewRequest(method, c.base+path, payload)
	if err != nil {
		log.Fatalf("build %s %s: %v", method, path, err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		log.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	if len(out) == 0 && len(raw) > 0 {
		out["_raw"] = string(raw)
	}
	return resp.StatusCode, out
}

var failures int

func check(label string, ok bool, detail string) {
	if ok {
		fmt.Printf("  ok   %s\n", label)
		return
	}
	failures++
	fmt.Printf("  FAIL %s — %s\n", label, detail)
}

func main() {
	dotenv.Load(".env")

	base := os.Getenv("OWNSPCE_API")
	if base == "" {
		base = "https://api.ownspce.com/v1"
	}
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		log.Fatal("DATABASE_URL is required")
	}
	rawKey := os.Getenv("JWT_PRIVATE_KEY")
	if rawKey == "" {
		log.Fatal("JWT_PRIVATE_KEY is required and must match the deployment's key")
	}
	seed, err := base64.StdEncoding.DecodeString(rawKey)
	if err != nil || len(seed) != ed25519.SeedSize {
		log.Fatalf("JWT_PRIVATE_KEY must be base64 of a %d byte seed", ed25519.SeedSize)
	}
	private := ed25519.NewKeyFromSeed(seed)
	signer := auth.NewSigner(private, private.Public().(ed25519.PublicKey))

	ctx := context.Background()
	st, err := store.Open(ctx, dsn)
	if err != nil {
		log.Fatalf("open database: %v", err)
	}
	defer st.Close()

	fmt.Printf("e2e: %s\n", base)

	publicKey := make([]byte, seal.PublicKeySize)
	if _, err := rand.Read(publicKey); err != nil {
		log.Fatalf("random key: %v", err)
	}
	user, _, err := st.UpsertUserByProvider(ctx, "google", "e2e-"+uuid.NewString(), fmt.Sprintf("e2e-%s@ownspce.test", uuid.NewString()), "e2e probe", "")
	if err != nil {
		log.Fatalf("create probe user: %v", err)
	}
	defer func() {
		if _, err := st.Pool().Exec(context.Background(), "DELETE FROM users WHERE id = $1", user.ID); err != nil {
			log.Printf("cleanup probe user: %v", err)
		} else {
			fmt.Println("  ok   probe user deleted")
		}
	}()

	device, err := st.RegisterDevice(ctx, user.ID, "e2e", "linux", publicKey)
	if err != nil {
		log.Fatalf("register probe device: %v", err)
	}
	token, _, err := signer.Mint(user.ID, device.ID)
	if err != nil {
		log.Fatalf("mint token: %v", err)
	}
	c := &client{base: base, token: token, http: &http.Client{Timeout: 20 * time.Second}}

	status, body := c.call(http.MethodGet, "/me", nil)
	check("token accepted by deployment", status == 200 && body["id"] == user.ID.String(), fmt.Sprintf("status %d body %v", status, body))

	wrapped := make([]byte, 80)
	_, _ = rand.Read(wrapped)
	status, body = c.call(http.MethodPost, "/spaces", map[string]any{"wrappedKeys": []map[string]any{{"deviceId": device.ID.String(), "wrappedKey": base64.StdEncoding.EncodeToString(wrapped)}}})
	check("create space", status == 201, fmt.Sprintf("status %d body %v", status, body))
	if status != 201 {
		os.Exit(1)
	}
	spaceID, _ := body["id"].(string)

	sealed := make([]byte, seal.Buckets[0]+seal.AEADOverhead)
	if _, err := rand.Read(sealed); err != nil {
		log.Fatalf("random payload: %v", err)
	}
	encoded := base64.StdEncoding.EncodeToString(sealed)
	cid := uuid.NewString()

	status, body = c.call(http.MethodPost, "/spaces/"+spaceID+"/updates", map[string]any{"keyEpoch": 1, "changes": []map[string]any{{"cid": cid, "ciphertext": encoded}}})
	check("append sealed change", status == 200, fmt.Sprintf("status %d body %v", status, body))

	status, body = c.call(http.MethodGet, "/spaces/"+spaceID+"/updates?since=0", nil)
	relayed := false
	if changes, ok := body["changes"].([]any); ok && len(changes) == 1 {
		first, _ := changes[0].(map[string]any)
		relayed = first["ciphertext"] == encoded && first["cid"] == cid
	}
	check("ciphertext relayed byte for byte", status == 200 && relayed, fmt.Sprintf("status %d body %v", status, body))

	status, body = c.call(http.MethodPost, "/spaces/"+spaceID+"/updates", map[string]any{"keyEpoch": 1, "changes": []map[string]any{{"cid": uuid.NewString(), "ciphertext": base64.StdEncoding.EncodeToString(make([]byte, 999))}}})
	check("unpadded ciphertext rejected", status == 413, fmt.Sprintf("status %d body %v", status, body))

	status, body = c.call(http.MethodPost, "/spaces/"+spaceID+"/updates", map[string]any{"keyEpoch": 99, "changes": []map[string]any{{"cid": uuid.NewString(), "ciphertext": encoded}}})
	check("stale key epoch rejected", status == 409, fmt.Sprintf("status %d body %v", status, body))

	status, body = c.call(http.MethodPut, "/spaces/"+spaceID+"/workspace", map[string]any{"baseVersion": 0, "keyEpoch": 1, "ciphertext": encoded})
	check("write sealed workspace doc", status == 200 && body["version"] == float64(1), fmt.Sprintf("status %d body %v", status, body))

	status, body = c.call(http.MethodPut, "/spaces/"+spaceID+"/workspace", map[string]any{"baseVersion": 0, "keyEpoch": 1, "ciphertext": encoded})
	check("workspace version conflict detected", status == 409, fmt.Sprintf("status %d body %v", status, body))

	snapshot := make([]byte, seal.Buckets[1]+seal.AEADOverhead)
	if _, err := rand.Read(snapshot); err != nil {
		log.Fatalf("random snapshot: %v", err)
	}
	status, body = c.call(http.MethodPost, "/spaces/"+spaceID+"/snapshot", map[string]any{"uptoSeq": 1, "keyEpoch": 1, "ciphertext": base64.StdEncoding.EncodeToString(snapshot)})
	check("commit snapshot and compact", status == 200, fmt.Sprintf("status %d body %v", status, body))

	status, body = c.call(http.MethodGet, "/spaces/"+spaceID+"/updates?since=0", nil)
	check("lagging poller told to resync", status == 200 && body["resync"] == true && body["snapshot"] != nil, fmt.Sprintf("status %d body %v", status, body))

	status, body = c.call(http.MethodGet, "/spaces", nil)
	hasKey := false
	if spaces, ok := body["spaces"].([]any); ok && len(spaces) == 1 {
		first, _ := spaces[0].(map[string]any)
		hasKey = first["wrappedKey"] != nil && first["id"] == spaceID
	}
	check("space lists wrapped key for this device", status == 200 && hasKey, fmt.Sprintf("status %d body %v", status, body))

	// Publishing is the one readable surface, and the only path that needs object
	// storage. Without a blob token the API answers 503 by design, so that is
	// reported as a skip rather than a failure.
	username := "e2e" + uuid.NewString()[:8]
	slug := "probe-" + uuid.NewString()[:8]
	status, body = c.call(http.MethodPatch, "/me", map[string]any{"username": username})
	check("set username", status == 200 && body["username"] == username, fmt.Sprintf("status %d body %v", status, body))

	status, body = c.call(http.MethodPost, "/publish", map[string]any{"slug": slug, "html": base64.StdEncoding.EncodeToString([]byte("<h1>probe</h1>")), "blocks": base64.StdEncoding.EncodeToString([]byte(`{"blocks":[]}`)), "assetUrls": []string{}, "ogTitle": "probe", "ogDescription": ""})
	switch status {
	case 503:
		fmt.Println("  skip publish — no blob store configured for this deployment")
	default:
		check("publish page", status == 200, fmt.Sprintf("status %d body %v", status, body))

		status, body = c.call(http.MethodGet, "/public/pages/"+username+"/"+slug, nil)
		check("public page resolves", status == 200 && body["htmlUrl"] != nil, fmt.Sprintf("status %d body %v", status, body))

		status, body = c.call(http.MethodDelete, "/publish/"+slug, nil)
		check("unpublish page", status == 204, fmt.Sprintf("status %d body %v", status, body))

		status, _ = c.call(http.MethodGet, "/public/pages/"+username+"/"+slug, nil)
		check("unpublished page is gone", status == 404, fmt.Sprintf("status %d", status))
	}

	fmt.Println()
	if failures > 0 {
		fmt.Printf("FAILED: %d check(s)\n", failures)
		os.Exit(1)
	}
	fmt.Println("all checks passed")
}
