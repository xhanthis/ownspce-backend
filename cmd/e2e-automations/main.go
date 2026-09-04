// Command e2e-automations provisions a throwaway user and daemon pairing so the
// automations loop can be exercised against a running deployment.
//
// It creates a user and device directly in the database, mints a session token
// with the deployment's signing key, then uses the real HTTP surface to mint a
// daemon token and queue a run. It prints the daemon token, the run id, and the
// cleanup command; the daemon binary does the rest.
//
// Usage:
//
//	OWNSPCE_API=http://localhost:8080/v1 go run ./cmd/e2e-automations -repo owner/name
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/google/uuid"
	"github.com/ownspce/backend/pkg/auth"
	"github.com/ownspce/backend/pkg/config"
	"github.com/ownspce/backend/pkg/dotenv"
	"github.com/ownspce/backend/pkg/seal"
	"github.com/ownspce/backend/pkg/store"
)

// call performs one authenticated API request and returns the decoded body.
func call(base, token, method, path string, body any) (int, map[string]any) {
	var payload io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			log.Fatalf("encode %s %s: %v", method, path, err)
		}
		payload = bytes.NewReader(encoded)
	}

	req, err := http.NewRequest(method, base+path, payload)
	if err != nil {
		log.Fatalf("build %s %s: %v", method, path, err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatalf("%s %s: %v", method, path, err)
	}
	defer res.Body.Close()

	raw, _ := io.ReadAll(res.Body)
	out := map[string]any{}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &out)
	}
	if res.StatusCode >= 400 {
		log.Fatalf("%s %s -> %d %s", method, path, res.StatusCode, string(raw))
	}
	return res.StatusCode, out
}

func main() {
	repo := flag.String("repo", "", "owner/name of the repository the daemon may build")
	pageID := flag.String("page", "smoke-page", "page id to attribute the run to")
	taskID := flag.String("task", "", "task id (defaults to a fresh uuid)")
	title := flag.String("title", "Add a hello file", "task title")
	instructions := flag.String("instructions", "Create hello.md containing a one-line greeting.", "run instructions")
	flag.Parse()

	if *repo == "" {
		log.Fatal("-repo is required")
	}
	if *taskID == "" {
		*taskID = uuid.NewString()
	}

	dotenv.Load(".env")
	base := os.Getenv("OWNSPCE_API")
	if base == "" {
		base = "http://localhost:8080/v1"
	}

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	st, err := store.Open(context.Background(), cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("open database: %v", err)
	}
	defer st.Close()

	ctx := context.Background()
	user, _, err := st.UpsertUserByProvider(ctx, "google", "smoke-"+uuid.NewString(), fmt.Sprintf("smoke-%s@ownspce.test", uuid.NewString()), "Automation smoke", "")
	if err != nil {
		log.Fatalf("create user: %v", err)
	}

	publicKey := make([]byte, seal.PublicKeySize)
	device, err := st.RegisterDevice(ctx, user.ID, "smoke device", "macos", publicKey)
	if err != nil {
		log.Fatalf("register device: %v", err)
	}

	signer := auth.NewSigner(cfg.JWTPrivateKey, cfg.JWTPublicKey)
	token, _, err := signer.Mint(user.ID, device.ID)
	if err != nil {
		log.Fatalf("mint session: %v", err)
	}

	_, minted := call(base, token, http.MethodPost, "/automations/daemons", map[string]any{"name": "smoke daemon"})
	daemonToken, _ := minted["token"].(string)

	_, _ = call(base, daemonToken, http.MethodPost, "/daemon/register", map[string]any{
		"name": "smoke daemon", "version": "e2e",
		"repos": []map[string]any{{"fullName": *repo, "defaultBranch": "main"}},
	})

	_, queued := call(base, token, http.MethodPost, "/automations/runs", map[string]any{
		"pageId": *pageID, "taskId": *taskID, "taskTitle": *title,
		"instructions": *instructions, "repo": *repo, "baseBranch": "",
	})
	run, _ := queued["run"].(map[string]any)

	fmt.Printf("USER_ID=%s\n", user.ID)
	fmt.Printf("SESSION_TOKEN=%s\n", token)
	fmt.Printf("DAEMON_TOKEN=%s\n", daemonToken)
	fmt.Printf("RUN_ID=%s\n", run["id"])
	fmt.Printf("BRANCH=%s\n", run["branch"])
}
