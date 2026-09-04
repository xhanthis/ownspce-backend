// Command e2e-money provisions throwaway accounts for the Kosh end-to-end test
// and tears them down again.
//
// It exists because that test has to run real client crypto — sealing, wrapping,
// unwrapping — which lives in TypeScript, while minting a session needs the
// database and the deployment's signing key, which live here. So this half
// creates users and devices and prints their bearer tokens; the other half, in
// the money repo, does the encryption and drives the HTTP surface.
//
// It never touches money tables. Everything it creates cascades from the user
// rows it prints, and `cleanup` deletes exactly those.
//
// Usage:
//
//	go run ./cmd/e2e-money provision '{"users":[{"label":"arjun","devices":["<b64 x25519 public key>"]}]}'
//	go run ./cmd/e2e-money cleanup '{"userIds":["..."]}'
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/google/uuid"
	"github.com/ownspce/backend/pkg/auth"
	"github.com/ownspce/backend/pkg/config"
	"github.com/ownspce/backend/pkg/dotenv"
	"github.com/ownspce/backend/pkg/seal"
	"github.com/ownspce/backend/pkg/store"
)

type provisionRequest struct {
	Users []struct {
		Label   string   `json:"label"`
		Devices []string `json:"devices"`
	} `json:"users"`
}

type deviceOut struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Token  string `json:"token"`
}

type userOut struct {
	ID      string      `json:"id"`
	Email   string      `json:"email"`
	Name    string      `json:"name"`
	Devices []deviceOut `json:"devices"`
}

type cleanupRequest struct {
	UserIDs []string `json:"userIds"`
}

func main() {
	dotenv.Load(".env")

	if len(os.Args) < 3 {
		log.Fatal("usage: e2e-money provision|cleanup '<json>'")
	}

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	if cfg.IsProduction() {
		log.Fatal("refusing to run against a production configuration")
	}

	ctx := context.Background()
	st, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("open database: %v", err)
	}
	defer st.Close()

	switch os.Args[1] {
	case "provision":
		provision(ctx, st, auth.NewSigner(cfg.JWTPrivateKey, cfg.JWTPublicKey), os.Args[2])
	case "cleanup":
		cleanup(ctx, st, os.Args[2])
	default:
		log.Fatalf("unknown command %q", os.Args[1])
	}
}

// provision creates one user per entry, registers its devices in the order
// given, and prints a bearer token for each. Every device is active from
// registration — signing in is the whole gate — so each token reaches the data
// plane immediately, and what a device can read is decided by the keys wrapped
// for it rather than by an approval.
func provision(ctx context.Context, st *store.Store, signer *auth.Signer, raw string) {
	var req provisionRequest
	if err := json.Unmarshal([]byte(raw), &req); err != nil {
		log.Fatalf("decode request: %v", err)
	}

	// Every key is decoded before a single row is written. Validating as we go
	// would leave a user behind on the first bad key, with its id never printed
	// and so never cleaned up — a leak that only shows itself weeks later as
	// junk in the accounts table.
	keys := make([][][]byte, len(req.Users))
	for i, spec := range req.Users {
		keys[i] = make([][]byte, len(spec.Devices))
		for j, encoded := range spec.Devices {
			publicKey, err := base64.StdEncoding.DecodeString(encoded)
			if err != nil {
				log.Fatalf("%s device %d: not base64: %v", spec.Label, j, err)
			}
			if err := seal.ValidatePublicKey(publicKey); err != nil {
				log.Fatalf("%s device %d: %v", spec.Label, j, err)
			}
			keys[i][j] = publicKey
		}
	}

	out := make([]userOut, 0, len(req.Users))
	for i, spec := range req.Users {
		email := fmt.Sprintf("kosh-e2e-%s@ownspce.test", uuid.NewString())
		user, _, err := st.UpsertUserByProvider(ctx, "google", "sub-"+uuid.NewString(), email, spec.Label, "")
		if err != nil {
			log.Fatalf("create user %s: %v", spec.Label, err)
		}

		devices := make([]deviceOut, 0, len(spec.Devices))
		for index, publicKey := range keys[i] {
			device, err := st.RegisterDevice(ctx, user.ID, fmt.Sprintf("%s-%d", spec.Label, index), "web", publicKey)
			if err != nil {
				log.Fatalf("register device: %v", err)
			}
			token, _, err := signer.Mint(user.ID, device.ID)
			if err != nil {
				log.Fatalf("mint token: %v", err)
			}
			devices = append(devices, deviceOut{ID: device.ID.String(), Status: device.Status, Token: token})
		}
		out = append(out, userOut{ID: user.ID.String(), Email: user.Email, Name: spec.Label, Devices: devices})
	}

	if err := json.NewEncoder(os.Stdout).Encode(map[string]any{"users": out}); err != nil {
		log.Fatalf("encode response: %v", err)
	}
}

// cleanup removes the throwaway users. Deleting a user cascades to its devices,
// spaces, keys and every money row hanging off them, so nothing else needs
// naming here — and nothing outside the ids printed by provision can be reached.
func cleanup(ctx context.Context, st *store.Store, raw string) {
	var req cleanupRequest
	if err := json.Unmarshal([]byte(raw), &req); err != nil {
		log.Fatalf("decode request: %v", err)
	}

	removed := 0
	for _, id := range req.UserIDs {
		userID, err := uuid.Parse(id)
		if err != nil {
			log.Fatalf("not a user id: %q", id)
		}
		tag, err := st.Pool().Exec(ctx, "DELETE FROM users WHERE id = $1 AND email LIKE 'kosh-e2e-%@ownspce.test'", userID)
		if err != nil {
			log.Fatalf("remove user %s: %v", id, err)
		}
		removed += int(tag.RowsAffected())
	}
	fmt.Printf("removed %d test user(s)\n", removed)
}
