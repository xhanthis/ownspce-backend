// Command keygen prints a fresh Ed25519 keypair for signing session tokens,
// formatted for the JWT_PRIVATE_KEY / JWT_PUBLIC_KEY environment variables.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
)

func main() {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("generate key: %v", err)
	}
	fmt.Printf("JWT_PRIVATE_KEY=%s\n", base64.StdEncoding.EncodeToString(priv.Seed()))
	fmt.Printf("JWT_PUBLIC_KEY=%s\n", base64.StdEncoding.EncodeToString(pub))
}
