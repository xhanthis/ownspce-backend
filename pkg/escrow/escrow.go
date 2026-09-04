// Package escrow holds the account key the server keeps on a person's behalf.
//
// This is a deliberate, load-bearing exception to the rest of the system. Every
// other key in Ownspce lives only on a device; this one lives here, so that
// somebody who has lost every device can prove their email address and get
// their ledger back. The cost is stated plainly and must stay stated plainly:
// an operator with both the database and ESCROW_MASTER_KEY can decrypt any
// household. The alternative — a lost phrase meaning a lost ledger — was judged
// the worse product.
//
// Two things follow from that and are enforced here. The escrow private key is
// never stored in the clear: the database column holds it sealed under a master
// key that lives only in the environment, so a stolen dump is not enough on its
// own. And the plaintext private key exists only for the microseconds it takes
// to re-wrap a space key, never in a struct field and never in a log.
package escrow

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
)

// KeySize is the X25519 key length, and also the master key length.
const KeySize = 32

const nonceSize = 24

var (
	// ErrNotConfigured means ESCROW_MASTER_KEY is absent, so no escrow key can
	// be created or opened.
	ErrNotConfigured = errors.New("escrow: no master key configured")
	// ErrCorrupt means a stored escrow key did not open under the master key —
	// a rotated or wrong ESCROW_MASTER_KEY, or a tampered row.
	ErrCorrupt = errors.New("escrow: stored key could not be opened")
)

// Keeper seals and opens account escrow keys under one master key.
type Keeper struct {
	master *[KeySize]byte
}

// New builds a Keeper. A nil master key is allowed and every method then fails
// with ErrNotConfigured, so a deployment without the secret refuses escrow
// rather than silently storing openable keys.
func New(masterKey []byte) *Keeper {
	if len(masterKey) != KeySize {
		return &Keeper{}
	}
	var m [KeySize]byte
	copy(m[:], masterKey)
	return &Keeper{master: &m}
}

// Configured reports whether escrow can be used at all.
func (k *Keeper) Configured() bool { return k.master != nil }

// NewAccountKey mints an account escrow keypair.
// Returns: the public half to publish, the private half sealed under the master
// key for storage, or ErrNotConfigured
func (k *Keeper) NewAccountKey() (publicKey, sealedPrivateKey []byte, err error) {
	if !k.Configured() {
		return nil, nil, ErrNotConfigured
	}

	var private [KeySize]byte
	if _, err := io.ReadFull(rand.Reader, private[:]); err != nil {
		return nil, nil, err
	}
	public, err := curve25519.X25519(private[:], curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}

	sealed, err := k.seal(private[:])
	if err != nil {
		return nil, nil, err
	}
	return public, sealed, nil
}

// RewrapTo opens a space key that was sealed to the account escrow public key
// and seals it again to a device.
//
// The whole point of the escrow key passes through this one function, which is
// why it is the only place the private half is ever unsealed.
// Args: sealedPrivateKey (as stored), escrowPublicKey, wrappedKey (the escrow
// copy of the space key), devicePublicKey (the new recipient)
// Returns: the space key sealed to the device, or an error
// Handles: a wrap that belongs to a different escrow key, which fails rather
// than producing a wrap that would decrypt a ledger into noise
func (k *Keeper) RewrapTo(sealedPrivateKey, escrowPublicKey, wrappedKey, devicePublicKey []byte) ([]byte, error) {
	if !k.Configured() {
		return nil, ErrNotConfigured
	}
	if len(escrowPublicKey) != KeySize || len(devicePublicKey) != KeySize {
		return nil, fmt.Errorf("escrow: public keys must be %d bytes", KeySize)
	}

	private, err := k.open(sealedPrivateKey)
	if err != nil {
		return nil, err
	}
	defer zero(private)

	var pub, priv [KeySize]byte
	copy(pub[:], escrowPublicKey)
	copy(priv[:], private)
	defer zero(priv[:])

	spaceKey, ok := box.OpenAnonymous(nil, wrappedKey, &pub, &priv)
	if !ok {
		return nil, fmt.Errorf("escrow: wrapped key does not open under this account's escrow key")
	}
	defer zero(spaceKey)

	var recipient [KeySize]byte
	copy(recipient[:], devicePublicKey)
	return box.SealAnonymous(nil, spaceKey, &recipient, rand.Reader)
}

// seal encrypts the escrow private key for storage: a random nonce followed by
// the secretbox, so the stored bytes are self-describing.
func (k *Keeper) seal(plaintext []byte) ([]byte, error) {
	var nonce [nonceSize]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, err
	}
	return secretbox.Seal(nonce[:], plaintext, &nonce, k.master), nil
}

// open reverses seal.
func (k *Keeper) open(stored []byte) ([]byte, error) {
	if len(stored) <= nonceSize {
		return nil, ErrCorrupt
	}
	var nonce [nonceSize]byte
	copy(nonce[:], stored[:nonceSize])

	plaintext, ok := secretbox.Open(nil, stored[nonceSize:], &nonce, k.master)
	if !ok {
		return nil, ErrCorrupt
	}
	if len(plaintext) != KeySize {
		return nil, ErrCorrupt
	}
	return plaintext, nil
}

// zero scrubs key material rather than leaving it for the collector.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
