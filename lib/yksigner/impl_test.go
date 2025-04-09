package yksigner

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cviecco/piv-go/v2/piv"
)

// This is a an imperfect test, but should cover most use cases
func hasYubiKeyCards() bool {
	cards, err := piv.Cards()
	if err != nil {
		return false
	}
	for _, card := range cards {
		if strings.Contains(strings.ToLower(card), "yubikey") {
			return true
		}
	}
	return false
}

func getHashFuncFromPub(pub crypto.PublicKey) (crypto.Hash, error) {
	switch key := pub.(type) {
	case ed25519.PublicKey:
		// From the docs
		// A value of type Options can be used as opts, or crypto.Hash(0) or crypto.SHA512 directly to select plain Ed25519 or Ed25519ph,
		return crypto.Hash(0), nil
	case *ecdsa.PublicKey:
		switch key.Curve {
		case elliptic.P256():
			return crypto.SHA256, nil
		case elliptic.P384():
			return crypto.SHA384, nil
		default:
			return crypto.SHA256, fmt.Errorf("invalid pub key")
		}
	case *rsa.PublicKey:
		return crypto.SHA256, nil
	default:
		return crypto.SHA256, fmt.Errorf("invalid pub key")
	}
}

func TestBaseYkPivSigner(t *testing.T) {
	hasCard := hasYubiKeyCards()
	if !hasCard {
		t.Skip("Skipping testing with no cards present")
	}
	YKPin := os.Getenv("YK_PIN")
	if YKPin == "" {
		YKPin = piv.DefaultPIN
	}
	begin := time.Now()
	signer, err := NewYkPivSigner(0, YKPin, nil)
	if err != nil {
		t.Fatal(err)
	}
	postNewSigner := time.Now()
	t.Logf("getSigner Duration %v", postNewSigner.Sub(begin))
	pub := signer.Public()
	if pub == nil {
		t.Fatal("publicKey should not be null")
	}

	hashFunc, err := getHashFuncFromPub(pub)
	if err != nil {
		t.Fatal(err)
	}
	preSignTime := time.Now()
	_, err = signer.Sign(rand.Reader, []byte("hello world"), hashFunc)
	if err != nil {
		t.Fatal(err)
	}
	postSignTime := time.Now()
	t.Logf("signDuration %v", postSignTime.Sub(preSignTime))
	t.Logf("Full test done")
}
