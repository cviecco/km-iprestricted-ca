package yksigner

import (
	"crypto"
	"io"

	"github.com/cviecco/piv-go/v2/piv"
)

type YkSigner struct {
	yk        *piv.YubiKey
	ykSerial  uint32
	pivPIN    string
	publicKey crypto.PublicKey
	signer    crypto.Signer
}

func NewYkPivSigner(serial uint32, pivPIN string, pub crypto.PublicKey) (*YkSigner, error) {
	//return newKmsSigner(cfg, ctx, keyname)
	return newYkPivSigner(serial, pivPIN, pub)
}

func (ks *YkSigner) Public() crypto.PublicKey {
	return ks.public()
}

func (ks *YkSigner) Sign(reader io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	return ks.sign(reader, message, opts)
	//return nil, fmt.Errorf("not implemented")
}

func (ks *YkSigner) Close() {
	if ks.yk != nil {
		ks.yk.Close()
	}
}
