package kmssigner

import (
	"context"
	"crypto"
	"io"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

type KmsSigner struct {
	client    *kms.Client
	keyID     string
	publicKey crypto.PublicKey
}

func NewKmsSigner(cfg aws.Config, ctx context.Context, keyname string) (*KmsSigner, error) {
	return newKmsSigner(cfg, ctx, keyname)
}

func (ks *KmsSigner) Public() crypto.PublicKey {
	return ks.public()
}

func (ks *KmsSigner) Sign(reader io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	return ks.sign(reader, message, opts)
}
