package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"strings"
	"time"

	"github.com/Cloud-Foundations/keymaster/lib/certgen"
	"github.com/alecthomas/kong"
	//"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"

	"github.com/cviecco/km-iprestricted-ca/lib/kmssigner"
)

const demoCN = "ip-restricted-demo-cn"
const keyFilename = "key.pem"
const defaultNetBlock = "10.0.0.0/8"
const caCertFolename = "cacert.pem"

// ssh-keygen -t ecdsa -f key.pem
// openssl genrsa -out private-key.pem 3072

// A Context stores the global flags for the CLI.
type Context struct {
	Debug      bool
	NoFallback bool

	CaCN   string
	stdout io.Writer
	caCert *x509.Certificate
	signer crypto.Signer
}

// ListCommand represents the `list` command, which is used to list information for multiple users.
type ShowCertCommand struct {
	Users []string `arg:"" name:"users" help:"Users to get userinfo." type:"string"`
	CaCN  string   `name: "ca_cn" help:"Common name for the CA if needed to generate"`
}

func (l *ShowCertCommand) Run(ctx *Context) error {
	//caBytes, err := generateCAFromCliContext(ctx)
	//caBytes, err := certgen.GenSelfSignedCACert(ctx.CaCN, "test-org", ctx.signer)
	//if err != nil {
	//	return err
	//}
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ctx.caCert.Raw,
	}
	return pem.Encode(ctx.stdout, block)
}

type SignCertCommand struct {
	//Duration    time.Duration `name:"duration"`
	Username    string `name:"username" required:"" help:"What the CN field would actually be" `
	CsrFilename string `arg:"" name:"csr" help:"Certificate Signing request file." type:"string"`
}

func (scc *SignCertCommand) Run(ctx *Context) error {
	/*
	   GenIPRestrictedX509Cert(userName string, userPub interface{},
	       caCert *x509.Certificate, caPriv crypto.Signer,
	       ipv4Netblocks []net.IPNet, duration time.Duration,
	       crlURL []string, OCPServer []string) ([]byte, error) {
	*/
	_, netBlock, err := net.ParseCIDR(defaultNetBlock)
	if err != nil {
		return err
	}
	/*
		caBytes, err := generateCAFromCliContext(ctx)
		if err != nil {
			return err
		}
		cacert, err := x509.ParseCertificate(caBytes)
		if err != nil {
			return err
		}
	*/
	certDuration := time.Hour * 24 * 250

	csrPemBytes, err := os.ReadFile(scc.CsrFilename)
	if err != nil {
		return err
	}
	csrPemBlock, _ := pem.Decode(csrPemBytes)
	if csrPemBlock == nil || csrPemBlock.Type != "CERTIFICATE REQUEST" {
		log.Fatal("failed to decode PEM block containing public key")
	}
	csr, err := x509.ParseCertificateRequest(csrPemBlock.Bytes)
	if err != nil {
		return err
	}
	certBytes, err := certgen.GenIPRestrictedX509Cert(scc.Username, csr.PublicKey,
		ctx.caCert, ctx.signer, []net.IPNet{*netBlock}, certDuration, nil, nil)
	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	}
	err = pem.Encode(ctx.stdout, pemBlock)
	if err != nil {
		return err
	}

	caBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ctx.caCert.Raw,
	}
	return pem.Encode(ctx.stdout, caBlock)

}

var cli struct {
	Debug      bool   `help:"Enable debug mode."`
	NoFallback bool   `help:"Do not fallback to legacy auth_helper.py."`
	KeyArn     string `help:"Key urn to use for signing operations"`

	ShowCert ShowCertCommand `cmd:"" help:"Get specific user group."`
	SignCert SignCertCommand `cmd:"" help:"Sing certificate."`
}

/////// To move to a separate lib later

func getSignerHashFromPublic(pub interface{}) (crypto.Hash, error) {
	// crypto.SHA256
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return crypto.SHA256, nil
	case *ecdsa.PublicKey:
		switch pub.Curve {
		case elliptic.P224(), elliptic.P256():
			return crypto.SHA256, nil
		case elliptic.P384():
			return crypto.SHA384, nil
		case elliptic.P521():
			return crypto.SHA512, nil
		default:
			return 0, fmt.Errorf("x509: unknown elliptic curve")
		}
	//Ed25519 signatures (by default) dont have a prefered signer
	case *ed25519.PublicKey, ed25519.PublicKey:
		return 0, nil

	default:
		return 0, fmt.Errorf("unknown key type")
	}
}

func isSignatureStable(pub interface{}) ([]byte, bool, error) {
	switch pub := pub.(type) {
	case *rsa.PublicKey, *ed25519.PublicKey, ed25519.PublicKey:
		return nil, true, nil
	case *ecdsa.PublicKey:
		ecdh, err := pub.ECDH()
		if err != nil {
			return nil, false, err
		}
		return ecdh.Bytes(), false, nil
	default:
		return nil, false, fmt.Errorf("unknown key type")
	}
}

func GenSelfSignedCACert(commonName string, organization string, caPriv crypto.Signer) ([]byte, error) {

	log.Printf("top of GenSelfSignedCACer")
	//// Now do the actual work...
	notBefore := time.Now()
	notAfter := notBefore.Add(24 * 365 * 8 * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	// On the initial version of keymaster we used the base64 encoding
	// of the sha256sum of the rsa signature of the sha256 of the
	// common name. This to have a stable, key dependent
	// serial number.
	// Howeve this was a bad idea as:
	// 1. Not all signers can use sha256
	// 2. Not all signatures are stable.
	//
	// However for compatility reasons me must keep the rsa behaviour
	// Thus the pkix common name generation is extermelly messy
	keyStableBytes, stableSig, err := isSignatureStable(caPriv.Public())
	if err != nil {
		return nil, err
	}
	if stableSig {
		message := ([]byte(commonName))
		hashfunc, err := getSignerHashFromPublic(caPriv.Public())
		if err != nil {
			return nil, err
		}
		if hashfunc != 0 {
			//message needs to be pre-hashed
			hasher := hashfunc.New()
			hasher.Write([]byte(message))
			message = hasher.Sum(nil)
		}
		keyStableBytes, err = caPriv.Sign(rand.Reader, message, hashfunc)
		if err != nil {
			return nil, err
		}
	}
	log.Printf("signedCN complete")
	sigSum := sha256.Sum256(keyStableBytes)
	sig := base64.StdEncoding.EncodeToString(sigSum[:])
	log.Printf("sig=%s", sig)
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{organization},
			SerialNumber: sig,
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		//ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	log.Printf("before calling internal create cert")

	return x509.CreateCertificate(rand.Reader, &template, &template, caPriv.Public(), caPriv)
}

func generateCAFromCliContext(ctx *Context) ([]byte, error) {
	return GenSelfSignedCACert(ctx.CaCN, "test-org", ctx.signer)
}

func LoadCertOrGenerate(filename string, ctx *Context) (*x509.Certificate, error) {
	certPemBytes, err := os.ReadFile(filename)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		//file does not exist, lets generate it
		caBytes, err := generateCAFromCliContext(ctx)
		if err != nil {
			return nil, err
		}
		// Write the new cert!
		//err := os.WriteFile("/tmp/dat1", d1, 0644)

		caCert, err := x509.ParseCertificate(caBytes)
		if err != nil {
			return nil, err
		}
		return caCert, nil

	}
	// PEM decode
	certPemBlock, _ := pem.Decode(certPemBytes)
	if certPemBlock == nil || certPemBlock.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("failed to decode PEM block containing public key")
	}
	return x509.ParseCertificate(certPemBlock.Bytes)

}

func initSigner(ctx context.Context, location string) (crypto.Signer, error) {
	if strings.HasPrefix(location, "arn:") {
		cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion("us-west-2"))
		if err != nil {
			return nil, err
		}
		return kmssigner.NewKmsSigner(cfg, ctx, location)
	}
	// asume then local file.. TODO: fallback to try aws if file does not exist
	privateKeyBytes, err := os.ReadFile(location)
	if err != nil {
		return nil, err
	}
	return certgen.GetSignerFromPEMBytes(privateKeyBytes)
}

func main() {
	ctx := kong.Parse(&cli)

	// Load Certificate OR generate new one

	// Load signer + initialize whatwever
	signerLocation := keyFilename
	if cli.KeyArn != "" {
		signerLocation = cli.KeyArn
	}
	gctx := context.Background()

	signer, err := initSigner(gctx, signerLocation)
	if err != nil {
		log.Fatalf("Error loading signer err=%s", err)
	}

	// Now
	ctx2 := Context{Debug: cli.Debug, signer: signer, stdout: os.Stdout}
	caCert, err := LoadCertOrGenerate(caCertFolename, &ctx2)
	if err != nil {
		log.Fatalf("could not load certificate err=%s", err)
	}
	ctx2.caCert = caCert
	// TODO ensure cert and signer match

	err = ctx.Run(&ctx2)
	ctx.FatalIfErrorf(err)
}
