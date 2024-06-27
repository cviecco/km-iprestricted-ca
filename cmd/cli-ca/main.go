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
	aws_config "github.com/aws/aws-sdk-go-v2/config"

	cliconfig "github.com/cviecco/km-iprestricted-ca/lib/config"
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
	signer crypto.Signer
	config cliconfig.CliCaConfig
}

type GenerateCACertCommand struct {
	CaCN string `name: "ca_cn" help:"Common name for the CA if needed to generate"`
}

func (gca *GenerateCACertCommand) Run(ctx *Context) error {
	caBytes, err := generateCAFromCliContext(ctx)
	if err != nil {
		return err
	}
	// Write the new cert!
	//err := os.WriteFile("/tmp/dat1", d1, 0644)

	caCert, err := x509.ParseCertificate(caBytes)
	if err != nil {
		return err
	}
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCert.Raw,
	}
	return pem.Encode(ctx.stdout, block)

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
	caCert, err := LocaCertFromFile(ctx.config.Signer.CertLocation)
	if err != nil {
		return err
	}

	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCert.Raw,
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

	caCert, err := LocaCertFromFile(ctx.config.Signer.CertLocation)
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
		caCert, ctx.signer, []net.IPNet{*netBlock}, certDuration, nil, nil)
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
		Bytes: caCert.Raw,
	}
	return pem.Encode(ctx.stdout, caBlock)

}

var cli struct {
	Debug          bool   `help:"Enable debug mode."`
	NoFallback     bool   `help:"Do not fallback to legacy auth_helper.py."`
	ConfigFilename string `help:"configuration filename" default:"config.yml"`

	GenerateCert GenerateCACertCommand `cmd:"" help:"Generate a cacert."`
	ShowCert     ShowCertCommand       `cmd:"" help:"Get specific user group."`
	SignCert     SignCertCommand       `cmd:"" help:"Sing certificate."`
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
	//sum := sha256.Sum256([]byte(commonName))

	hashfunc, err := getSignerHashFromPublic(caPriv.Public())
	if err != nil {
		return nil, err
	}
	hasher := hashfunc.New()
	hasher.Write([]byte(commonName))
	sum := hasher.Sum(nil)

	signedCN, err := caPriv.Sign(rand.Reader, sum, hashfunc)
	if err != nil {
		return nil, err
	}
	log.Printf("signedCN complete")
	sigSum := sha256.Sum256(signedCN)
	sig := base64.StdEncoding.EncodeToString(sigSum[:])
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

func LocaCertFromFile(filename string) (*x509.Certificate, error) {
	certPemBytes, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	certPemBlock, _ := pem.Decode(certPemBytes)
	if certPemBlock == nil || certPemBlock.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("failed to decode PEM block containing public key")
	}
	return x509.ParseCertificate(certPemBlock.Bytes)
}

func loadSignerFromLocation(location string) (crypto.Signer, error) {
	if strings.HasPrefix(location, "arn:aws:kms:") {
		ctx := context.Background()
		cfg, err := aws_config.LoadDefaultConfig(ctx, aws_config.WithRegion("us-west-2"))
		if err != nil {
			return nil, err
		}
		return kmssigner.NewKmsSigner(cfg, ctx, location)
	}
	privateKeyBytes, err := os.ReadFile(location)
	if err != nil {
		return nil, err
	}
	return certgen.GetSignerFromPEMBytes(privateKeyBytes)

}

func main() {
	kctx := kong.Parse(&cli)

	// Load Certificate OR generate new one
	config, err := cliconfig.LoadCliCaConfigFromFile(cli.ConfigFilename)
	if err != nil {
		log.Fatalf("faile to load config err=%s", err)
	}
	fmt.Printf("config =%+v", config)

	var signer crypto.Signer
	signer, err = loadSignerFromLocation(config.Signer.KeyLocation)
	if err != nil {
		log.Fatal(err)
	}
	// Load signer + initialize whatwever
	// Now
	ctx2 := Context{Debug: cli.Debug, signer: signer, config: *config, stdout: os.Stdout}

	err = kctx.Run(&ctx2)
	kctx.FatalIfErrorf(err)
}
