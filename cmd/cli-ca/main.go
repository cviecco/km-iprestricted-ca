package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
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
	"time"

	"github.com/Cloud-Foundations/keymaster/lib/certgen"
	"github.com/alecthomas/kong"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	//kmsapi "go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/kms/awskms"
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

type KmsSigner struct {
	client    *kms.Client
	keyID     string
	publicKey crypto.PublicKey
}

func NewKmsSigner(cfg aws.Config, ctx context.Context, keyname string) (*KmsSigner, error) {
	client := kms.NewFromConfig(cfg)
	var ks KmsSigner
	ks.client = client
	ks.keyID = keyname
	err := ks.preloadKey(ctx)
	if err != nil {
		return nil, err
	}
	return &ks, nil
}

// assumes keyID is set
func (ks *KmsSigner) preloadKey(ctx context.Context) error {

	resp, err := ks.client.GetPublicKey(ctx, &kms.GetPublicKeyInput{
		KeyId: &ks.keyID,
	})
	if err != nil {
		return err
	}
	ks.publicKey, err = x509.ParsePKIXPublicKey(resp.PublicKey)
	if err != nil {
		ks.publicKey, err = x509.ParsePKCS1PublicKey(resp.PublicKey)
		if err != nil {
			return fmt.Errorf("cannot decode key err=%s", err)
		}

	}
	return nil
}

func (ks *KmsSigner) Public() crypto.PublicKey {
	return ks.publicKey
}

func defaultContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 15*time.Second)
}

func (ks *KmsSigner) Sign(_ io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {

	//Sign(rand io.Reader,
	//message []byte,
	//opts crypto.SignerOpts) ([]byte, error)

	alg, err := getSigningAlgorithm(ks.Public(), opts)
	if err != nil {
		return nil, err
	}
	messageType := types.MessageTypeRaw
	if opts.HashFunc() != 0 {
		log.Printf("is digest type ")
		messageType = types.MessageTypeDigest
	}

	req := &kms.SignInput{
		KeyId:            &ks.keyID,
		SigningAlgorithm: alg,
		Message:          message,
		MessageType:      messageType,
	}

	ctx, cancel := defaultContext()
	defer cancel()

	resp, err := ks.client.Sign(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("awskms Sign failed err=%s", err)
	}

	return resp.Signature, nil
}

func getSigningAlgorithm(key crypto.PublicKey, opts crypto.SignerOpts) (types.SigningAlgorithmSpec, error) {
	switch pub := key.(type) {
	case *rsa.PublicKey:
		_, isPSS := opts.(*rsa.PSSOptions)
		switch h := opts.HashFunc(); h {
		case crypto.SHA256:
			if isPSS {
				return types.SigningAlgorithmSpecRsassaPssSha256, nil
			}
			return types.SigningAlgorithmSpecRsassaPkcs1V15Sha256, nil
		case crypto.SHA384:
			if isPSS {
				return types.SigningAlgorithmSpecRsassaPssSha384, nil
			}
			return types.SigningAlgorithmSpecRsassaPkcs1V15Sha384, nil
		case crypto.SHA512:
			if isPSS {
				return types.SigningAlgorithmSpecRsassaPssSha512, nil
			}
			return types.SigningAlgorithmSpecRsassaPkcs1V15Sha512, nil
		default:
			return "", fmt.Errorf("unsupported hash function %v", h)
		}
	case *ecdsa.PublicKey:
		switch pub.Curve {

		case elliptic.P224(), elliptic.P256():
			//return types.SigningAlgorithmSpecEcdsaSha256, nil
			log.Printf("p256 curve")

		case elliptic.P384():
			log.Printf("p384 curve")
			//return types.SigningAlgorithmSpecEcdsaSha384, nil
		case elliptic.P521():
			log.Printf("p521 curve")
			//return types.SigningAlgorithmSpecEcdsaSha512, nil

		default:
			//return "", fmt.Errorf("unsupported hash function %v", h)
			//err = errors.New("x509: unknown elliptic curve")
			log.Printf("unkown curve")

		}

		switch h := opts.HashFunc(); h {
		case crypto.SHA256:
			log.Printf("getSigningAlgorithm hash opts selecting sha256")
			return types.SigningAlgorithmSpecEcdsaSha256, nil
		case crypto.SHA384:
			return types.SigningAlgorithmSpecEcdsaSha384, nil
		case crypto.SHA512:
			return types.SigningAlgorithmSpecEcdsaSha512, nil
		default:
			return "", fmt.Errorf("unsupported hash function %v", h)
		}
		/*
					switch pub.Curve {

					case elliptic.P224(), elliptic.P256():
						return types.SigningAlgorithmSpecEcdsaSha256, nil

					case elliptic.P384():
						return types.SigningAlgorithmSpecEcdsaSha384, nil
					case elliptic.P521():
						return types.SigningAlgorithmSpecEcdsaSha512, nil

					default:
			            return "", fmt.Errorf("unsupported hash function %v", h)
						//err = errors.New("x509: unknown elliptic curve")

					}
		*/
	default:
		return "", fmt.Errorf("unsupported key type %T", key)
	}
}

// /implementation
func initAWSKmsSigner(ctx context.Context, keyname string) (crypto.Signer, error) {

	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion("us-west-2"))
	if err != nil {
		return nil, err
	}
	kmsClient := kms.NewFromConfig(cfg)

	log.Printf("after client")
	_, err = kmsClient.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: &keyname})
	if err != nil {
		return nil, err
	}
	log.Printf("after raw getpublicKey")

	signer, err := awskms.NewSigner(kmsClient, keyname)
	if err != nil {
		return nil, err
	}
	return signer, nil
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
	sum := sha256.Sum256([]byte(commonName))
	signedCN, err := caPriv.Sign(rand.Reader, sum[:], crypto.SHA256)
	if err != nil {
		return nil, err
	}
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

func main() {
	ctx := kong.Parse(&cli)

	// Load Certificate OR generate new one

	// Load signer + initialize whatwever
	privateKeyBytes, err := os.ReadFile(keyFilename)
	if err != nil {
		log.Fatalf("failure readking key file")
	}

	signer, err := certgen.GetSignerFromPEMBytes(privateKeyBytes)
	if err != nil {
		log.Fatalf("cannot inicialize signer err=%s", err)
	}
	if cli.KeyArn != "" {
		ctx := context.Background()
		/*
			signer, err = initAWSKmsSigner(ctx, cli.KeyArn)
			if err != nil {
				log.Fatalf("error initializing aws secret", err)
			}
		*/
		cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion("us-west-2"))
		if err != nil {
			log.Fatal(err)
		}

		ks, err := NewKmsSigner(cfg, ctx, cli.KeyArn)
		if err != nil {
			log.Fatal(err)
		}
		signer = ks
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
