package main

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	//"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"

	"github.com/Cloud-Foundations/keymaster/lib/certgen"
	"github.com/alecthomas/kong"
)

const demoCN = "ip-restricted-demo-cn"
const keyFilename = "key.pem"
const defaultNetBlock = "10.0.0.0/8"

// ssh-keygen -t ecdsa -f key.pem
// openssl genrsa -out private-key.pem 3072

// A Context stores the global flags for the CLI.
type Context struct {
	Debug      bool
	NoFallback bool

	CaCN   string
	stdout io.Writer
	signer crypto.Signer
}

// ListCommand represents the `list` command, which is used to list information for multiple users.
type ShowCertCommand struct {
	Users []string `arg:"" name:"users" help:"Users to get userinfo." type:"string"`
}

func (l *ShowCertCommand) Run(ctx *Context) error {
	caBytes, err := generateCAFromCliContext(ctx)
	//caBytes, err := certgen.GenSelfSignedCACert(ctx.CaCN, "test-org", ctx.signer)
	if err != nil {
		return err
	}
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	}
	return pem.Encode(ctx.stdout, block)
}

type SignCertCommand struct {
	csrFilename string `arg:"" name:"csr" help:"Certificate Signing request file." type:"string"`
}

func (scc *SignCertCommand) Run(ctx *Context) error {
	/*
	   GenIPRestrictedX509Cert(userName string, userPub interface{},
	       caCert *x509.Certificate, caPriv crypto.Signer,
	       ipv4Netblocks []net.IPNet, duration time.Duration,
	       crlURL []string, OCPServer []string) ([]byte, error) {
	*/
	_, netBlock, err := net.ParseCIDR("defaultNetBlock")
	if err != nil {
		return err
	}
	caBytes, err := generateCAFromCliContext(ctx)
	if err != nil {
		return err
	}
	cacert, err := x509.ParseCertificate(caBytes)
	if err != nil {
		return err
	}
	certDuration := time.Hour * 24

	csrBytes, err := os.ReadFile(scc.csrFilename)
	if err != nil {
		return err
	}
	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		return err
	}
	certBytes, err := certgen.GenIPRestrictedX509Cert("someusername", csr.PublicKey,
		cacert, ctx.signer, []net.IPNet{*netBlock}, certDuration, nil, nil)
	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	}
	return pem.Encode(ctx.stdout, pemBlock)

}

var cli struct {
	Debug      bool `help:"Enable debug mode."`
	NoFallback bool `help:"Do not fallback to legacy auth_helper.py."`

	ShowCert ShowCertCommand `cmd:"" help:"Get specific user group."`
	SignCert SignCertCommand `cmd:"" help:"Sing certificate."`
}

///implementation

func generateCAFromCliContext(ctx *Context) ([]byte, error) {
	return certgen.GenSelfSignedCACert(ctx.CaCN, "test-org", ctx.signer)
}

func main() {
	ctx := kong.Parse(&cli)

	// Load signer + initialize whatwever
	privateKeyBytes, err := os.ReadFile(keyFilename)
	if err != nil {
		log.Fatalf("failure readking key file")
	}

	signer, err := certgen.GetSignerFromPEMBytes(privateKeyBytes)
	if err != nil {
		log.Fatalf("cannot inicialize signer err=%s", err)
	}

	err = ctx.Run(&Context{Debug: cli.Debug, signer: signer, stdout: os.Stdout})
	ctx.FatalIfErrorf(err)
}
