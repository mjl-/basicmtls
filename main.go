// Command basicmtls is a proof of concept for very basic mutually
// authenticated secured connections based on crypto/tls and ed25519 keys.
//
// We use ed25519 keys as verified identities. We don't care about domain name
// validations, key expirations, and generally use as little of x509 as needed.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
)

func usage() {
	log.Println("usage: basicmtls listen addr server.privkey client.pubkey")
	log.Println("       basicmtls dial addr client.privkey server.pubkey")
	log.Println("       basicmtls genkey >private.key")
	log.Println("       basicmtls pubkey <private.key >public.key")
	os.Exit(2)
}

func main() {
	log.SetFlags(0)

	if len(os.Args) < 2 {
		usage()
	}
	cmd := os.Args[1]
	args := os.Args[2:]
	switch cmd {
	case "genkey":
		genkey(args)
	case "pubkey":
		pubkey(args)
	case "dial":
		dial(args)
	case "listen":
		listen(args)
	default:
		usage()
	}
}

func genkey(args []string) {
	if len(args) != 0 {
		usage()
	}

	// We have ed25519 private keys in their smallest form, 32 bytes, stored as raw base64 (no padding).
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		log.Fatalf("generate key: %s", err)
	}
	fmt.Println(base64.RawStdEncoding.EncodeToString(priv.Seed()))
}

func pubkey(args []string) {
	if len(args) != 0 {
		usage()
	}

	// Derive public key from the private key, also stored as raw base64 (no padding).
	buf, err := io.ReadAll(base64.NewDecoder(base64.RawStdEncoding, os.Stdin))
	if err != nil {
		log.Fatalf("reading private key: %s", err)
	}
	if len(buf) != ed25519.SeedSize {
		log.Fatalf("bad length %d for private key, should be %d", len(buf), ed25519.SeedSize)
	}
	privkey := ed25519.NewKeyFromSeed(buf)
	pubkey := privkey.Public().(ed25519.PublicKey)
	fmt.Println(base64.RawStdEncoding.EncodeToString(pubkey))
}

func dial(args []string) {
	if len(args) != 3 {
		usage()
	}

	localPrivkey := readPrivkey(args[1])
	remotePubkey := readPubkey(args[2])
	localCert := makeCert(localPrivkey)

	config := &tls.Config{
		MinVersion:         tls.VersionTLS13, // No old stuff.
		InsecureSkipVerify: true,             // We're not doing domain name verification, it's all about the keys!
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			// log.Printf("VerifyPeerCertificate: len rawCerts %d, verifiedChains %#v", len(rawCerts), verifiedChains)
			return verifyCert(rawCerts, remotePubkey)
		},
		Certificates: []tls.Certificate{localCert},
	}
	c, err := tls.Dial("tcp", args[0], config)
	if err != nil {
		log.Fatalf("dial: %s", err)
	}

	// Ensure handshake is done, otherwise it'll be done at the first read.
	// We want to explicitly see the result of the handshake.
	if err := c.Handshake(); err != nil {
		log.Fatalf("handshake: %s", err)
	}
	log.Printf("connection state: %#v", c.ConnectionState())

	// Sloppy copy of data from stdin to remote, and remote to stdout.
	go io.Copy(c, os.Stdin)
	io.Copy(os.Stdout, c)
	log.Printf("(eof)")
}

func listen(args []string) {
	if len(args) != 3 {
		usage()
	}

	localPrivkey := readPrivkey(args[1])
	remotePubkey := readPubkey(args[2])
	localCert := makeCert(localPrivkey)

	config := &tls.Config{
		MinVersion:         tls.VersionTLS13,      // No old stuff.
		InsecureSkipVerify: true,                  // We're not doing domain name verification, it's all about the keys!
		ClientAuth:         tls.RequestClientCert, // Causes VerifyPeerCertificate to be called for the (required) client certificate.
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			// log.Printf("VerifyPeerCertificate: len rawCerts %d, verifiedChains %#v", len(rawCerts), verifiedChains)
			return verifyCert(rawCerts, remotePubkey)
		},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			// log.Printf("GetCertificate %#v", hello)
			return &localCert, nil
		},
	}
	lconn, err := tls.Listen("tcp", args[0], config)
	if err != nil {
		log.Fatalf("listen: %s", err)
	}
	for {
		c, err := lconn.Accept()
		if err != nil {
			log.Fatalf("accept: %s", err)
		}
		go serve(c)
	}
}

func serve(c net.Conn) {
	defer c.Close()

	tlsConn := c.(*tls.Conn)
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("handshake: %s", err)
		return
	}
	log.Printf("connection state: %#v", tlsConn.ConnectionState())

	// Just echo the data back to client.
	if _, err := io.Copy(c, c); err != nil {
		log.Printf("%s", err)
	}
}

// readPrivkey reads an ed25519 private key seed, in base64 raw encoding, from a file.
func readPrivkey(path string) ed25519.PrivateKey {
	f, err := os.Open(path)
	if err != nil {
		log.Fatalf("open private key file: %s", err)
	}
	defer f.Close()

	buf, err := io.ReadAll(base64.NewDecoder(base64.RawStdEncoding, f))
	if err != nil {
		log.Fatalf("reading private key: %s", err)
	}
	if len(buf) != ed25519.SeedSize {
		log.Fatalf("bad length %d for private key, should be %d", len(buf), ed25519.SeedSize)
	}
	return ed25519.NewKeyFromSeed(buf)
}

// readPubkey reads an ed25519 public key, in base64 raw encoding, from a file.
func readPubkey(path string) ed25519.PublicKey {
	f, err := os.Open(path)
	if err != nil {
		log.Fatalf("open public key file: %s", err)
	}
	defer f.Close()

	buf, err := io.ReadAll(base64.NewDecoder(base64.RawStdEncoding, f))
	if err != nil {
		log.Fatalf("reading public key: %s", err)
	}
	if len(buf) != ed25519.PublicKeySize {
		log.Fatalf("bad length %d for public key, should be %d", len(buf), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(buf)
}

// makeCert returns a tls.Certificate for the private key. We really don't care
// about all the stuff x509 brings, like expirations, host name validations,
// but TLS needs x509 certificates...
func makeCert(privKey ed25519.PrivateKey) tls.Certificate {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), // Required field...
	}
	localCertBuf, err := x509.CreateCertificate(rand.Reader, template, template, privKey.Public(), privKey)
	if err != nil {
		log.Fatalf("making certificate: %s", err)
	}
	cert, err := x509.ParseCertificate(localCertBuf)
	if err != nil {
		log.Fatalf("parsing generated certificate: %s", err)
	}
	c := tls.Certificate{
		Certificate: [][]byte{localCertBuf},
		PrivateKey:  privKey,
		Leaf:        cert,
	}
	// log.Printf("certificate: %#v", c)
	return c
}

// verifyCert checks that the certificate in rawCerts is for remotePubkey.
func verifyCert(rawCerts [][]byte, remotePubkey ed25519.PublicKey) (rerr error) {
	if len(rawCerts) != 1 {
		return fmt.Errorf("expect single cert, got %d certs", len(rawCerts))
	}
	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("parsing certificate: %s", err)
	}
	if pubkey, ok := cert.PublicKey.(ed25519.PublicKey); !ok {
		return fmt.Errorf("public key not ed25519, but %T", cert.PublicKey)
	} else if !pubkey.Equal(remotePubkey) {
		return fmt.Errorf("unrecognized remote public key, aborting connection")
	}
	return nil
}
