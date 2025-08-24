package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"

	"github.com/matthewmueller/sshx"
	"golang.org/x/crypto/ssh"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func loadSigner(path string) (ssh.Signer, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// Handle OpenSSH (new format) or PEM PKCS#1/8
	if signer, err := ssh.ParsePrivateKey(b); err == nil {
		return signer, nil
	}
	// Fallback for PEM blocks
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", path)
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		pkcs8, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("parse key: %v / %v", err, err2)
		}
		return ssh.NewSignerFromKey(pkcs8)
	}
	return ssh.NewSignerFromKey(key)
}

func run() error {
	ip := os.Getenv("IP")
	keypath := os.Getenv("SSH_KEY_PATH")
	user := os.Getenv("SSH_USER")
	if ip == "" || keypath == "" || user == "" {
		return fmt.Errorf("IP or SSH_KEY_PATH or SSH_USER environment variables not set")
	}
	signer, err := loadSigner(keypath)
	if err != nil {
		return fmt.Errorf("load signer: %v", err)
	}
	conn, err := sshx.Dial(user, ip+":22", signer)
	if err != nil {
		return fmt.Errorf("dial: %v", err)
	}
	defer conn.Close()

	stdout, err := sshx.Run(conn, "hostnamectl")
	if err != nil {
		return fmt.Errorf("run: %v", err)
	}
	fmt.Println(stdout)

	return nil
}
