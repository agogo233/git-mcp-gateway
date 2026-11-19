package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/local/git-mcp-gateway/internal/auth"
	"github.com/local/git-mcp-gateway/internal/creds"
)

func authHash(token string) (string, error) { return auth.HashToken(token) }

// runKeytool implements the `keytool` subcommands used during setup:
//
//	git-mcp-gateway keytool hash -t <token>              # bcrypt for users.yaml
//	git-mcp-gateway keytool encrypt -i <pem> -o <out>    # seal a private key into a blob
//	git-mcp-gateway keytool gen-deploy-key -name <c> -pub <pub.out> -o <priv.age>
//	                                                     # generate an ed25519 deploy key:
//	                                                     # prints the authorized_keys line,
//	                                                     # writes the encrypted private key
func runKeytool(args []string) {
	if len(args) == 0 {
		keytoolUsage()
	}
	switch args[0] {
	case "hash":
		fs := flag.NewFlagSet("hash", flag.ExitOnError)
		token := fs.String("t", "", "plaintext token")
		_ = fs.Parse(args[1:])
		if *token == "" {
			fatal("keytool hash: -t <token> required")
		}
		hash, err := authHash(*token)
		if err != nil {
			fatal("hash: %v", err)
		}
		fmt.Println(hash)
	case "encrypt":
		fs := flag.NewFlagSet("encrypt", flag.ExitOnError)
		in := fs.String("i", "", "plaintext private key file (OpenSSH PEM)")
		out := fs.String("o", "", "encrypted output file (.age)")
		_ = fs.Parse(args[1:])
		if *in == "" || *out == "" {
			fatal("keytool encrypt: -i and -o required")
		}
		plain, err := os.ReadFile(*in)
		if err != nil {
			fatal("read: %v", err)
		}
		key, err := creds.GlobalMasterKey()
		if err != nil {
			fatal("%v", err)
		}
		blob, err := creds.Encrypt(key, plain)
		creds.Zero(plain)
		if err != nil {
			fatal("encrypt: %v", err)
		}
		if err := os.MkdirAll(filepath.Dir(*out), 0o700); err != nil {
			fatal("mkdir: %v", err)
		}
		if err := os.WriteFile(*out, []byte(blob), 0o600); err != nil {
			fatal("write: %v", err)
		}
		fmt.Printf("encrypted key written to %s\n", *out)
	case "gen-deploy-key":
		fs := flag.NewFlagSet("gen-deploy-key", flag.ExitOnError)
		name := fs.String("name", "git-mcp", "key comment")
		pubOut := fs.String("pub", "", "where to write the public key (authorized_keys format)")
		out := fs.String("o", "", "encrypted private key output file (.age)")
		_ = fs.Parse(args[1:])
		if *out == "" {
			fatal("keytool gen-deploy-key: -o required")
		}
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			fatal("generate: %v", err)
		}
		block, err := ssh.MarshalPrivateKey(priv, *name)
		if err != nil {
			fatal("marshal: %v", err)
		}
		sshPub, err := ssh.NewPublicKey(pub)
		if err != nil {
			fatal("public key: %v", err)
		}
		key, err := creds.GlobalMasterKey()
		if err != nil {
			fatal("%v", err)
		}
		blob, err := creds.Encrypt(key, block.Bytes)
		if err != nil {
			fatal("encrypt: %v", err)
		}
		if err := os.MkdirAll(filepath.Dir(*out), 0o700); err != nil {
			fatal("mkdir: %v", err)
		}
		if err := os.WriteFile(*out, []byte(blob), 0o600); err != nil {
			fatal("write: %v", err)
		}
		if *pubOut != "" {
			if err := os.WriteFile(*pubOut, ssh.MarshalAuthorizedKey(sshPub), 0o644); err != nil {
				fatal("write pub: %v", err)
			}
		}
		fmt.Println(strings.TrimRight(string(ssh.MarshalAuthorizedKey(sshPub)), " \r\n"))
		fmt.Printf("encrypted private key written to %s\n", *out)
	default:
		keytoolUsage()
	}
}

func keytoolUsage() {
	fmt.Fprintln(os.Stderr, `usage:
  git-mcp-gateway keytool hash -t <token>
  git-mcp-gateway keytool encrypt -i <pem-file> -o <encrypted-out>
  git-mcp-gateway keytool gen-deploy-key -name <comment> -pub <public-out> -o <encrypted-out>`)
	os.Exit(2)
}
