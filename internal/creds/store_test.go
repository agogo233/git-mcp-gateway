package creds

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func testKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	return key
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key := testKey(t)
	plain := []byte("-----BEGIN OPENSSH PRIVATE KEY-----test-----END-----")
	blob, err := Encrypt(key, plain)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains([]byte(blob), []byte(magic)) {
		t.Fatal("blob missing magic header")
	}
	got, err := Decrypt(key, blob)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatal("round trip mismatch")
	}
}

func TestDecryptWrongKey(t *testing.T) {
	key := testKey(t)
	blob, err := Encrypt(key, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	other := testKey(t)
	other[0] ^= 0xff
	if _, err := Decrypt(other, blob); err == nil {
		t.Fatal("expected decrypt failure with wrong key")
	}
}

func TestLoadPlaintext(t *testing.T) {
	key := testKey(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "k.age")
	blob, err := Encrypt(key, []byte("private-key-material"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(blob), 0o600); err != nil {
		t.Fatal(err)
	}
	plain, err := LoadPlaintext(key, path)
	if err != nil {
		t.Fatal(err)
	}
	if string(plain) != "private-key-material" {
		t.Fatal("mismatch")
	}
}

func TestMasterKeyFromEnv(t *testing.T) {
	t.Setenv("GIT_MCP_MASTER_KEY", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	if _, err := MasterKey(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_MCP_MASTER_KEY", "tooshort")
	if _, err := MasterKey(); err == nil {
		t.Fatal("expected error for short key")
	}
}
