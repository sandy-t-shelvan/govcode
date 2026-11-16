package sign

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRoundTripAndTamper(t *testing.T) {
	dir := t.TempDir()
	pub, err := GenerateKeyFiles(filepath.Join(dir, "k"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := LoadSigner(filepath.Join(dir, "k.key"))
	if err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(dir, "manifest.json")
	os.WriteFile(f, []byte(`{"a":1}`), 0o644)
	if err := SignFile(s, f); err != nil {
		t.Fatal(err)
	}
	if _, kid, err := VerifyFile(f, pub); err != nil || kid != s.KeyID() {
		t.Fatalf("verify: %v", err)
	}
	os.WriteFile(f, []byte(`{"a":2}`), 0o644)
	if _, _, err := VerifyFile(f, pub); err == nil {
		t.Fatal("tampered file verified")
	}
}

func TestLoadSignerRejectsLoosePerms(t *testing.T) {
	dir := t.TempDir()
	GenerateKeyFiles(filepath.Join(dir, "k"))
	os.Chmod(filepath.Join(dir, "k.key"), 0o644)
	if _, err := LoadSigner(filepath.Join(dir, "k.key")); err == nil {
		t.Fatal("0644 private key accepted")
	}
}

func TestNoOverwrite(t *testing.T) {
	dir := t.TempDir()
	GenerateKeyFiles(filepath.Join(dir, "k"))
	if _, err := GenerateKeyFiles(filepath.Join(dir, "k")); err == nil {
		t.Fatal("overwrote key")
	}
}
