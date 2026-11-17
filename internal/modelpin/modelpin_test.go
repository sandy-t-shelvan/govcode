package modelpin

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestRepoLockParses(t *testing.T) {
	l, err := Load("../../models/models.lock.json")
	if err != nil {
		t.Fatal(err)
	}
	m, err := l.Find("")
	if err != nil || m.ID != "devstral-small-24b" {
		t.Fatalf("default model: %v %v", m, err)
	}
	if m.Serve.NumCtx <= 0 {
		t.Error("num_ctx must be explicit in lock")
	}
	for _, mm := range l.Models {
		for _, f := range mm.Upstream.Files {
			if f.GitBlobSHA1 == "" && len(f.SHA256) != 64 {
				t.Errorf("%s/%s: bad sha256 %q", mm.ID, f.Path, f.SHA256)
			}
		}
	}
}

func TestVerifyArtifacts(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "weights"), 0o755)
	os.WriteFile(filepath.Join(dir, "weights", "m.gguf"), []byte("weights"), 0o644)
	sum, _, _ := HashFile(filepath.Join(dir, "weights", "m.gguf"))
	m := &Model{Artifact: Source{Files: []File{{Path: "m.gguf", Size: 7, SHA256: sum}}}}
	if p := VerifyArtifacts(m, dir, nil); len(p) != 0 {
		t.Fatalf("good file failed: %v", p)
	}
	os.WriteFile(filepath.Join(dir, "weights", "m.gguf"), []byte("weightz"), 0o644)
	if p := VerifyArtifacts(m, dir, nil); len(p) != 1 {
		t.Fatal("tampered weights passed")
	}
	m.Artifact.Files[0].SHA256 = Unfilled
	if p := VerifyArtifacts(m, dir, nil); len(p) != 1 {
		t.Fatal("unstaged lock passed")
	}
}

func TestCheckOllama(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"models":[{"name":"govcode-qwen3-coder:30b-q4km","digest":"abc123"}]}`)
	}))
	defer srv.Close()
	m := &Model{ID: "q", Serve: Serve{OllamaName: "govcode-qwen3-coder:30b-q4km", OllamaDigest: "sha256:abc123"}}
	if err := CheckOllama(context.Background(), srv.URL, m); err != nil {
		t.Fatal(err)
	}
	m.Serve.OllamaDigest = "def456"
	if err := CheckOllama(context.Background(), srv.URL, m); err == nil {
		t.Fatal("digest mismatch passed")
	}
}
