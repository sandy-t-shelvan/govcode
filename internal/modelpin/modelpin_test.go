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
	os.WriteFile(filepath.Join(dir, "weights", "m.gguf"), []byte("GGUFwts"), 0o644)
	sum, _, _ := HashFile(filepath.Join(dir, "weights", "m.gguf"))
	m := &Model{Artifact: Source{Files: []File{{Path: "m.gguf", Size: 7, SHA256: sum}}}}
	if p := VerifyArtifacts(m, dir, nil); len(p) != 0 {
		t.Fatalf("good file failed: %v", p)
	}
	os.WriteFile(filepath.Join(dir, "weights", "m.gguf"), []byte("GGUFwtz"), 0o644)
	if p := VerifyArtifacts(m, dir, nil); len(p) != 1 {
		t.Fatal("tampered weights passed")
	}
	m.Artifact.Files[0].SHA256 = Unfilled
	if p := VerifyArtifacts(m, dir, nil); len(p) != 1 {
		t.Fatal("unstaged lock passed")
	}
}

func TestVerifyArtifactsChatTemplate(t *testing.T) {
	dir := t.TempDir()
	w := filepath.Join(dir, "weights")
	os.MkdirAll(w, 0o755)
	os.WriteFile(filepath.Join(w, "m.gguf"), []byte("GGUFwts"), 0o644)
	os.WriteFile(filepath.Join(w, "m.jinja"), []byte("{{ tools }}"), 0o644)
	gs, _, _ := HashFile(filepath.Join(w, "m.gguf"))
	ts, _, _ := HashFile(filepath.Join(w, "m.jinja"))
	m := &Model{
		Artifact: Source{Files: []File{{Path: "m.gguf", SHA256: gs}}},
		Serve:    Serve{LlamaCppChatTemplate: &ChatTemplate{File: File{Path: "m.jinja", Size: 11, SHA256: ts}}},
	}
	// A template is text, not GGUF/safetensors: it must not be refused as a weight.
	if p := VerifyArtifacts(m, dir, nil); len(p) != 0 {
		t.Fatalf("good template failed: %v", p)
	}
	os.WriteFile(filepath.Join(w, "m.jinja"), []byte("{{ nothing }}"), 0o644)
	if p := VerifyArtifacts(m, dir, nil); len(p) == 0 {
		t.Fatal("tampered chat template passed")
	}
	os.Remove(filepath.Join(w, "m.jinja"))
	if p := VerifyArtifacts(m, dir, nil); len(p) != 1 {
		t.Fatal("missing chat template passed")
	}
	m.Serve.LlamaCppChatTemplate.SHA256 = Unfilled
	if p := VerifyArtifacts(m, dir, nil); len(p) != 1 {
		t.Fatal("unstaged chat template passed")
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
