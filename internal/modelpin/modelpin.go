// Package modelpin verifies that the model being served is exactly the one
// pinned in the signed lock file.
package modelpin

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/sandy-t-shelvan/govcode/internal/llm"
	"github.com/sandy-t-shelvan/govcode/internal/sign"
)

const Unfilled = "FILL_AT_STAGING"

type File struct {
	Path        string `json:"path"`
	Size        int64  `json:"size"`
	SHA256      string `json:"sha256"`
	GitBlobSHA1 string `json:"git_blob_sha1,omitempty"`
}

type Source struct {
	Repo       string `json:"repo"`
	Revision   string `json:"revision"`
	Files      []File `json:"files"`
	Format     string `json:"format,omitempty"`
	Quant      string `json:"quantization,omitempty"`
	ProducedBy string `json:"produced_by,omitempty"`
	Note       string `json:"note,omitempty"`
}

type Serve struct {
	OllamaName     string  `json:"ollama_name"`
	NumCtx         int     `json:"num_ctx"`
	MaxTokens      int     `json:"max_tokens"`
	Temperature    float64 `json:"temperature"`
	VLLMToolParser string  `json:"vllm_tool_call_parser"`
	OllamaDigest   string  `json:"ollama_manifest_digest"`
	// ToolPrompt, if set, is appended to the system prompt when tools are
	// offered (see llm.Options.ToolPrompt). It is part of the signed lock
	// because it changes how the model behaves.
	ToolPrompt string `json:"tool_prompt,omitempty"`
	// LlamaCppChatTemplate, if set, is the Jinja chat template llama-server
	// must use instead of the one embedded in the GGUF (passed with
	// --chat-template-file). Some first-party GGUFs embed a template with no
	// tool support, and llama.cpp then drops the tools without an error.
	// It is staged under weights/ and verified like a weight file.
	LlamaCppChatTemplate *ChatTemplate `json:"llamacpp_chat_template,omitempty"`
}

// ChatTemplate is a staged Jinja chat template and where it came from.
type ChatTemplate struct {
	File
	// Source names the pinned origin, e.g. "ggml-org/llama.cpp@<commit>:<path>".
	Source string `json:"source"`
}

// Lineage names a model this one was derived from (fine-tuned, distilled
// or merged), with the country of its publisher.
type Lineage struct {
	Model     string `json:"model"`
	Publisher string `json:"publisher"`
	Origin    string `json:"origin"`
}

type Model struct {
	ID        string `json:"id"`
	Default   bool   `json:"default,omitempty"`
	Name      string `json:"name"`
	License   string `json:"license"`
	Publisher string `json:"publisher"`
	// Origin is the publisher's country as an ISO 3166-1 alpha-2 code.
	Origin      string    `json:"origin"`
	DerivedFrom []Lineage `json:"derived_from,omitempty"`
	Upstream    Source    `json:"upstream"`
	Artifact    Source    `json:"artifact"`
	Prequant    *Source   `json:"reference_prequantized,omitempty"`
	Serve       Serve     `json:"serve"`
	// StagingScan is the low-side malware scan of the staged weights,
	// recorded by stage-models.sh inside the signed lock.
	StagingScan *Scan `json:"staging_scan,omitempty"`
}

type Scan struct {
	Scanner    string `json:"scanner"`
	Version    string `json:"version"`
	Signatures string `json:"signatures,omitempty"` // signature database version/date
	Result     string `json:"result"`               // "clean" or the scanner's finding
	ScannedAt  string `json:"scanned_at"`
}

type Lock struct {
	Schema string  `json:"schema"`
	Models []Model `json:"models"`
}

func Parse(data []byte) (*Lock, error) {
	var l Lock
	if err := json.Unmarshal(data, &l); err != nil {
		return nil, err
	}
	if l.Schema != "govcode.models.lock/v1" {
		return nil, fmt.Errorf("unknown lock schema %q", l.Schema)
	}
	return &l, nil
}

// LoadVerified loads the lock only if its detached signature verifies
// against one of the trusted model-signing keys.
func LoadVerified(path string, trusted []ed25519.PublicKey) (*Lock, string, error) {
	data, kid, err := sign.VerifyFile(path, trusted...)
	if err != nil {
		return nil, "", err
	}
	l, err := Parse(data)
	return l, kid, err
}

func Load(path string) (*Lock, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

func (l *Lock) Find(id string) (*Model, error) {
	for i := range l.Models {
		if l.Models[i].ID == id || (id == "" && l.Models[i].Default) {
			return &l.Models[i], nil
		}
	}
	return nil, fmt.Errorf("model %q not in lock file", id)
}

// Problem is one verification failure.
type Problem struct {
	Path string
	Msg  string
}

// VerifyArtifacts streams every staged artifact file under dir/weights and
// checks size and SHA-256. Unfilled hashes are a failure: a lock that has not
// been through staging must never be trusted.
func VerifyArtifacts(m *Model, dir string, progress func(string)) []Problem {
	var probs []Problem
	for _, f := range m.Artifact.Files {
		probs = append(probs, verifyFile(dir, f, true, progress)...)
	}
	if t := m.Serve.LlamaCppChatTemplate; t != nil {
		probs = append(probs, verifyFile(dir, t.File, false, progress)...)
	}
	return probs
}

// VerifyUpstream checks the first-party upstream files staged for serving
// directly (vLLM loads safetensors from dir/weights/<model id>/). If that
// directory is absent nothing is checked: GGUF-only stagings do not carry
// upstream weights. If it is present, every upstream file in the lock must be
// there and match, and nothing else may be: vLLM picks up weight files in
// that directory by pattern, so an extra shard would be loaded unpinned.
func VerifyUpstream(m *Model, dir string, progress func(string)) []Problem {
	sub := filepath.Join(dir, "weights", m.ID)
	if fi, err := os.Stat(sub); err != nil || !fi.IsDir() {
		return nil
	}
	var probs []Problem
	pinned := map[string]bool{}
	for _, f := range m.Upstream.Files {
		pinned[filepath.Clean(f.Path)] = true
		f.Path = filepath.Join(m.ID, f.Path)
		ext := strings.ToLower(filepath.Ext(f.Path))
		probs = append(probs, verifyFile(dir, f, ext == ".safetensors" || ext == ".gguf", progress)...)
	}
	err := filepath.WalkDir(sub, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(sub, p)
		if !pinned[rel] {
			probs = append(probs, Problem{p, "file is not in the lock (unpinned files must not be staged next to served weights)"})
		}
		return nil
	})
	if err != nil {
		probs = append(probs, Problem{sub, err.Error()})
	}
	return probs
}

// verifyFile checks one staged file under dir/weights against the lock.
// Weight files must also be GGUF or safetensors by content; a chat template
// is text, so that check is skipped for it.
func verifyFile(dir string, f File, weight bool, progress func(string)) []Problem {
	p := filepath.Join(dir, "weights", f.Path)
	if f.SHA256 == "" || f.SHA256 == Unfilled {
		return []Problem{{p, "lock has no SHA-256 for this file (not staged)"}}
	}
	if weight {
		if err := CheckWeightFile(p); err != nil {
			return []Problem{{p, err.Error()}}
		}
	}
	if progress != nil {
		progress(p)
	}
	sum, size, err := HashFile(p)
	if err != nil {
		return []Problem{{p, err.Error()}}
	}
	var probs []Problem
	if f.Size > 0 && size != f.Size {
		probs = append(probs, Problem{p, fmt.Sprintf("size %d, lock says %d", size, f.Size)})
	}
	if sum != f.SHA256 {
		probs = append(probs, Problem{p, fmt.Sprintf("sha256 %s, lock says %s", sum, f.SHA256)})
	}
	return probs
}

func HashFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// CheckOllama confirms the model Ollama will serve has the pinned manifest
// digest. A model re-pulled, re-created or swapped on disk changes digest.
func CheckOllama(ctx context.Context, baseURL string, m *Model) error {
	want := strings.TrimPrefix(m.Serve.OllamaDigest, "sha256:")
	if want == "" || want == Unfilled {
		return fmt.Errorf("lock has no ollama_manifest_digest for %s (not staged)", m.ID)
	}
	models, err := llm.ListOllamaModels(ctx, baseURL)
	if err != nil {
		return fmt.Errorf("cannot query ollama at %s: %w", baseURL, err)
	}
	for _, om := range models {
		if om.Name == m.Serve.OllamaName || om.Name == m.Serve.OllamaName+":latest" {
			got := strings.TrimPrefix(om.Digest, "sha256:")
			if got != want {
				return fmt.Errorf("ollama model %s digest %s does not match pinned %s", om.Name, got, want)
			}
			return nil
		}
	}
	return fmt.Errorf("ollama does not have model %s", m.Serve.OllamaName)
}
