package modelpin

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func safetensors(hdr string) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(len(hdr)))
	return append(append(b, hdr...), make([]byte, 16)...)
}

// A minimal pickle (protocol 4) whose REDUCE would call os.system on load.
var evilPickle = []byte("\x80\x04\x95\x1f\x00\x00\x00\x00\x00\x00\x00\x8c\x02os\x8c\x06system\x93\x8c\x05touch\x85R.")

func TestSniff(t *testing.T) {
	for name, tc := range map[string]struct {
		data []byte
		want string
	}{
		"gguf":              {[]byte("GGUF\x03\x00\x00\x00rest"), FormatGGUF},
		"safetensors":       {safetensors(`{"w":{"dtype":"F16","shape":[2],"data_offsets":[0,4]}}  `), FormatSafetensors},
		"pickle":            {evilPickle, FormatPickle},
		"torch zip":         {[]byte("PK\x03\x04archive/data.pkl"), FormatTorchZip},
		"empty":             {nil, FormatUnknown},
		"text":              {[]byte("hello world, not weights"), FormatUnknown},
		"bad st header":     {safetensors(`not json`), FormatUnknown},
		"st length too big": {append([]byte{0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0}, '{', '}'), FormatUnknown},
	} {
		if got := Sniff(bytes.NewReader(tc.data), int64(len(tc.data))); got != tc.want {
			t.Errorf("%s: %s, want %s", name, got, tc.want)
		}
	}
}

func TestPickleNamedGGUFIsRefused(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "weights"), 0o755)
	p := filepath.Join(dir, "weights", "m.gguf")
	os.WriteFile(p, evilPickle, 0o644)
	sum, _, _ := HashFile(p)
	// Even with a matching hash in the lock, the content is refused.
	m := &Model{Artifact: Source{Files: []File{{Path: "m.gguf", SHA256: sum}}}}
	probs := VerifyArtifacts(m, dir, nil)
	if len(probs) != 1 || !strings.Contains(probs[0].Msg, "content is pickle") {
		t.Fatalf("pickle accepted: %v", probs)
	}
	os.WriteFile(p, safetensors(`{"a":{}}`), 0o644)
	if err := CheckWeightFile(p); err == nil || !strings.Contains(err.Error(), "named .gguf but content is safetensors") {
		t.Errorf("format/name mismatch accepted: %v", err)
	}
	st := filepath.Join(dir, "weights", "x.safetensors")
	os.WriteFile(st, safetensors(`{"a":{}}`), 0o644)
	if err := CheckWeightFile(st); err != nil {
		t.Errorf("safetensors refused: %v", err)
	}
}

func TestLockFormats(t *testing.T) {
	l, err := Load("../../models/models.lock.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range l.Models {
		if p := m.CheckFormats(); len(p) != 0 {
			t.Errorf("repo lock %s: %v", m.ID, p)
		}
	}
	bad := &Model{ID: "x", Upstream: Source{Files: []File{{Path: "pytorch_model.bin"}}},
		Artifact: Source{Format: "pytorch", Files: []File{{Path: "model.pt"}}}}
	if p := bad.CheckFormats(); len(p) != 4 {
		t.Errorf("want 4 problems (bin, format, pt, non-weight artifact), got %v", p)
	}
}

func FuzzSniff(f *testing.F) {
	f.Add([]byte("GGUF"))
	f.Add(safetensors(`{"a":{}}`))
	f.Add(evilPickle)
	f.Fuzz(func(t *testing.T, data []byte) {
		got := Sniff(bytes.NewReader(data), int64(len(data)))
		if got == FormatGGUF && !bytes.HasPrefix(data, []byte("GGUF")) {
			t.Fatal("GGUF without magic")
		}
		if (got == FormatGGUF || got == FormatSafetensors) && len(data) > 1 && data[0] == 0x80 && data[1] >= 2 && data[1] <= 5 {
			t.Fatal("pickle protocol header accepted as weights")
		}
	})
}
