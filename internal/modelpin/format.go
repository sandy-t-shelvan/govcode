package modelpin

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Weight formats. GGUF and safetensors are data-only. Python pickle (and
// PyTorch checkpoints, which are zip archives of pickles) can execute
// arbitrary code when loaded, so they are refused wherever they appear:
// in the lock, on the staging host and in the staged directory.
const (
	FormatGGUF        = "gguf"
	FormatSafetensors = "safetensors"
	FormatPickle      = "pickle"
	FormatTorchZip    = "pytorch-zip"
	FormatUnknown     = "unknown"
)

// PickleExtensions are names that conventionally hold pickled data.
var PickleExtensions = []string{".bin", ".pt", ".pth", ".ckpt", ".pkl", ".pickle", ".joblib", ".npy", ".npz"}

// WeightExtensions are files that must be one of the allowed weight formats.
var WeightExtensions = []string{".gguf", ".safetensors"}

func hasExt(p string, exts []string) bool {
	e := strings.ToLower(filepath.Ext(p))
	for _, x := range exts {
		if e == x {
			return true
		}
	}
	return false
}

// maxSafetensorsHeader bounds the JSON header (the format's own limit is
// 100 MB); anything larger is treated as not safetensors.
const maxSafetensorsHeader = 100 << 20

// Sniff identifies a weight file by its content, never by its name.
func Sniff(r io.ReaderAt, size int64) string {
	head := make([]byte, 8)
	n, _ := r.ReadAt(head, 0)
	head = head[:n]
	switch {
	case bytes.HasPrefix(head, []byte("GGUF")):
		return FormatGGUF
	case bytes.HasPrefix(head, []byte("PK\x03\x04")):
		return FormatTorchZip
	case len(head) >= 2 && head[0] == 0x80 && head[1] >= 2 && head[1] <= 5:
		return FormatPickle // pickle protocol 2-5 starts with PROTO
	}
	if n == 8 {
		hl := binary.LittleEndian.Uint64(head)
		if hl >= 2 && hl <= maxSafetensorsHeader && int64(hl) <= size-8 {
			hdr := make([]byte, hl)
			if m, _ := r.ReadAt(hdr, 8); uint64(m) == hl {
				var obj map[string]json.RawMessage
				if hdr[0] == '{' && json.Unmarshal(bytes.TrimRight(hdr, " "), &obj) == nil {
					return FormatSafetensors
				}
			}
		}
	}
	return FormatUnknown
}

// SniffFile opens path and identifies its format.
func SniffFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return "", err
	}
	return Sniff(f, st.Size()), nil
}

// CheckWeightFile refuses a file whose content is not GGUF or safetensors.
func CheckWeightFile(path string) error {
	f, err := SniffFile(path)
	if err != nil {
		return err
	}
	if f != FormatGGUF && f != FormatSafetensors {
		return fmt.Errorf("refused: content is %s; only GGUF and safetensors weights are allowed (pickle-based formats can execute code when loaded)", f)
	}
	if want := strings.TrimPrefix(strings.ToLower(filepath.Ext(path)), "."); (want == FormatGGUF || want == FormatSafetensors) && want != f {
		return fmt.Errorf("refused: named .%s but content is %s", want, f)
	}
	return nil
}

// CheckFormats refuses lock entries that name a pickle-based format: a
// served artifact that is not GGUF or safetensors, or any file (upstream,
// artifact or reference) with a pickle extension.
func (m *Model) CheckFormats() []Problem {
	var probs []Problem
	srcs := []struct {
		name string
		s    *Source
	}{{"upstream", &m.Upstream}, {"artifact", &m.Artifact}, {"reference_prequantized", m.Prequant}}
	for _, x := range srcs {
		if x.s == nil {
			continue
		}
		if f := strings.ToLower(x.s.Format); f != "" && f != FormatGGUF && f != FormatSafetensors {
			probs = append(probs, Problem{m.ID + " " + x.name, fmt.Sprintf("format %q is not allowed (GGUF or safetensors only)", x.s.Format)})
		}
		for _, f := range x.s.Files {
			if hasExt(f.Path, PickleExtensions) {
				probs = append(probs, Problem{m.ID + " " + x.name + " " + f.Path, "pickle-based file is not allowed"})
			}
		}
	}
	for _, f := range m.Artifact.Files {
		if !hasExt(f.Path, WeightExtensions) {
			probs = append(probs, Problem{m.ID + " artifact " + f.Path, "served artifact must be .gguf or .safetensors"})
		}
	}
	return probs
}
