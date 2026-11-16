package supply

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sandy-t-shelvan/govcode/internal/modelpin"
	"github.com/sandy-t-shelvan/govcode/internal/sign"
)

// Manifest lists every file in a release with its SHA-256. It is signed by
// the release key; the binary refuses to run (in strict mode) unless its own
// hash appears in a manifest signed by a trusted key.
type Manifest struct {
	Schema  string         `json:"schema"`
	Version string         `json:"version"`
	Files   []ManifestFile `json:"files"`
}

type ManifestFile struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	Role   string `json:"role,omitempty"`
}

const ManifestSchema = "govcode.release.manifest/v1"

func BuildManifest(dir, version string, files map[string]string) (*Manifest, error) {
	m := &Manifest{Schema: ManifestSchema, Version: version}
	for rel, role := range files {
		sum, size, err := modelpin.HashFile(filepath.Join(dir, rel))
		if err != nil {
			return nil, err
		}
		m.Files = append(m.Files, ManifestFile{Path: rel, Size: size, SHA256: sum, Role: role})
	}
	sortFiles(m.Files)
	return m, nil
}

func sortFiles(fs []ManifestFile) {
	for i := 1; i < len(fs); i++ {
		for j := i; j > 0 && fs[j].Path < fs[j-1].Path; j-- {
			fs[j], fs[j-1] = fs[j-1], fs[j]
		}
	}
}

// VerifySelf checks that the running executable is listed, with matching
// hash, in a manifest whose signature verifies against a trusted key.
func VerifySelf(manifestPath string, trusted []ed25519.PublicKey) (string, error) {
	data, kid, err := sign.VerifyFile(manifestPath, trusted...)
	if err != nil {
		return "", err
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil || m.Schema != ManifestSchema {
		return "", fmt.Errorf("bad release manifest")
	}
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	exe, _ = filepath.EvalSymlinks(exe)
	sum, _, err := modelpin.HashFile(exe)
	if err != nil {
		return "", err
	}
	for _, f := range m.Files {
		if f.Role == "binary" && f.SHA256 == sum {
			return fmt.Sprintf("binary %s matches manifest %s (signed by %s)", sum[:16], m.Version, kid), nil
		}
	}
	return "", fmt.Errorf("this binary (sha256 %s) is not in the signed release manifest %s", sum, manifestPath)
}
