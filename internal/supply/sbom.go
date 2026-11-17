package supply

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"

	"github.com/sandy-t-shelvan/govcode/internal/modelpin"
)

// Extra is an additional shipped artifact (e.g. the VS Code extension).
type Extra struct {
	Name, Type, Path, Description string
}

// SystemTool is an external executable govcode invokes. Each is listed in
// the SBOM with its resolved path, version string and SHA-256 so the
// reviewer can compare against the site's approved software baseline.
type SystemTool struct {
	Name     string
	Args     []string // to print version
	Required bool
	Purpose  string
}

var SystemTools = []SystemTool{
	{"git", []string{"--version"}, true, "repository operations (worktrees, diff, commit, merge-tree)"},
	{"bwrap", []string{"--version"}, false, "command sandbox (no network, worktree-only writes)"},
	{"ollama", []string{"--version"}, false, "local model server"},
	{"llama-server", []string{"--version"}, false, "local model server (llama.cpp)"},
	{"vllm", []string{"--version"}, false, "local model server (vLLM)"},
	{"bash", []string{"--version"}, true, "shell for run_tests/run_command"},
}

type ToolInfo struct {
	Name, Path, Version, SHA256, Purpose string
	Required, Found                      bool
}

func ProbeTools() []ToolInfo {
	var out []ToolInfo
	for _, t := range SystemTools {
		ti := ToolInfo{Name: t.Name, Required: t.Required, Purpose: t.Purpose}
		if p, err := exec.LookPath(t.Name); err == nil {
			real, _ := filepath.EvalSymlinks(p)
			ti.Path, ti.Found = real, true
			if v, err := exec.Command(p, t.Args...).CombinedOutput(); err == nil {
				ti.Version = strings.TrimSpace(strings.SplitN(string(v), "\n", 2)[0])
			}
			ti.SHA256, _, _ = modelpin.HashFile(real)
		}
		out = append(out, ti)
	}
	return out
}

// SBOM describes this binary (from embedded build info, so it reflects
// exactly what was linked), its Go module dependencies, the Go toolchain,
// the system tools found on this host, and optionally the model set.
func SBOM(lock *modelpin.Lock, extras ...Extra) (*BOM, error) {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return nil, fmt.Errorf("binary has no build info")
	}
	exe, _ := os.Executable()
	selfHash, _, _ := modelpin.HashFile(exe)
	main := Component{
		BOMRef: "pkg:golang/" + bi.Main.Path, Type: "application", Name: "govcode",
		Version: Version, Purl: fmt.Sprintf("pkg:golang/%s@%s", bi.Main.Path, Version),
		Licenses: License("MIT"),
	}
	if selfHash != "" {
		main.Hashes = []Hash{{"SHA-256", selfHash}}
	}
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision", "vcs.time", "vcs.modified", "CGO_ENABLED", "GOOS", "GOARCH", "-trimpath", "-ldflags", "GOFIPS140", "GOAMD64", "DefaultGODEBUG":
			main.Properties = append(main.Properties, Property{"build:" + s.Key, s.Value})
		}
	}
	b := newBOM(main)
	b.Components = append(b.Components, Component{
		BOMRef: "pkg:golang/stdlib@" + bi.GoVersion, Type: "framework", Name: "go-stdlib",
		Version: strings.TrimPrefix(bi.GoVersion, "go"), Purl: "pkg:golang/stdlib@" + strings.TrimPrefix(bi.GoVersion, "go"),
		Licenses: License("BSD-3-Clause"), Description: "Go standard library and runtime (statically linked)",
		Properties: []Property{{"runtime:GOOS/GOARCH", runtime.GOOS + "/" + runtime.GOARCH}},
	})
	deps := []string{"pkg:golang/stdlib@" + bi.GoVersion}
	for _, d := range bi.Deps {
		m := d
		if d.Replace != nil {
			m = d.Replace
		}
		ref := fmt.Sprintf("pkg:golang/%s@%s", m.Path, m.Version)
		c := Component{BOMRef: ref, Type: "library", Name: m.Path, Version: m.Version, Purl: ref}
		if m.Sum != "" {
			c.Properties = []Property{{"go:sum", m.Sum}}
		}
		b.Components = append(b.Components, c)
		deps = append(deps, ref)
	}
	for _, t := range ProbeTools() {
		c := Component{BOMRef: "system:" + t.Name, Type: "application", Name: t.Name, Version: t.Version, Description: t.Purpose,
			Properties: []Property{{"govcode:required", fmt.Sprint(t.Required)}, {"govcode:found", fmt.Sprint(t.Found)}}}
		if t.Found {
			c.Properties = append(c.Properties, Property{"path", t.Path})
			c.Hashes = []Hash{{"SHA-256", t.SHA256}}
		}
		b.Components = append(b.Components, c)
		if t.Found {
			deps = append(deps, c.BOMRef)
		}
	}
	for _, x := range extras {
		sum, size, err := modelpin.HashFile(x.Path)
		if err != nil {
			return nil, fmt.Errorf("sbom extra %s: %w", x.Name, err)
		}
		c := Component{BOMRef: "file:" + x.Name, Type: x.Type, Name: x.Name, Version: Version, Description: x.Description,
			Hashes: []Hash{{"SHA-256", sum}}, Licenses: License("MIT"), Properties: []Property{{"size", fmt.Sprint(size)}}}
		b.Components = append(b.Components, c)
		deps = append(deps, c.BOMRef)
	}
	if lock != nil {
		ai := AIBOM(lock)
		b.Components = append(b.Components, ai.Components...)
		b.Dependencies = append(b.Dependencies, ai.Dependencies...)
		for _, c := range ai.Components {
			deps = append(deps, c.BOMRef)
		}
	}
	b.Dependencies = append(b.Dependencies, Dependency{Ref: main.BOMRef, DependsOn: deps})
	b.Metadata.Properties = []Property{{"govcode:third_party_go_modules", fmt.Sprint(len(bi.Deps))}}
	return b, nil
}
