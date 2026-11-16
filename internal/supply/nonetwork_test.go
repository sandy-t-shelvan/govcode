package supply

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoHiddenNetwork enforces, at build time, that only the netguard and
// llm packages can touch the network, and that nothing bypasses netguard's
// loopback-only client (http.Get, http.DefaultClient, net.Dial, ...).
func TestNoHiddenNetwork(t *testing.T) {
	allowedNet := map[string]bool{"internal/netguard": true, "internal/llm": true}
	forbiddenCalls := []string{"http.Get(", "http.Post(", "http.PostForm(", "http.Head(", "http.DefaultClient", "http.DefaultTransport", "net.Dial(", "net.DialTimeout(", "tls.Dial(", "net.Listen(", "http.ListenAndServe"}
	root := "../.."
	fset := token.NewFileSet()
	filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		pkg := filepath.ToSlash(filepath.Dir(rel))
		f, err := parser.ParseFile(fset, p, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("%s: %v", rel, err)
		}
		for _, imp := range f.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			if (path == "net" || path == "net/http" || path == "crypto/tls" || strings.HasPrefix(path, "net/rpc") || path == "net/smtp") && !allowedNet[pkg] {
				t.Errorf("%s imports %s; only %v may use the network", rel, path, keys(allowedNet))
			}
			if strings.Contains(path, ".") && !strings.HasPrefix(path, "github.com/sandy-t-shelvan/govcode/") {
				t.Errorf("%s imports third-party module %s; govcode is stdlib-only", rel, path)
			}
		}
		if pkg != "internal/netguard" {
			src, _ := os.ReadFile(p)
			for _, c := range forbiddenCalls {
				if strings.Contains(string(src), c) {
					t.Errorf("%s uses %s; all HTTP must go through netguard.Client", rel, c)
				}
			}
		}
		return nil
	})
}

func keys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestGoModHasNoRequires(t *testing.T) {
	b, _ := os.ReadFile("../../go.mod")
	for _, l := range strings.Split(string(b), "\n") {
		if f := strings.Fields(l); len(f) > 0 && f[0] == "require" {
			t.Fatal("go.mod has requirements; third-party modules need security review and SBOM update")
		}
	}
	if false {
		t.Fatal("go.mod has requirements; third-party modules need security review and SBOM update")
	}
	if _, err := os.Stat("../../go.sum"); err == nil {
		t.Fatal("go.sum present; govcode should have no module dependencies")
	}
}
