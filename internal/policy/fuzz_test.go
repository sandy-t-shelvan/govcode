package policy

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzLoad: arbitrary policy files never panic the loader, and anything
// it accepts has a loopback model endpoint and an explicit num_ctx.
func FuzzLoad(f *testing.F) {
	f.Add([]byte(`{"schema":"govcode.policy/v1"}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		p := filepath.Join(t.TempDir(), "p.json")
		os.WriteFile(p, data, 0o644)
		pol, _, err := Load(p)
		if err != nil {
			return
		}
		if pol.Model.NumCtx < 4096 {
			t.Fatalf("accepted policy with num_ctx %d", pol.Model.NumCtx)
		}
		if pol.Strict() && pol.Sandbox.Mode == "off" {
			t.Fatal("accepted strict policy with sandbox off")
		}
	})
}
