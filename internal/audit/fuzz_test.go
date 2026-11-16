package audit

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzVerifyGarbage: a log file containing arbitrary bytes must never
// verify as OK and must never panic the verifier.
func FuzzVerifyGarbage(f *testing.F) {
	f.Add([]byte(`{"v":1,"seq":0,"prev":"` + GenesisPrev + `","hash":"x","sig":"y"}` + "\n"))
	f.Add([]byte("not json\n"))
	f.Add([]byte("{}\n{}\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		fx := setup(t)
		os.WriteFile(filepath.Join(fx.log.Dir, "log.jsonl"), data, 0o660)
		r, err := fx.log.Verify(fx.kr, nil, false)
		if err != nil {
			return
		}
		if r.Entries > 0 && r.OK() {
			t.Fatalf("garbage log verified OK: %q", data)
		}
	})
}
