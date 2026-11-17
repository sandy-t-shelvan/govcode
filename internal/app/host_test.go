package app

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sandy-t-shelvan/govcode/internal/policy"
)

func hostFixture(t *testing.T, fips, selinux string, goMode bool) {
	t.Helper()
	dir := t.TempDir()
	of, os2, og := fipsPath, selinuxPath, goFIPS
	t.Cleanup(func() { fipsPath, selinuxPath, goFIPS = of, os2, og })
	fipsPath, selinuxPath = filepath.Join(dir, "fips"), filepath.Join(dir, "enforce")
	if fips != "" {
		os.WriteFile(fipsPath, []byte(fips+"\n"), 0o644)
	}
	if selinux != "" {
		os.WriteFile(selinuxPath, []byte(selinux), 0o644)
	}
	goFIPS = func() bool { return goMode }
}

func requireHost(p *policy.Policy) { p.Host = policy.Host{RequireFIPS: true, RequireSELinux: true} }

func TestHostChecksPassOnHardenedHost(t *testing.T) {
	hostFixture(t, "1", "1", true)
	_, checks, err := openWorld(t, requireHost)
	if err != nil || !hasCheck(checks, "host FIPS", "PASS") || !hasCheck(checks, "SELinux", "PASS") {
		t.Fatalf("%v %+v", err, checks)
	}
}

func TestHostChecksFailWhenRequired(t *testing.T) {
	for name, tc := range map[string]struct {
		fips, se string
		goMode   bool
		want     string
	}{
		"kernel fips off":    {"0", "1", true, "kernel FIPS mode is off"},
		"binary not fips":    {"1", "1", false, "not in FIPS mode"},
		"selinux permissive": {"1", "0", true, "permissive"},
		"selinux absent":     {"1", "", true, "not enabled"},
	} {
		t.Run(name, func(t *testing.T) {
			hostFixture(t, tc.fips, tc.se, tc.goMode)
			_, _, err := openWorld(t, requireHost)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want failure containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestHostChecksAdvisoryWhenNotRequired(t *testing.T) {
	hostFixture(t, "0", "", false)
	_, checks, err := openWorld(t, nil) // dev policy: warn mode, nothing required
	if err != nil || !hasCheck(checks, "host FIPS", "SKIP") || !hasCheck(checks, "SELinux", "SKIP") {
		t.Fatalf("%v %+v", err, checks)
	}
}

// Mirrors the RPM %post: an empty, pre-created, chattr +a audit log must be
// accepted with audit.require_append_only, and runs must append to it.
func TestPrecreatedAppendOnlyAuditLog(t *testing.T) {
	var logPath string
	a, checks, err := openWorld(t, func(p *policy.Policy) {
		p.Audit.RequireAppendOnly = true
		dir := filepath.Join(p.StateDir, "audit")
		os.MkdirAll(dir, 0o2770)
		logPath = filepath.Join(dir, "log.jsonl")
		os.WriteFile(logPath, nil, 0o660)
		if out, err := exec.Command("chattr", "+a", logPath).CombinedOutput(); err != nil {
			t.Skipf("chattr +a unavailable here: %v %s", err, out)
		}
		t.Cleanup(func() { exec.Command("chattr", "-a", logPath).Run() })
	})
	if err != nil || !hasCheck(checks, "audit log", "PASS") {
		t.Fatalf("%v %+v", err, checks)
	}
	if _, err := a.Run(context.Background(), RunOptions{Task: "set port to 2", Backend: edit("int port = 2;")}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(logPath, []byte("x"), 0o660); err == nil {
		t.Fatal("append-only log was overwritten")
	}
	rep, err := a.Log.Verify(a.Keyring, nil, true)
	if err != nil || rep == nil {
		t.Fatalf("verify: %v %+v", err, rep)
	}
}
