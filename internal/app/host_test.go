package app

import (
	"os"
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
