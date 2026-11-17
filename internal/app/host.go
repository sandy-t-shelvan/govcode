package app

import (
	"crypto/fips140"
	"os"
	"strings"
)

// Host security checks for STIG-hardened RHEL: kernel FIPS mode, the Go
// Cryptographic Module running in FIPS mode, and SELinux enforcing. The
// paths are variables so tests can point them at fixtures.
var (
	fipsPath    = "/proc/sys/crypto/fips_enabled"
	selinuxPath = "/sys/fs/selinux/enforce"
	goFIPS      = fips140.Enabled
)

func readFlag(path string) (string, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(b)), true
}

// checkHost reports FIPS and SELinux state. With host.require_* set, a
// missing property is a FAIL (and fatal); otherwise strict mode warns.
func (a *App) checkHost(add func(name, status, detail string)) {
	p := a.Policy
	miss := func(required bool) string {
		switch {
		case required:
			return "FAIL"
		case p.Strict():
			return "WARN"
		}
		return "SKIP"
	}
	kernel, ok := readFlag(fipsPath)
	switch {
	case ok && kernel == "1" && goFIPS():
		add("host FIPS", "PASS", "kernel FIPS mode on; Go Cryptographic Module in FIPS 140-3 mode")
	case ok && kernel == "1":
		add("host FIPS", miss(p.Host.RequireFIPS), "kernel FIPS mode on, but this govcode binary is not in FIPS mode (use a release build: GOFIPS140=v1.0.0)")
	case !goFIPS():
		add("host FIPS", miss(p.Host.RequireFIPS), "kernel FIPS mode off and this binary is not in FIPS mode")
	default:
		add("host FIPS", miss(p.Host.RequireFIPS), "binary in FIPS mode, but kernel FIPS mode is off (fips-mode-setup --enable)")
	}
	switch v, ok := readFlag(selinuxPath); {
	case ok && v == "1":
		add("SELinux", "PASS", "enforcing")
	case ok:
		add("SELinux", miss(p.Host.RequireSELinux), "permissive (setenforce 1, and SELINUX=enforcing in /etc/selinux/config)")
	default:
		add("SELinux", miss(p.Host.RequireSELinux), "not enabled on this host")
	}
}
