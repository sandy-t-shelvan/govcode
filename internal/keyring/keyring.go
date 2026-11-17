// Package keyring maps users to their public signing keys.
//
// A key file <dir>/<username>.pub is only trusted if the file is owned by
// that user's uid (they put it there themselves) or by root (the ISSO
// provisioned it), and is not group/world writable. One user therefore
// cannot register a key in another user's name, which is what makes
// "proposer != approver" meaningful.
package keyring

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/sandy-t-shelvan/govcode/internal/identity"
	"github.com/sandy-t-shelvan/govcode/internal/sign"
)

type Entry struct {
	Username string
	UID      int
	KeyID    string
	Pub      crypto.PublicKey  // Ed25519 or ECDSA P-256
	Cert     *x509.Certificate // set when the entry is a certificate (PIV/CAC)
	Path     string
}

// CertValidNow reports whether a certificate entry is inside its validity
// period now. Plain-key entries have no validity period.
func (e Entry) CertValidNow() error {
	if e.Cert == nil {
		return nil
	}
	now := time.Now()
	if now.Before(e.Cert.NotBefore) || now.After(e.Cert.NotAfter) {
		return fmt.Errorf("certificate for %s is valid %s to %s", e.Username, e.Cert.NotBefore.Format("2006-01-02"), e.Cert.NotAfter.Format("2006-01-02"))
	}
	return nil
}

type Keyring struct {
	Dir     string
	byKeyID map[string]Entry
	byUser  map[string][]Entry
	Skipped []string // files rejected, with reason
	roots   *x509.CertPool
}

func Load(dir string) (*Keyring, error) { return LoadWithCA(dir, nil) }

// LoadWithCA loads the keyring. With a CA pool, only certificate entries
// that chain to it are trusted; plain keys are skipped. The chain is
// checked as of the certificate's own validity period, so signatures made
// while it was valid still verify after it expires; whether a user may
// sign now is checked separately (CertValidNow).
func LoadWithCA(dir string, roots *x509.CertPool) (*Keyring, error) {
	k := &Keyring{Dir: dir, byKeyID: map[string]Entry{}, byUser: map[string][]Entry{}, roots: roots}
	ents, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return k, nil
		}
		return nil, err
	}
	for _, de := range ents {
		name := de.Name()
		if !strings.HasSuffix(name, ".pub") || de.IsDir() {
			continue
		}
		// <user>.pub or <user>.<n>.pub (key rotation)
		user := strings.SplitN(strings.TrimSuffix(name, ".pub"), ".", 2)[0]
		p := filepath.Join(dir, name)
		e, err := loadEntry(p, user)
		if err == nil && roots != nil {
			err = checkChain(e, roots)
		}
		if err != nil {
			k.Skipped = append(k.Skipped, fmt.Sprintf("%s: %v", name, err))
			continue
		}
		k.byKeyID[e.KeyID] = e
		k.byUser[user] = append(k.byUser[user], e)
	}
	return k, nil
}

func loadEntry(p, user string) (Entry, error) {
	fi, err := os.Lstat(p)
	if err != nil {
		return Entry{}, err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return Entry{}, fmt.Errorf("symlinks not accepted")
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return Entry{}, fmt.Errorf("group/world writable (mode %o)", fi.Mode().Perm())
	}
	uid, err := identity.Lookup(user)
	if err != nil {
		return Entry{}, fmt.Errorf("no such user %q", user)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return Entry{}, fmt.Errorf("cannot stat owner")
	}
	if int(st.Uid) != uid && st.Uid != 0 {
		return Entry{}, fmt.Errorf("owned by uid %d, must be owned by %s (uid %d) or root", st.Uid, user, uid)
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return Entry{}, err
	}
	pub, cert, err := sign.ParseUserKey(data)
	if err != nil {
		return Entry{}, err
	}
	return Entry{Username: user, UID: uid, KeyID: sign.KeyID(pub), Pub: pub, Cert: cert, Path: p}, nil
}

func checkChain(e Entry, roots *x509.CertPool) error {
	if e.Cert == nil {
		return fmt.Errorf("trust.user_ca is set: a certificate is required, not a bare public key")
	}
	at := e.Cert.NotBefore.Add(time.Minute)
	if at.After(e.Cert.NotAfter) {
		at = e.Cert.NotBefore
	}
	if _, err := e.Cert.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: at, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return fmt.Errorf("certificate does not chain to the site CA bundle: %v", err)
	}
	return nil
}

// RequiresCertificates reports whether the keyring was loaded with a CA.
func (k *Keyring) RequiresCertificates() bool { return k.roots != nil }

func (k *Keyring) ByKeyID(id string) (Entry, bool) { e, ok := k.byKeyID[id]; return e, ok }
func (k *Keyring) ForUser(u string) []Entry        { return k.byUser[u] }

// Register copies pub into the keyring as <username>.pub. The resulting file
// is owned by the caller, which is what binds it to them.
func Register(dir string, u identity.User, pub crypto.PublicKey) (string, error) {
	return register(dir, u, func(p string) error { return sign.WritePublic(p, pub) })
}

// RegisterPEM registers a PEM public key or certificate (e.g. a PIV
// certificate read from the card).
func RegisterPEM(dir string, u identity.User, data []byte) (string, error) {
	if _, _, err := sign.ParseUserKey(data); err != nil {
		return "", err
	}
	return register(dir, u, func(p string) error { return os.WriteFile(p, data, 0o644) })
}

func register(dir string, u identity.User, write func(string) error) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	p := filepath.Join(dir, u.Username+".pub")
	if _, err := os.Stat(p); err == nil {
		for i := 2; ; i++ {
			p = filepath.Join(dir, fmt.Sprintf("%s.%d.pub", u.Username, i))
			if _, err := os.Stat(p); os.IsNotExist(err) {
				break
			}
		}
	}
	if err := write(p); err != nil {
		return "", err
	}
	return p, os.Chmod(p, 0o644)
}
