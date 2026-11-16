// Package keyring maps users to their public signing keys.
//
// A key file <dir>/<username>.pub is only trusted if the file is owned by
// that user's uid (they put it there themselves) or by root (the ISSO
// provisioned it), and is not group/world writable. One user therefore
// cannot register a key in another user's name, which is what makes
// "proposer != approver" meaningful.
package keyring

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/sandy-t-shelvan/govcode/internal/identity"
	"github.com/sandy-t-shelvan/govcode/internal/sign"
)

type Entry struct {
	Username string
	UID      int
	KeyID    string
	Pub      ed25519.PublicKey
	Path     string
}

type Keyring struct {
	Dir     string
	byKeyID map[string]Entry
	byUser  map[string][]Entry
	Skipped []string // files rejected, with reason
}

func Load(dir string) (*Keyring, error) {
	k := &Keyring{Dir: dir, byKeyID: map[string]Entry{}, byUser: map[string][]Entry{}}
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
	pub, err := sign.LoadPublic(p)
	if err != nil {
		return Entry{}, err
	}
	return Entry{Username: user, UID: uid, KeyID: sign.KeyID(pub), Pub: pub, Path: p}, nil
}

func (k *Keyring) ByKeyID(id string) (Entry, bool) { e, ok := k.byKeyID[id]; return e, ok }
func (k *Keyring) ForUser(u string) []Entry        { return k.byUser[u] }

// Register copies pub into the keyring as <username>.pub. The resulting file
// is owned by the caller, which is what binds it to them.
func Register(dir string, u identity.User, pub ed25519.PublicKey) (string, error) {
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
	if err := sign.WritePublic(p, pub); err != nil {
		return "", err
	}
	return p, os.Chmod(p, 0o644)
}
