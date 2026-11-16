package audit

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/sandy-t-shelvan/govcode/internal/keyring"
	"github.com/sandy-t-shelvan/govcode/internal/sign"
)

type Report struct {
	Entries  int
	Head     *Entry
	Problems []string
	Actors   map[string]int
	Anchors  int
}

func (r *Report) OK() bool { return len(r.Problems) == 0 }

func (r *Report) fail(format string, a ...any) {
	if len(r.Problems) < 200 {
		r.Problems = append(r.Problems, fmt.Sprintf(format, a...))
	}
}

// Verify checks, for every entry: valid JSON, sequence continuity, hash
// recomputation, chain link to the previous hash, that the signing key is
// in the keyring and belongs to the user named as actor, the signature, and
// that every referenced object exists with the right content hash.
// anchors (seq -> hash) found in git history must all be present.
func (l *Log) Verify(kr *keyring.Keyring, anchors map[uint64]string, checkObjects bool) (*Report, error) {
	r := &Report{Actors: map[string]int{}}
	prev := GenesisPrev
	var expect uint64
	seen := map[uint64]string{}
	err := l.Each(func(e *Entry, _ []byte) error {
		r.Entries++
		if e.Seq != expect {
			r.fail("seq %d: expected seq %d (entries missing, duplicated or reordered)", e.Seq, expect)
			expect = e.Seq
		}
		expect++
		if e.Prev != prev {
			r.fail("seq %d: prev=%s… does not match hash of previous entry %s… (chain broken)", e.Seq, short(e.Prev), short(prev))
		}
		h, err := e.computeHash()
		if err != nil || h != e.Hash {
			r.fail("seq %d: content does not match its hash (entry modified)", e.Seq)
		}
		prev = e.Hash
		seen[e.Seq] = e.Hash
		k, ok := kr.ByKeyID(e.KeyID)
		switch {
		case !ok:
			r.fail("seq %d: signing key %s is not in the keyring", e.Seq, e.KeyID)
		case k.Username != e.Actor.Username || k.UID != e.Actor.UID:
			r.fail("seq %d: signed by key of %s but actor claims %s (impersonation)", e.Seq, k.Username, e.Actor.Username)
		default:
			sig, _ := base64.StdEncoding.DecodeString(e.Sig)
			hb, _ := hex.DecodeString(e.Hash)
			if !sign.Verify(k.Pub, hb, sig) {
				r.fail("seq %d: bad signature", e.Seq)
			}
		}
		r.Actors[e.Actor.Username]++
		if checkObjects {
			for name, id := range e.Objects {
				if _, err := l.GetObject(id); err != nil {
					r.fail("seq %d: object %s (%s): %v", e.Seq, name, short(id), err)
				}
			}
		}
		ce := *e
		r.Head = &ce
		return nil
	})
	if err != nil {
		r.fail("%v", err)
	}
	for seq, h := range anchors {
		r.Anchors++
		got, ok := seen[seq]
		if !ok {
			r.fail("anchor seq %d (recorded in git history) is missing from the log: log was truncated or replaced", seq)
		} else if got != h {
			r.fail("anchor seq %d: git history says %s…, log has %s… (log rewritten)", seq, short(h), short(got))
		}
	}
	return r, nil
}

func short(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}
