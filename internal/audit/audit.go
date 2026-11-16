// Package audit implements the append-only, hash-chained, signed log.
//
// Each line of log.jsonl is one Entry. Entry.Hash is SHA-256 over the
// canonical JSON of the entry with Hash and Sig empty; that includes Prev,
// the previous entry's Hash, so editing, reordering or deleting any entry
// breaks every later link. Entry.Sig is the acting user's Ed25519 signature
// over Hash. Full payloads (prompts, model output, tool output, diffs) are
// stored content-addressed in objects/ and referenced by SHA-256.
//
// Tail truncation (deleting the newest entries) cannot be detected from the
// chain alone; it is detected by anchors: every commit that lands on a
// protected branch carries a "Govcode-Audit-Anchor: <seq>:<hash>" trailer,
// and `govcode audit verify` checks that each anchor exists in the log.
//
// The log records the code it describes and is classified at that level.
package audit

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"

	"github.com/sandy-t-shelvan/govcode/internal/identity"
	"github.com/sandy-t-shelvan/govcode/internal/sign"
)

const GenesisPrev = "0000000000000000000000000000000000000000000000000000000000000000"

type Entry struct {
	V              int               `json:"v"`
	Seq            uint64            `json:"seq"`
	Time           string            `json:"ts"`
	Prev           string            `json:"prev"`
	Classification string            `json:"classification"`
	Repo           string            `json:"repo"`
	Session        string            `json:"session"`
	Actor          identity.User     `json:"actor"`
	Kind           string            `json:"kind"`
	Summary        map[string]any    `json:"summary,omitempty"`
	Objects        map[string]string `json:"objects,omitempty"` // name -> sha256 of stored object
	KeyID          string            `json:"key_id"`
	Hash           string            `json:"hash"`
	Sig            string            `json:"sig"`
}

func (e *Entry) computeHash() (string, error) {
	c := *e
	c.Hash, c.Sig = "", ""
	b, err := json.Marshal(&c) // struct field order + sorted map keys = canonical
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}

type Log struct {
	Dir            string
	Classification string
	Repo           string
	RequireAppend  bool // policy: refuse unless the file has the append-only inode flag
}

func (l *Log) path() string    { return filepath.Join(l.Dir, "log.jsonl") }
func (l *Log) objDir() string  { return filepath.Join(l.Dir, "objects") }
func (l *Log) LogPath() string { return l.path() }

// Open prepares the directory. Files are group-readable/appendable so a
// proposer and an approver in the same group share one log; the installer
// sets chattr +a so even the owner cannot rewrite it.
func (l *Log) Open() error {
	if err := os.MkdirAll(l.objDir(), 0o2770); err != nil {
		return err
	}
	f, err := os.OpenFile(l.path(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o660)
	if err != nil {
		return err
	}
	f.Close()
	if l.RequireAppend {
		ok, err := AppendOnlyFlag(l.path())
		if err != nil {
			return fmt.Errorf("audit: cannot read inode flags of %s: %w", l.path(), err)
		}
		if !ok {
			return fmt.Errorf("audit: %s is not append-only; an administrator must run: chattr +a %s", l.path(), l.path())
		}
	}
	return nil
}

// PutObject stores data content-addressed and returns its SHA-256.
func (l *Log) PutObject(data []byte) (string, error) {
	h := sha256.Sum256(data)
	id := hex.EncodeToString(h[:])
	dir := filepath.Join(l.objDir(), id[:2])
	p := filepath.Join(dir, id[2:])
	if _, err := os.Stat(p); err == nil {
		return id, nil
	}
	if err := os.MkdirAll(dir, 0o2770); err != nil {
		return "", err
	}
	tmp := p + ".tmp" + fmt.Sprint(os.Getpid())
	if err := os.WriteFile(tmp, data, 0o440); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, p); err != nil {
		return "", err
	}
	return id, nil
}

func (l *Log) GetObject(id string) ([]byte, error) {
	if len(id) != 64 {
		return nil, fmt.Errorf("bad object id")
	}
	data, err := os.ReadFile(filepath.Join(l.objDir(), id[:2], id[2:]))
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(data)
	if hex.EncodeToString(h[:]) != id {
		return nil, fmt.Errorf("object %s is corrupt (content hash mismatch)", id)
	}
	return data, nil
}

// Append writes one signed entry under an exclusive lock and fsyncs it.
func (l *Log) Append(s sign.Signer, actor identity.User, session, kind string, summary map[string]any, objects map[string]string) (*Entry, error) {
	f, err := os.OpenFile(l.path(), os.O_RDWR|os.O_APPEND, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return nil, err
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)

	last, err := lastEntry(f)
	if err != nil {
		return nil, err
	}
	e := &Entry{V: 1, Time: time.Now().UTC().Format(time.RFC3339Nano), Prev: GenesisPrev,
		Classification: l.Classification, Repo: l.Repo, Session: session, Actor: actor,
		Kind: kind, Summary: summary, Objects: objects, KeyID: s.KeyID()}
	if last != nil {
		e.Seq = last.Seq + 1
		e.Prev = last.Hash
	}
	if e.Hash, err = e.computeHash(); err != nil {
		return nil, err
	}
	hb, _ := hex.DecodeString(e.Hash)
	sig, err := s.Sign(hb)
	if err != nil {
		return nil, err
	}
	e.Sig = base64.StdEncoding.EncodeToString(sig)
	line, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		return nil, err
	}
	return e, f.Sync()
}

// lastEntry reads the final line by scanning backward from EOF.
func lastEntry(f *os.File) (*Entry, error) {
	fi, err := f.Stat()
	if err != nil || fi.Size() == 0 {
		return nil, err
	}
	size := fi.Size()
	const chunk = 64 << 10
	var buf []byte
	for off := size; off > 0; {
		n := int64(chunk)
		if off < n {
			n = off
		}
		off -= n
		b := make([]byte, n)
		if _, err := f.ReadAt(b, off); err != nil && err != io.EOF {
			return nil, err
		}
		buf = append(b, buf...)
		trimmed := bytes.TrimRight(buf, "\n")
		if i := bytes.LastIndexByte(trimmed, '\n'); i >= 0 || off == 0 {
			lastLine := trimmed[i+1:]
			var e Entry
			if err := json.Unmarshal(lastLine, &e); err != nil {
				return nil, fmt.Errorf("audit: last log line is corrupt: %w", err)
			}
			return &e, nil
		}
	}
	return nil, nil
}

// Head returns the most recent entry (nil for an empty log).
func (l *Log) Head() (*Entry, error) {
	f, err := os.Open(l.path())
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return lastEntry(f)
}

// Each streams entries in order.
func (l *Log) Each(fn func(*Entry, []byte) error) error {
	f, err := os.Open(l.path())
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	line := 0
	for sc.Scan() {
		line++
		raw := sc.Bytes()
		if len(bytes.TrimSpace(raw)) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(raw, &e); err != nil {
			return fmt.Errorf("line %d: unparseable entry: %w", line, err)
		}
		if err := fn(&e, raw); err != nil {
			return err
		}
	}
	return sc.Err()
}

// AppendOnlyFlag reports whether the inode has FS_APPEND_FL (chattr +a).
func AppendOnlyFlag(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	const fsIocGetflags = 0x80086601
	const fsAppendFl = 0x00000020
	var flags int32
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), fsIocGetflags, uintptr(unsafe.Pointer(&flags)))
	if errno != 0 {
		return false, errno
	}
	return flags&fsAppendFl != 0, nil
}

var ErrEmpty = errors.New("audit log is empty")
