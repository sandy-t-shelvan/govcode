package siem

import (
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFormatRFC5424(t *testing.T) {
	ts := time.Date(2026, 11, 16, 22, 0, 0, 0, time.UTC)
	m := Format(Critical, "ws01", "spillage_blocked", "SECRET//NOFORN", map[string]string{"level": "TOP SECRET", "where": `read_file a"b]\c`, "bad key": "x\ny"}, ts)
	if !strings.HasPrefix(m, "<82>1 2026-11-16T22:00:00Z ws01 govcode ") {
		t.Fatalf("header: %q", m)
	}
	for _, want := range []string{`[govcode@32473 `, `bad_key="x y"`, `classification="SECRET//NOFORN"`, `event="spillage_blocked"`, `level="TOP SECRET"`, `where="read_file a\"b\]\\c"`} {
		if !strings.Contains(m, want) {
			t.Errorf("missing %q in %q", want, m)
		}
	}
	if strings.Contains(m, "\n") {
		t.Error("newline in record")
	}
}

func TestSendOverUnixDatagram(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "log")
	l, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: sock, Net: "unixgram"})
	if err != nil {
		t.Skip("unixgram unavailable:", err)
	}
	defer l.Close()
	e := &Exporter{Socket: sock, Classification: "SECRET", Host: "h"}
	defer e.Close()
	e.Send(Warning, "secret_found", map[string]string{"file": "cfg.c", "line": "12"})
	buf := make([]byte, 4096)
	l.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := l.ReadFromUnix(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buf[:n]); !strings.HasPrefix(got, "<84>1 ") || !strings.Contains(got, `file="cfg.c"`) {
		t.Fatalf("datagram %q", got)
	}
}

func TestFailsOpen(t *testing.T) {
	var warned []string
	e := &Exporter{Socket: "/nonexistent/sock", Warn: func(s string) { warned = append(warned, s) }}
	e.Send(Info, "approval", nil)
	e.Send(Info, "approval", nil)
	if len(warned) != 1 {
		t.Fatalf("want exactly one warning, got %v", warned)
	}
	var nilE *Exporter
	nilE.Send(Info, "x", nil) // nil exporter is a no-op
}

func FuzzFormat(f *testing.F) {
	f.Add("event", "k", "v\"]\\\n")
	f.Fuzz(func(t *testing.T, ev, k, v string) {
		m := Format(Info, "h", ev, "S", map[string]string{k: v}, time.Unix(0, 0))
		if strings.ContainsAny(m, "\n\r") {
			t.Fatalf("record contains newline: %q", m)
		}
	})
}
