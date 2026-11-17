// Package siem forwards security events to the host's syslog daemon over
// the local datagram socket (/dev/log). This is a Unix-domain socket, not
// a network connection: journald or rsyslog on the same host receives the
// events, and the site's existing log forwarding takes them from there.
//
// Messages are RFC 5424 with structured data. They carry event kinds,
// locations, levels and hashes only, never code, prompts or model output.
// Export fails open: the signed audit log stays the authoritative record.
package siem

import (
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// Severity values from RFC 5424.
const (
	Alert    = 1
	Critical = 2
	Warning  = 4
	Notice   = 5
	Info     = 6
)

const facilityAuthpriv = 10

// SDID uses the IANA "example" enterprise number reserved for
// documentation (RFC 5612); sites with their own PEN may change it.
const SDID = "govcode@32473"

type Exporter struct {
	Socket         string // default /dev/log
	Classification string
	Host           string
	Warn           func(string)

	mu     sync.Mutex
	conn   *net.UnixConn
	failed bool
}

func (e *Exporter) dial() error {
	if e.conn != nil {
		return nil
	}
	path := e.Socket
	if path == "" {
		path = "/dev/log"
	}
	c, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		return err
	}
	e.conn = c
	return nil
}

// Send emits one event. fields become SD-PARAMs (sorted, escaped).
func (e *Exporter) Send(severity int, event string, fields map[string]string) {
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.dial(); err != nil {
		e.warnOnce("SIEM export disabled: cannot open syslog socket: " + err.Error())
		return
	}
	msg := Format(severity, e.host(), event, e.Classification, fields, time.Now())
	if _, err := e.conn.Write([]byte(msg)); err != nil {
		e.conn.Close()
		e.conn = nil
		e.warnOnce("SIEM export failed: " + err.Error())
	}
}

func (e *Exporter) host() string {
	if e.Host != "" {
		return e.Host
	}
	h, _ := os.Hostname()
	if h == "" {
		h = "-"
	}
	return h
}

func (e *Exporter) warnOnce(s string) {
	if e.failed {
		return
	}
	e.failed = true
	if e.Warn != nil {
		e.Warn(s)
	}
}

func (e *Exporter) Close() {
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.conn != nil {
		e.conn.Close()
		e.conn = nil
	}
}

// Format renders an RFC 5424 message.
func Format(severity int, host, event, classification string, fields map[string]string, t time.Time) string {
	pri := facilityAuthpriv*8 + severity
	var sd strings.Builder
	sd.WriteString("[" + SDID)
	params := map[string]string{"event": event, "classification": classification}
	for k, v := range fields {
		params[k] = v
	}
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&sd, ` %s="%s"`, sdName(k), sdEscape(params[k]))
	}
	sd.WriteString("]")
	// The free-text MSG is escaped too: a control character there would
	// split one record into two (log injection).
	return fmt.Sprintf("<%d>1 %s %s govcode %d %s %s govcode %s", pri, t.UTC().Format(time.RFC3339Nano), token(host), os.Getpid(), token(event), sd.String(), sdEscape(event))
}

// SD-NAME: printable US-ASCII except '=', ' ', ']', '"'; max 32 chars.
func sdName(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r > 32 && r < 127 && !strings.ContainsRune(`= ]"`, r) {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	out := b.String()
	if len(out) > 32 {
		out = out[:32]
	}
	return out
}

// PARAM-VALUE escaping: '"', '\' and ']' are backslash-escaped. Control
// characters (newlines would split the record) are replaced.
func sdEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '"' || r == '\\' || r == ']':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r < 32 || r == 127:
			b.WriteByte(' ')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func token(s string) string {
	s = sdName(s)
	if s == "" {
		return "-"
	}
	return s
}
