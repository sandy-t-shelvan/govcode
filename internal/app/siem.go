package app

import (
	"fmt"
	"os"
	"strings"

	"github.com/sandy-t-shelvan/govcode/internal/audit"
	"github.com/sandy-t-shelvan/govcode/internal/siem"
)

// securityEvent maps an audit entry to a SIEM severity. Only security-
// relevant kinds are exported; content never is, only summary fields.
func securityEvent(e *audit.Entry) (int, bool) {
	k := strings.TrimPrefix(e.Kind, "tool_event:")
	switch k {
	case "spillage_blocked":
		return siem.Critical, true
	case "secret_found", "approval_refused", "approval_failed", "audit_verify_failed":
		return siem.Warning, true
	case "permission":
		if fmt.Sprint(e.Summary["decision"]) == "deny" {
			return siem.Notice, true
		}
	case "hook":
		if fmt.Sprint(e.Summary["passed"]) == "false" {
			return siem.Notice, true
		}
	case "approval", "landed", "rejection", "proposal", "task":
		return siem.Info, true
	}
	return 0, false
}

// exporter returns the policy's SIEM exporter, or nil when disabled.
func (a *App) exporter() *siem.Exporter {
	if !a.Policy.SIEM.Syslog {
		return nil
	}
	if a.siemExp == nil {
		a.siemExp = &siem.Exporter{Socket: a.Policy.SIEM.Socket, Classification: a.Policy.Classification,
			Warn: func(s string) { fmt.Fprintln(os.Stderr, "warning:", s) }}
	}
	return a.siemExp
}

func (a *App) forward(e *audit.Entry) {
	ex := a.exporter()
	if ex == nil {
		return
	}
	sev, ok := securityEvent(e)
	if !ok {
		return
	}
	f := map[string]string{"user": e.Actor.Username, "uid": fmt.Sprint(e.Actor.UID), "session": e.Session,
		"audit_seq": fmt.Sprint(e.Seq), "audit_hash": e.Hash, "repo": e.Repo}
	for k, v := range e.Summary {
		f[k] = fmt.Sprint(v)
	}
	ex.Send(sev, strings.TrimPrefix(e.Kind, "tool_event:"), f)
}

// ReportAuditFailure exports a failed `audit verify` (not an audit entry:
// the log itself may be the thing that is broken).
func (a *App) ReportAuditFailure(problems int, head string) {
	if ex := a.exporter(); ex != nil {
		ex.Send(siem.Critical, "audit_verify_failed", map[string]string{"problems": fmt.Sprint(problems), "head": head, "repo": a.Repo.Root})
	}
}
