package modelpin

import (
	"fmt"
	"strings"
)

// OriginPolicy restricts models by the country of their publisher and of
// every model they were derived from. Codes are ISO 3166-1 alpha-2.
type OriginPolicy struct {
	Allowed []string
	Denied  []string
}

// Active reports whether any origin restriction is configured.
func (p OriginPolicy) Active() bool { return len(p.Allowed) > 0 || len(p.Denied) > 0 }

// ValidCountry reports whether c looks like an ISO 3166-1 alpha-2 code.
func ValidCountry(c string) bool {
	if len(c) != 2 {
		return false
	}
	for _, r := range c {
		if r < 'A' || r > 'Z' {
			return false
		}
	}
	return true
}

func contains(list []string, c string) bool {
	for _, x := range list {
		if strings.EqualFold(x, c) {
			return true
		}
	}
	return false
}

// CheckOrigin returns an error naming every origin that the policy refuses,
// for the model itself and for its lineage. A model or ancestor with no
// origin recorded fails whenever a restriction is active: unknown provenance
// is treated as denied.
func CheckOrigin(m *Model, p OriginPolicy) error {
	if !p.Active() {
		return nil
	}
	type subject struct{ what, origin string }
	subs := []subject{{m.Name + " (" + m.Publisher + ")", m.Origin}}
	for _, d := range m.DerivedFrom {
		subs = append(subs, subject{"ancestor " + d.Model + " (" + d.Publisher + ")", d.Origin})
	}
	var bad []string
	for _, s := range subs {
		o := strings.ToUpper(strings.TrimSpace(s.origin))
		switch {
		case !ValidCountry(o):
			bad = append(bad, s.what+": origin not recorded in the lock")
		case contains(p.Denied, o):
			bad = append(bad, s.what+": origin "+o+" is denied by policy")
		case len(p.Allowed) > 0 && !contains(p.Allowed, o):
			bad = append(bad, s.what+": origin "+o+" is not in model.allowed_origins")
		}
	}
	if len(bad) > 0 {
		return fmt.Errorf("%s", strings.Join(bad, "; "))
	}
	return nil
}

// Origins returns the model's origin followed by its ancestors' origins,
// de-duplicated, for audit records.
func (m *Model) Origins() []string {
	seen := map[string]bool{}
	var out []string
	for _, o := range append([]string{m.Origin}, func() []string {
		var a []string
		for _, d := range m.DerivedFrom {
			a = append(a, d.Origin)
		}
		return a
	}()...) {
		o = strings.ToUpper(o)
		if o != "" && !seen[o] {
			seen[o] = true
			out = append(out, o)
		}
	}
	return out
}
