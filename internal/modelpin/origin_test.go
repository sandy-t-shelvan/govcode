package modelpin

import (
	"strings"
	"testing"
)

func TestCheckOrigin(t *testing.T) {
	fr := &Model{Name: "Devstral", Publisher: "Mistral AI", Origin: "FR",
		DerivedFrom: []Lineage{{Model: "Mistral-Small", Publisher: "Mistral AI", Origin: "FR"}}}
	cn := &Model{Name: "Qwen", Publisher: "Alibaba", Origin: "CN"}
	laundered := &Model{Name: "Tuned", Publisher: "Someone", Origin: "US",
		DerivedFrom: []Lineage{{Model: "Qwen-Base", Publisher: "Alibaba", Origin: "CN"}}}
	unknown := &Model{Name: "Mystery", Publisher: "?"}
	unknownAncestor := &Model{Name: "M", Origin: "US", DerivedFrom: []Lineage{{Model: "X"}}}
	deny := OriginPolicy{Denied: []string{"CN"}}
	allow := OriginPolicy{Allowed: []string{"US", "FR"}}
	cases := []struct {
		m    *Model
		p    OriginPolicy
		fail string
	}{
		{fr, deny, ""},
		{fr, allow, ""},
		{cn, deny, "origin CN is denied"},
		{cn, allow, "not in model.allowed_origins"},
		{laundered, deny, "ancestor Qwen-Base"},
		{laundered, allow, "ancestor Qwen-Base"},
		{unknown, deny, "origin not recorded"},
		{unknownAncestor, deny, "ancestor X"},
		{cn, OriginPolicy{}, ""}, // no restriction configured
		{&Model{Name: "lc", Origin: "cn"}, deny, "denied"},
	}
	for i, c := range cases {
		err := CheckOrigin(c.m, c.p)
		switch {
		case c.fail == "" && err != nil:
			t.Errorf("%d: unexpected %v", i, err)
		case c.fail != "" && (err == nil || !strings.Contains(err.Error(), c.fail)):
			t.Errorf("%d: got %v, want %q", i, err, c.fail)
		}
	}
	if got := strings.Join(laundered.Origins(), ","); got != "US,CN" {
		t.Errorf("Origins = %s", got)
	}
}

func TestRepoLockRecordsOrigins(t *testing.T) {
	l, err := Load("../../models/models.lock.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range l.Models {
		if !ValidCountry(m.Origin) {
			t.Errorf("%s: origin %q", m.ID, m.Origin)
		}
		for _, d := range m.DerivedFrom {
			if !ValidCountry(d.Origin) || d.Model == "" {
				t.Errorf("%s: lineage %+v", m.ID, d)
			}
		}
	}
	d, _ := l.Find("")
	if err := CheckOrigin(d, OriginPolicy{Denied: []string{"CN"}}); err != nil {
		t.Errorf("default model must pass the example strict policy: %v", err)
	}
}
