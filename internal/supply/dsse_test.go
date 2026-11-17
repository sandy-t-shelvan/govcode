package supply

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sandy-t-shelvan/govcode/internal/sign"
)

// Test vector from the DSSE protocol specification.
func TestPAESpecVector(t *testing.T) {
	got := string(PAE("http://example.com/HelloWorld", []byte("hello world")))
	if want := "DSSEv1 29 http://example.com/HelloWorld 11 hello world"; got != want {
		t.Fatalf("PAE = %q", got)
	}
	if got := string(PAE("", nil)); got != "DSSEv1 0  0 " {
		t.Fatalf("empty PAE = %q", got)
	}
}

func signer(t *testing.T) sign.Signer {
	_, priv, _ := ed25519.GenerateKey(nil)
	return sign.NewSigner(priv)
}

func TestEnvelopeRoundTripAndTamper(t *testing.T) {
	s, other := signer(t), signer(t)
	env, err := SignEnvelope(s, InTotoPayloadType, []byte(`{"a":1}`))
	if err != nil {
		t.Fatal(err)
	}
	trusted := []ed25519.PublicKey{s.Public().(ed25519.PublicKey)}
	if p, kid, err := VerifyEnvelope(env, InTotoPayloadType, trusted); err != nil || string(p) != `{"a":1}` || kid != s.KeyID() {
		t.Fatalf("verify: %s %s %v", p, kid, err)
	}
	// The signature verifies against the raw ed25519 PAE, as other DSSE
	// implementations will check it.
	sig, _ := base64.StdEncoding.DecodeString(env.Signatures[0].Sig)
	if !ed25519.Verify(s.Public().(ed25519.PublicKey), PAE(InTotoPayloadType, []byte(`{"a":1}`)), sig) {
		t.Fatal("signature is not over PAE")
	}

	cases := map[string]func(e *Envelope) ([]ed25519.PublicKey, string){
		"payload changed": func(e *Envelope) ([]ed25519.PublicKey, string) {
			e.Payload = base64.StdEncoding.EncodeToString([]byte(`{"a":2}`))
			return trusted, InTotoPayloadType
		},
		"type changed": func(e *Envelope) ([]ed25519.PublicKey, string) {
			e.PayloadType = "text/plain"
			return trusted, "text/plain"
		},
		"wrong type wanted": func(e *Envelope) ([]ed25519.PublicKey, string) { return trusted, "text/plain" },
		"untrusted key": func(e *Envelope) ([]ed25519.PublicKey, string) {
			return []ed25519.PublicKey{other.Public().(ed25519.PublicKey)}, InTotoPayloadType
		},
		"no signatures": func(e *Envelope) ([]ed25519.PublicKey, string) {
			e.Signatures = nil
			return trusted, InTotoPayloadType
		},
		"garbage sig": func(e *Envelope) ([]ed25519.PublicKey, string) {
			e.Signatures[0].Sig = "!!"
			return trusted, InTotoPayloadType
		},
	}
	for name, mut := range cases {
		e := *env
		e.Signatures = append([]EnvelopeSign(nil), env.Signatures...)
		keys, want := mut(&e)
		if _, _, err := VerifyEnvelope(&e, want, keys); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A lying keyid neither rejects a good signature nor accepts a bad one.
	e := *env
	e.Signatures = []EnvelopeSign{{KeyID: other.KeyID(), Sig: env.Signatures[0].Sig}}
	if _, _, err := VerifyEnvelope(&e, InTotoPayloadType, trusted); err != nil {
		t.Errorf("keyid hint caused a reject: %v", err)
	}
}

func release(t *testing.T) string {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"bin/govcode": "BINARY", "sbom.cdx.json": `{"bomFormat":"CycloneDX"}`, "manifest.json": "{}",
		"vscode/govcode-1.vsix": "VSIX", "SHA256SUMS": "skip me",
	} {
		p := filepath.Join(dir, name)
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte(body), 0o644)
	}
	return dir
}

func TestProvenanceSignVerify(t *testing.T) {
	s := signer(t)
	dir := release(t)
	st, err := BuildProvenance(dir, BuildInfo{Version: "1.0", SourceRepo: "git+https://git.local/govcode", Commit: "abc123",
		GoVersion: "go version go1.27.4 linux/amd64", GoToolSHA256: "00", Reproducible: true, BuilderID: "host://b1"})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, s := range st.Subject {
		names = append(names, s.Name)
	}
	if got := strings.Join(names, ","); got != "bin/govcode,manifest.json,sbom.cdx.json,vscode/govcode-1.vsix" {
		t.Fatalf("subjects %s", got)
	}
	line, err := SignStatement(s, st)
	if err != nil {
		t.Fatal(err)
	}
	bin := st.Subject[0].Digest["sha256"]
	trusted := []ed25519.PublicKey{s.Public().(ed25519.PublicKey)}
	r, err := VerifyAttestation(line, SLSAProvenanceType, trusted, bin)
	if err != nil {
		t.Fatal(err)
	}
	if r.Subject.Name != "bin/govcode" || r.Commit != "abc123" || r.Builder != "host://b1" || !r.Repro || r.Source != "git+https://git.local/govcode" {
		t.Fatalf("%+v", r)
	}
	var pred Provenance
	json.Unmarshal(st.Predicate, &pred)
	if pred.BuildDefinition.ResolvedDependencies[1].URI != "pkg:golang/toolchain@1.27.4" {
		t.Errorf("toolchain dep %+v", pred.BuildDefinition.ResolvedDependencies)
	}

	if _, err := VerifyAttestation(line, SLSAProvenanceType, trusted, strings.Repeat("0", 64)); err == nil || !strings.Contains(err.Error(), "not a subject") {
		t.Errorf("non-subject accepted: %v", err)
	}
	if _, err := VerifyAttestation(line, CycloneDXPredicate, trusted, bin); err == nil {
		t.Error("wrong predicate type accepted")
	}
	if _, err := VerifyAttestation(line, SLSAProvenanceType, []ed25519.PublicKey{signer(t).Public().(ed25519.PublicKey)}, bin); err == nil {
		t.Error("untrusted key accepted")
	}
	if _, err := BuildProvenance(dir, BuildInfo{}); err == nil {
		t.Error("provenance without source accepted")
	}

	sb, _ := os.ReadFile(filepath.Join(dir, "sbom.cdx.json"))
	sst, err := SBOMStatement(sb, st.Subject[:1])
	if err != nil {
		t.Fatal(err)
	}
	sl, _ := SignStatement(s, sst)
	if _, err := VerifyAttestation(append(line, sl...), CycloneDXPredicate, trusted, bin); err != nil {
		t.Errorf("SBOM attestation in a two-line bundle: %v", err)
	}
}

func FuzzVerifyAttestation(f *testing.F) {
	s := sign.NewSigner(ed25519.NewKeyFromSeed(make([]byte, 32)))
	st := &Statement{Type: StatementType, PredicateType: SLSAProvenanceType, Predicate: json.RawMessage(`{}`),
		Subject: []Subject{{Name: "bin/govcode", Digest: map[string]string{"sha256": "aa"}}}}
	line, _ := SignStatement(s, st)
	f.Add(line)
	f.Add([]byte(`{"payloadType":"application/vnd.in-toto+json","payload":"e30=","signatures":[{"sig":""}]}`))
	f.Add([]byte("{}\n{}"))
	trusted := []ed25519.PublicKey{s.Public().(ed25519.PublicKey)}
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := VerifyAttestation(data, SLSAProvenanceType, trusted, "aa")
		if err == nil && (r == nil || r.Subject.Digest["sha256"] != "aa") {
			t.Fatalf("accepted without the subject: %+v", r)
		}
		if err == nil && string(data) != string(line) {
			// Only a validly signed statement may pass: re-verify the envelope.
			envs, _ := ParseEnvelopes(data)
			ok := false
			for _, e := range envs {
				if _, _, err := VerifyEnvelope(e, InTotoPayloadType, trusted); err == nil {
					ok = true
				}
			}
			if !ok {
				t.Fatal("accepted with no valid signature")
			}
		}
	})
}
