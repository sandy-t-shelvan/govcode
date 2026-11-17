package supply

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/sandy-t-shelvan/govcode/internal/modelpin"
	"github.com/sandy-t-shelvan/govcode/internal/sign"
)

// in-toto Statement v1 with a SLSA v1.0 build provenance predicate.
// https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md
// https://slsa.dev/spec/v1.0/provenance

const (
	StatementType       = "https://in-toto.io/Statement/v1"
	SLSAProvenanceType  = "https://slsa.dev/provenance/v1"
	CycloneDXPredicate  = "https://cyclonedx.org/bom"
	BuildType           = "https://github.com/sandy-t-shelvan/govcode/blob/main/scripts/build-release.sh@v1"
	ProvenanceFile      = "provenance.intoto.jsonl"
	SBOMAttestationFile = "sbom.intoto.jsonl"
)

type Statement struct {
	Type          string          `json:"_type"`
	Subject       []Subject       `json:"subject"`
	PredicateType string          `json:"predicateType"`
	Predicate     json.RawMessage `json:"predicate"`
}

type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

type Provenance struct {
	BuildDefinition BuildDefinition `json:"buildDefinition"`
	RunDetails      RunDetails      `json:"runDetails"`
}

type BuildDefinition struct {
	BuildType            string               `json:"buildType"`
	ExternalParameters   map[string]any       `json:"externalParameters"`
	InternalParameters   map[string]any       `json:"internalParameters,omitempty"`
	ResolvedDependencies []ResourceDescriptor `json:"resolvedDependencies,omitempty"`
}

type ResourceDescriptor struct {
	URI    string            `json:"uri,omitempty"`
	Name   string            `json:"name,omitempty"`
	Digest map[string]string `json:"digest,omitempty"`
}

type RunDetails struct {
	Builder    Builder              `json:"builder"`
	Metadata   *BuildMetadata       `json:"metadata,omitempty"`
	Byproducts []ResourceDescriptor `json:"byproducts,omitempty"`
}

type Builder struct {
	ID      string            `json:"id"`
	Version map[string]string `json:"version,omitempty"`
}

type BuildMetadata struct {
	InvocationID string `json:"invocationId,omitempty"`
	StartedOn    string `json:"startedOn,omitempty"`
	FinishedOn   string `json:"finishedOn,omitempty"`
}

// BuildInfo is what the release script knows about the build.
type BuildInfo struct {
	Version      string
	SourceRepo   string // e.g. git+https://host/org/govcode
	Commit       string // full git commit
	TreeClean    bool
	GoVersion    string // `go version` output
	GoToolSHA256 string // sha256 of $(go env GOROOT)/bin/go
	Env          map[string]string
	Reproducible bool
	ReproSHA256  string // hash both builds produced
	BuilderID    string
	StartedOn    time.Time
	FinishedOn   time.Time
	Exclude      []string // further paths not to list as subjects
}

// Subjects lists every regular file under dir with its SHA-256, sorted.
func Subjects(dir string, exclude ...string) ([]Subject, error) {
	skip := map[string]bool{}
	for _, e := range exclude {
		skip[e] = true
	}
	var out []Subject
	err := filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		rel = filepath.ToSlash(rel)
		if skip[rel] || !info.Mode().IsRegular() {
			return nil
		}
		sum, _, err := modelpin.HashFile(p)
		if err != nil {
			return err
		}
		out = append(out, Subject{Name: rel, Digest: map[string]string{"sha256": sum}})
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, err
}

// BuildProvenance returns the SLSA v1 provenance statement for a release
// directory. Every file in it becomes a subject.
func BuildProvenance(dir string, bi BuildInfo) (*Statement, error) {
	if bi.Commit == "" || bi.SourceRepo == "" {
		return nil, errors.New("provenance needs the source repository and commit")
	}
	subs, err := Subjects(dir, append([]string{ProvenanceFile, SBOMAttestationFile, "SHA256SUMS"}, bi.Exclude...)...)
	if err != nil {
		return nil, err
	}
	deps := []ResourceDescriptor{{URI: bi.SourceRepo, Digest: map[string]string{"gitCommit": bi.Commit}}}
	if bi.GoToolSHA256 != "" {
		deps = append(deps, ResourceDescriptor{Name: "go-toolchain", URI: "pkg:golang/toolchain@" + goVer(bi.GoVersion), Digest: map[string]string{"sha256": bi.GoToolSHA256}})
	}
	env := map[string]any{}
	for k, v := range bi.Env {
		env[k] = v
	}
	p := Provenance{
		BuildDefinition: BuildDefinition{
			BuildType: BuildType,
			ExternalParameters: map[string]any{
				"version": bi.Version, "source": bi.SourceRepo, "commit": bi.Commit,
			},
			InternalParameters: map[string]any{
				"go_version": bi.GoVersion, "env": env, "tree_clean": bi.TreeClean,
				"reproducible": bi.Reproducible, "reproducible_sha256": bi.ReproSHA256,
				"third_party_modules": 0,
			},
			ResolvedDependencies: deps,
		},
		RunDetails: RunDetails{Builder: Builder{ID: bi.BuilderID, Version: map[string]string{"govcode": bi.Version}}},
	}
	if !bi.StartedOn.IsZero() {
		p.RunDetails.Metadata = &BuildMetadata{InvocationID: bi.Version + "@" + bi.Commit,
			StartedOn: bi.StartedOn.UTC().Format(time.RFC3339), FinishedOn: bi.FinishedOn.UTC().Format(time.RFC3339)}
	}
	pred, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	return &Statement{Type: StatementType, Subject: subs, PredicateType: SLSAProvenanceType, Predicate: pred}, nil
}

func goVer(s string) string {
	for _, f := range strings.Fields(s) {
		if strings.HasPrefix(f, "go1") {
			return strings.TrimPrefix(f, "go")
		}
	}
	return "unknown"
}

// SBOMStatement attests that sbomPath describes the given subjects.
func SBOMStatement(sbom []byte, subjects []Subject) (*Statement, error) {
	if !json.Valid(sbom) {
		return nil, errors.New("SBOM is not valid JSON")
	}
	return &Statement{Type: StatementType, Subject: subjects, PredicateType: CycloneDXPredicate, Predicate: sbom}, nil
}

// AttestationResult summarises a verified provenance attestation.
type AttestationResult struct {
	KeyID   string
	Builder string
	Source  string
	Commit  string
	Repro   bool
	Subject Subject
}

// VerifyAttestation checks the DSSE signature, the statement and predicate
// types, and that a file with the given SHA-256 is one of the subjects.
func VerifyAttestation(data []byte, predicateType string, trusted []ed25519.PublicKey, sha256 string) (*AttestationResult, error) {
	envs, err := ParseEnvelopes(data)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, env := range envs {
		payload, kid, err := VerifyEnvelope(env, InTotoPayloadType, trusted)
		if err != nil {
			lastErr = err
			continue
		}
		var st Statement
		if err := json.Unmarshal(payload, &st); err != nil {
			return nil, fmt.Errorf("statement: %w", err)
		}
		if st.Type != StatementType {
			lastErr = fmt.Errorf("statement _type %q", st.Type)
			continue
		}
		if st.PredicateType != predicateType {
			lastErr = fmt.Errorf("predicateType %q, want %q", st.PredicateType, predicateType)
			continue
		}
		res := &AttestationResult{KeyID: kid}
		if predicateType == SLSAProvenanceType {
			var p Provenance
			if err := json.Unmarshal(st.Predicate, &p); err != nil {
				return nil, fmt.Errorf("predicate: %w", err)
			}
			res.Builder = p.RunDetails.Builder.ID
			res.Source, _ = p.BuildDefinition.ExternalParameters["source"].(string)
			res.Commit, _ = p.BuildDefinition.ExternalParameters["commit"].(string)
			res.Repro, _ = p.BuildDefinition.InternalParameters["reproducible"].(bool)
		}
		for _, s := range st.Subject {
			if strings.EqualFold(s.Digest["sha256"], sha256) {
				res.Subject = s
				return res, nil
			}
		}
		return nil, fmt.Errorf("sha256 %s is not a subject of the signed attestation", sha256)
	}
	return nil, lastErr
}

// SignStatement wraps a statement in a DSSE envelope and returns one JSONL line.
func SignStatement(s sign.Signer, st *Statement) ([]byte, error) {
	payload, err := json.Marshal(st)
	if err != nil {
		return nil, err
	}
	env, err := SignEnvelope(s, InTotoPayloadType, payload)
	if err != nil {
		return nil, err
	}
	b, err := json.Marshal(env)
	return append(b, '\n'), err
}

// SelfSHA256 hashes the running executable.
func SelfSHA256() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	exe, _ = filepath.EvalSymlinks(exe)
	sum, _, err := modelpin.HashFile(exe)
	return sum, err
}
