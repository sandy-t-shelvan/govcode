// Package supply produces the SBOM / AI-BOM (CycloneDX 1.6) and verifies
// the signed release manifest.
package supply

import (
	"crypto/rand"
	"fmt"
	"time"
)

// Minimal CycloneDX 1.6 object model (only fields we emit).
type BOM struct {
	BOMFormat    string       `json:"bomFormat"`
	SpecVersion  string       `json:"specVersion"`
	SerialNumber string       `json:"serialNumber"`
	Version      int          `json:"version"`
	Metadata     Metadata     `json:"metadata"`
	Components   []Component  `json:"components"`
	Dependencies []Dependency `json:"dependencies,omitempty"`
}

type Metadata struct {
	Timestamp  string     `json:"timestamp"`
	Tools      *Tools     `json:"tools,omitempty"`
	Component  *Component `json:"component,omitempty"`
	Properties []Property `json:"properties,omitempty"`
}

type Tools struct {
	Components []Component `json:"components"`
}

type Component struct {
	BOMRef       string        `json:"bom-ref,omitempty"`
	Type         string        `json:"type"`
	Name         string        `json:"name"`
	Version      string        `json:"version,omitempty"`
	Publisher    string        `json:"publisher,omitempty"`
	Description  string        `json:"description,omitempty"`
	Purl         string        `json:"purl,omitempty"`
	Hashes       []Hash        `json:"hashes,omitempty"`
	Licenses     []LicenseRef  `json:"licenses,omitempty"`
	ExternalRefs []ExternalRef `json:"externalReferences,omitempty"`
	Properties   []Property    `json:"properties,omitempty"`
	Pedigree     *Pedigree     `json:"pedigree,omitempty"`
	ModelCard    *ModelCard    `json:"modelCard,omitempty"`
	Components   []Component   `json:"components,omitempty"`
}

type Hash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

type LicenseRef struct {
	License struct {
		ID string `json:"id"`
	} `json:"license"`
}

func License(id string) []LicenseRef {
	var l LicenseRef
	l.License.ID = id
	return []LicenseRef{l}
}

type ExternalRef struct {
	Type    string `json:"type"`
	URL     string `json:"url"`
	Comment string `json:"comment,omitempty"`
}

type Property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type Pedigree struct {
	Ancestors []Component `json:"ancestors,omitempty"`
	Notes     string      `json:"notes,omitempty"`
}

type ModelCard struct {
	ModelParameters *ModelParameters `json:"modelParameters,omitempty"`
	Considerations  *Considerations  `json:"considerations,omitempty"`
	Properties      []Property       `json:"properties,omitempty"`
}

type ModelParameters struct {
	Approach *struct {
		Type string `json:"type"`
	} `json:"approach,omitempty"`
	Task               string `json:"task,omitempty"`
	ArchitectureFamily string `json:"architectureFamily,omitempty"`
	ModelArchitecture  string `json:"modelArchitecture,omitempty"`
}

type Considerations struct {
	UseCases        []string `json:"useCases,omitempty"`
	TechnicalLimits []string `json:"technicalLimitations,omitempty"`
}

type Dependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn,omitempty"`
}

func newBOM(subject Component) *BOM {
	return &BOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.6",
		SerialNumber: "urn:uuid:" + uuid4(),
		Version:      1,
		Metadata: Metadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Tools:     &Tools{Components: []Component{{Type: "application", Name: "govcode", Version: Version}}},
			Component: &subject,
		},
	}
}

// Version is set at link time (-ldflags -X).
var Version = "dev"

func uuid4() string {
	var b [16]byte
	rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
