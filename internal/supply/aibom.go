package supply

import (
	"fmt"

	"github.com/sandy-t-shelvan/govcode/internal/modelpin"
)

// AIBOM builds a CycloneDX 1.6 ML-BOM from the model lock: one
// machine-learning-model component per model, with the served artifact's
// hashes, the upstream first-party weights as pedigree ancestors, license,
// and the serving parameters (num_ctx, tool parser) as properties.
func AIBOM(l *modelpin.Lock) *BOM {
	b := newBOM(Component{Type: "application", Name: "govcode-model-set", Version: Version,
		Description: "Open-weight models approved for govcode"})
	for _, m := range l.Models {
		up := Component{
			BOMRef:    "model-upstream:" + m.Upstream.Repo + "@" + m.Upstream.Revision,
			Type:      "machine-learning-model",
			Name:      m.Upstream.Repo,
			Version:   m.Upstream.Revision,
			Publisher: m.Publisher,
			Purl:      fmt.Sprintf("pkg:huggingface/%s@%s", m.Upstream.Repo, m.Upstream.Revision),
			Licenses:  License(m.License),
			ExternalRefs: []ExternalRef{{Type: "distribution", URL: "https://huggingface.co/" + m.Upstream.Repo + "/tree/" + m.Upstream.Revision,
				Comment: "low-side source; never contacted from the high side"}},
		}
		for _, f := range m.Upstream.Files {
			fc := Component{Type: "file", Name: f.Path, Properties: []Property{{"size", fmt.Sprint(f.Size)}}}
			if f.SHA256 != "" && f.SHA256 != modelpin.Unfilled {
				fc.Hashes = []Hash{{"SHA-256", f.SHA256}}
			}
			if f.GitBlobSHA1 != "" {
				fc.Properties = append(fc.Properties, Property{"git:blob-sha1", f.GitBlobSHA1})
			}
			up.Components = append(up.Components, fc)
		}
		served := Component{
			BOMRef:    "model:" + m.ID,
			Type:      "machine-learning-model",
			Name:      m.Name,
			Version:   m.Artifact.Quant,
			Publisher: m.Publisher,
			Licenses:  License(m.License),
			Description: fmt.Sprintf("%s quantized %s (%s), served locally", m.Name, m.Artifact.Quant, m.Artifact.Format),
			Pedigree:  &Pedigree{Ancestors: []Component{up}, Notes: "produced_by: " + m.Artifact.ProducedBy},
			ModelCard: &ModelCard{
				ModelParameters: &ModelParameters{Task: "text-generation", ArchitectureFamily: "transformer", ModelArchitecture: m.Name},
				Considerations: &Considerations{
					UseCases:        []string{"agentic code editing on legacy C/C++/Ada/COBOL in an air-gapped enclave"},
					TechnicalLimits: []string{fmt.Sprintf("context window limited to num_ctx=%d", m.Serve.NumCtx), "quantization reduces accuracy relative to BF16"},
				},
			},
			Properties: []Property{
				{"govcode:num_ctx", fmt.Sprint(m.Serve.NumCtx)},
				{"govcode:max_tokens", fmt.Sprint(m.Serve.MaxTokens)},
				{"govcode:ollama_name", m.Serve.OllamaName},
				{"govcode:ollama_manifest_digest", m.Serve.OllamaDigest},
				{"govcode:vllm_tool_call_parser", m.Serve.VLLMToolParser},
			},
		}
		if m.Artifact.Repo != "" {
			served.Properties = append(served.Properties, Property{"govcode:artifact_source", m.Artifact.Repo + "@" + m.Artifact.Revision})
		}
		for _, f := range m.Artifact.Files {
			fc := Component{Type: "file", Name: f.Path, Properties: []Property{{"size", fmt.Sprint(f.Size)}}}
			if f.SHA256 != "" && f.SHA256 != modelpin.Unfilled {
				fc.Hashes = []Hash{{"SHA-256", f.SHA256}}
			} else {
				fc.Properties = append(fc.Properties, Property{"govcode:status", "NOT STAGED - hash unavailable"})
			}
			served.Components = append(served.Components, fc)
		}
		b.Components = append(b.Components, served)
		b.Dependencies = append(b.Dependencies, Dependency{Ref: served.BOMRef, DependsOn: []string{up.BOMRef}})
	}
	return b
}
