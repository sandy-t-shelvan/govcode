package supply

import (
	"testing"

	"github.com/sandy-t-shelvan/govcode/internal/modelpin"
)

func TestAIBOMListsChatTemplate(t *testing.T) {
	l := &modelpin.Lock{Models: []modelpin.Model{{
		ID: "dev", Name: "Dev", Origin: "FR",
		Artifact: modelpin.Source{Files: []modelpin.File{{Path: "m.gguf", Size: 7, SHA256: "aa"}}},
		Serve: modelpin.Serve{LlamaCppChatTemplate: &modelpin.ChatTemplate{
			File:   modelpin.File{Path: "dev.jinja", Size: 9, SHA256: "bb"},
			Source: "ggml-org/llama.cpp@abc:models/templates/x.jinja",
		}},
	}}}
	var found *Component
	var walk func([]Component)
	walk = func(cs []Component) {
		for i := range cs {
			if cs[i].Name == "dev.jinja" {
				found = &cs[i]
			}
			walk(cs[i].Components)
		}
	}
	walk(AIBOM(l).Components)
	if found == nil {
		t.Fatal("chat template missing from AI-BOM")
	}
	if len(found.Hashes) != 1 || found.Hashes[0].Content != "bb" {
		t.Fatalf("template hash: %+v", found.Hashes)
	}
	var src string
	for _, p := range found.Properties {
		if p.Name == "govcode:source" {
			src = p.Value
		}
	}
	if src != "ggml-org/llama.cpp@abc:models/templates/x.jinja" {
		t.Fatalf("template source property: %q", src)
	}
}
