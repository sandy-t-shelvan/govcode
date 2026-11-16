package llm

import (
	"context"
	"fmt"
)

// Scripted replays fixed responses. It exists to test the agent loop and to
// validate the eval harness's scoring independent of any real model.
type Scripted struct {
	Name      string
	Responses []Response
	Opts      Options
	Seen      [][]Message // requests received, for assertions
	i         int
}

func (s *Scripted) Options() Options {
	if s.Opts.NumCtx == 0 {
		return Options{NumCtx: 32768, MaxTokens: 2048}
	}
	return s.Opts
}

func (s *Scripted) ModelName() string { return "scripted:" + s.Name }

func (s *Scripted) Chat(_ context.Context, msgs []Message, _ []ToolSpec) (*Response, error) {
	s.Seen = append(s.Seen, append([]Message(nil), msgs...))
	if s.i >= len(s.Responses) {
		return nil, fmt.Errorf("scripted model exhausted after %d responses", s.i)
	}
	r := s.Responses[s.i]
	s.i++
	return &r, nil
}
