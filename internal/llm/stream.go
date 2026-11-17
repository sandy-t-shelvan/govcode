package llm

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
)

// Streamer is implemented by backends that can deliver content as it is
// generated. onDelta receives raw text fragments; the full Response
// (including tool calls) is returned at the end, exactly as Chat would.
type Streamer interface {
	ChatStream(ctx context.Context, msgs []Message, tools []ToolSpec, onDelta func(string)) (*Response, error)
}

func openStream(ctx context.Context, c *http.Client, url string, body any) (io.ReadCloser, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		return nil, fmt.Errorf("model server %s: HTTP %d: %s", url, resp.StatusCode, truncate(string(data), 500))
	}
	return resp.Body, nil
}

func scanner(r io.Reader) *bufio.Scanner {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 16<<20)
	return sc
}

// ChatStream for Ollama: NDJSON chunks from /api/chat with stream=true.
func (o *Ollama) ChatStream(ctx context.Context, msgs []Message, tools []ToolSpec, onDelta func(string)) (*Response, error) {
	body := o.body(msgs, tools)
	body["stream"] = true
	rc, err := openStream(ctx, o.client, o.BaseURL+"/api/chat", body)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	r := &Response{}
	var content strings.Builder
	sc := scanner(rc)
	for sc.Scan() {
		var ch struct {
			Message         ollamaMsg `json:"message"`
			Done            bool      `json:"done"`
			DoneReason      string    `json:"done_reason"`
			PromptEvalCount int       `json:"prompt_eval_count"`
			EvalCount       int       `json:"eval_count"`
			Error           string    `json:"error"`
		}
		if err := json.Unmarshal(sc.Bytes(), &ch); err != nil {
			return nil, fmt.Errorf("ollama stream: bad chunk: %w", err)
		}
		if ch.Error != "" {
			return nil, fmt.Errorf("ollama: %s", ch.Error)
		}
		if ch.Message.Content != "" {
			content.WriteString(ch.Message.Content)
			if onDelta != nil {
				onDelta(ch.Message.Content)
			}
		}
		for _, tc := range ch.Message.ToolCalls {
			r.ToolCalls = append(r.ToolCalls, ToolCall{ID: fmt.Sprintf("call_%d", len(r.ToolCalls)),
				Name: tc.Function.Name, Args: normalizeArgs(tc.Function.Arguments), Source: SourceNative})
		}
		if ch.Done {
			r.Usage = Usage{PromptTokens: ch.PromptEvalCount, CompletionTokens: ch.EvalCount}
			r.FinishReason = ch.DoneReason
			break
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	r.Content = content.String()
	return r, nil
}

// ChatStream for OpenAI-compatible servers: server-sent events with
// incremental deltas; tool-call fragments are assembled by index.
func (o *OpenAICompat) ChatStream(ctx context.Context, msgs []Message, tools []ToolSpec, onDelta func(string)) (*Response, error) {
	body := o.body(msgs, tools)
	body["stream"] = true
	body["stream_options"] = map[string]any{"include_usage": true}
	rc, err := openStream(ctx, o.client, o.BaseURL+"/chat/completions", body)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	type partial struct {
		id, name string
		args     strings.Builder
	}
	calls := map[int]*partial{}
	r := &Response{}
	var content strings.Builder
	sc := scanner(rc)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if data == "[DONE]" {
			break
		}
		var ch struct {
			Choices []struct {
				Delta struct {
					Content   *string `json:"content"`
					ToolCalls []struct {
						Index    int    `json:"index"`
						ID       string `json:"id"`
						Function struct {
							Name      string `json:"name"`
							Arguments string `json:"arguments"`
						} `json:"function"`
					} `json:"tool_calls"`
				} `json:"delta"`
				FinishReason *string `json:"finish_reason"`
			} `json:"choices"`
			Usage *Usage `json:"usage"`
			Error *struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal([]byte(data), &ch); err != nil {
			return nil, fmt.Errorf("model stream: bad event: %w", err)
		}
		if ch.Error != nil {
			return nil, fmt.Errorf("model server: %s", ch.Error.Message)
		}
		if ch.Usage != nil {
			r.Usage = *ch.Usage
		}
		for _, c := range ch.Choices {
			if c.Delta.Content != nil && *c.Delta.Content != "" {
				content.WriteString(*c.Delta.Content)
				if onDelta != nil {
					onDelta(*c.Delta.Content)
				}
			}
			for _, tc := range c.Delta.ToolCalls {
				p := calls[tc.Index]
				if p == nil {
					p = &partial{}
					calls[tc.Index] = p
				}
				if tc.ID != "" {
					p.id = tc.ID
				}
				if tc.Function.Name != "" {
					p.name += tc.Function.Name
				}
				p.args.WriteString(tc.Function.Arguments)
			}
			if c.FinishReason != nil {
				r.FinishReason = *c.FinishReason
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	idx := make([]int, 0, len(calls))
	for i := range calls {
		idx = append(idx, i)
	}
	sort.Ints(idx)
	for _, i := range idx {
		p := calls[i]
		id := p.id
		if id == "" {
			id = fmt.Sprintf("call_%d", i)
		}
		r.ToolCalls = append(r.ToolCalls, ToolCall{ID: id, Name: p.name, Args: normalizeArgs(json.RawMessage(p.args.String())), Source: SourceNative})
	}
	r.Content = content.String()
	return r, nil
}
