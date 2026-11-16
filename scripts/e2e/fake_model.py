#!/usr/bin/env python3
"""Deterministic OpenAI-compatible model server for the end-to-end test.

Replays responses from a JSON file in a loop. Binds 127.0.0.1 only. This is
a test fixture: it lets the two-person approval test run without a GPU.
"""
import json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer

responses = json.load(open(sys.argv[1]))
port = int(sys.argv[2])
state = {"i": 0}

class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass
    def _send(self, obj):
        b = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)
    def do_GET(self):
        self._send({"data": [{"id": "fake-coder", "object": "model"}]})
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        req = json.loads(self.rfile.read(n))
        r = responses[state["i"] % len(responses)]
        state["i"] += 1
        msg = {"role": "assistant", "content": r.get("content", "")}
        if "tool_calls" in r:
            msg["tool_calls"] = [{"id": f"c{state['i']}_{j}", "type": "function",
                                  "function": {"name": c["name"], "arguments": json.dumps(c["arguments"])}}
                                 for j, c in enumerate(r["tool_calls"])]
        self._send({"choices": [{"message": msg, "finish_reason": "tool_calls" if "tool_calls" in r else "stop"}],
                    "usage": {"prompt_tokens": sum(len(m.get("content") or "") for m in req["messages"]) // 3,
                              "completion_tokens": 20}})

HTTPServer(("127.0.0.1", port), H).serve_forever()
