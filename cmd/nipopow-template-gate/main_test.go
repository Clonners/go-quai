package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dominant-strategies/go-quai/core/nipopow/templateclient"
)

func TestRunCLIFailsClosedWhenProofMissing(t *testing.T) {
	var seenRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Params []map[string]any `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if len(req.Params) != 1 {
			t.Fatalf("expected one request param, got %d", len(req.Params))
		}
		seenRequest = req.Params[0]
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"result":  map[string]any{"height": 1},
		})
	}))
	defer server.Close()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runCLI([]string{"--rpc", server.URL, "--m", "2"}, &stdout, &stderr, server.Client())
	if code == 0 {
		t.Fatalf("expected fail-closed CLI failure, stdout=%s", stdout.String())
	}
	if got := seenRequest["nipopowProof"]; got != true {
		t.Fatalf("expected upstream opt-in proof request, got %#v", got)
	}
	var out templateclient.FetchResult
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		t.Fatalf("expected JSON failure report: %v\nstdout=%s stderr=%s", err, stdout.String(), stderr.String())
	}
	if out.OK || out.Accepted {
		t.Fatalf("missing proof must not be accepted: %+v", out)
	}
	if out.Error == "" {
		t.Fatalf("expected error in failure report: %+v", out)
	}
}
