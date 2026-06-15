package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRunCLISelfTestFailsClosedWhenUpstreamProofMissing(t *testing.T) {
	var seenRequest map[string]any
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Params []map[string]any `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode upstream request: %v", err)
		}
		if len(req.Params) != 1 {
			t.Fatalf("expected one upstream request param, got %d", len(req.Params))
		}
		seenRequest = req.Params[0]
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{"height": 1, "quairoot": "abc"}})
	}))
	defer upstream.Close()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runCLI([]string{
		"--upstream", upstream.URL,
		"--listen", "127.0.0.1:0",
		"--self-test-samples", "1",
		"--m", "2",
	}, &stdout, &stderr, upstream.Client())
	if code == 0 {
		t.Fatalf("expected fail-closed proxy self-test failure, stdout=%s", stdout.String())
	}
	if got := seenRequest["nipopowProof"]; got != true {
		t.Fatalf("expected upstream opt-in proof request, got %#v", got)
	}
	var report proxyReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("decode failure report: %v\nstdout=%s stderr=%s", err, stdout.String(), stderr.String())
	}
	if report.OK || report.AcceptedResponses != 0 || report.RejectedResponses == 0 || report.Error == "" {
		t.Fatalf("expected rejected failure report: %+v", report)
	}
}
