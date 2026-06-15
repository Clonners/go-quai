package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRunObservationMarksHealthyDefaultAndOptInProof(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string                   `json:"method"`
			Params []map[string]interface{} `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if req.Method != "quai_getBlockTemplate" {
			t.Fatalf("unexpected method: %s", req.Method)
		}
		param := map[string]interface{}{}
		if len(req.Params) > 0 {
			param = req.Params[0]
		}
		result := map[string]interface{}{
			"height":            float64(123),
			"previousblockhash": "0xparent",
		}
		if proof, _ := param["nipopowProof"].(bool); proof {
			result["nipopowProof"] = map[string]interface{}{
				"proof": map[string]interface{}{
					"primeProof":   map[string]interface{}{"headers": []interface{}{map[string]interface{}{"hash": "0x1"}, map[string]interface{}{"hash": "0x2"}}},
					"regionHeader": map[string]interface{}{"manifest": []interface{}{"0xzone"}},
					"primeHeader":  map[string]interface{}{"manifest": []interface{}{"0xregion", "0xother"}},
				},
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      1,
			"result":  result,
		})
	}))
	defer server.Close()

	out := runObservation(observeConfig{
		RPCURL:  server.URL,
		Samples: 2,
		M:       2,
		Timeout: 2 * time.Second,
	}, server.Client())

	if !out.DefaultHealthy {
		t.Fatalf("default path should be healthy: %+v", out)
	}
	if out.DefaultProofCount != 0 {
		t.Fatalf("default path unexpectedly saw proofs: %d", out.DefaultProofCount)
	}
	if !out.DeployedOptInAvailable {
		t.Fatalf("opt-in proof path should be available: %+v", out)
	}
	if out.OptInProofCount != 2 {
		t.Fatalf("unexpected opt-in proof count: %d", out.OptInProofCount)
	}
	if out.OptInLatencyMS.Count != 2 || out.OptInLatencyMS.Max <= 0 {
		t.Fatalf("missing opt-in latency stats: %+v", out.OptInLatencyMS)
	}
	if len(out.BlockTemplateResponse) == 0 {
		t.Fatal("expected first opt-in block template response to be preserved for offline verification")
	}
}

func TestRunObservationFailsClosedWhenDefaultContainsProof(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      1,
			"result": map[string]interface{}{
				"height":       float64(123),
				"nipopowProof": map[string]interface{}{"proof": map[string]interface{}{}},
			},
		})
	}))
	defer server.Close()

	out := runObservation(observeConfig{
		RPCURL:  server.URL,
		Samples: 1,
		M:       2,
		Timeout: 2 * time.Second,
	}, server.Client())

	if out.DefaultHealthy {
		t.Fatalf("default path with nipopowProof must not be healthy: %+v", out)
	}
	if out.OK {
		t.Fatalf("gate must not pass when default templates include nipopowProof: %+v", out)
	}
}
