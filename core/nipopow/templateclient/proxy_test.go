package templateclient

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTemplateProxyFailsClosedWhenUpstreamProofMissing(t *testing.T) {
	var seenRequest map[string]any
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string           `json:"method"`
			Params []map[string]any `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode upstream request: %v", err)
		}
		if req.Method != "quai_getBlockTemplate" {
			t.Fatalf("unexpected upstream method: %s", req.Method)
		}
		if len(req.Params) != 1 {
			t.Fatalf("expected one upstream params object, got %d", len(req.Params))
		}
		seenRequest = req.Params[0]
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"result":  map[string]any{"height": 1, "quairoot": "abc"},
		})
	}))
	defer upstream.Close()

	proxy := NewTemplateProxy(ProxyOptions{UpstreamURL: upstream.URL, HTTPClient: upstream.Client(), M: 2, StripProof: true})
	local := httptest.NewServer(proxy)
	defer local.Close()

	rpcErr := callProxyTemplateExpectError(t, local.URL, map[string]any{"rules": []string{"kawpow"}, "extranonce1": "00000001"})
	if rpcErr.Code == 0 || rpcErr.Message == "" {
		t.Fatalf("expected JSON-RPC fail-closed error, got %+v", rpcErr)
	}
	if got := seenRequest["nipopowProof"]; got != true {
		t.Fatalf("expected proxy to force nipopowProof opt-in upstream, got %#v", got)
	}
	if got := uint64(seenRequest["nipopowProofM"].(float64)); got != 2 {
		t.Fatalf("expected proxy to request m=2 upstream, got %d", got)
	}
	if got := seenRequest["extranonce1"]; got != "00000001" {
		t.Fatalf("expected proxy to preserve downstream request fields upstream, got %#v", got)
	}
	stats := proxy.Stats()
	if stats.AcceptedResponses != 0 || stats.RejectedResponses != 1 || stats.UpstreamFetches != 1 {
		t.Fatalf("expected rejected response stats, got %+v", stats)
	}
}

func TestTemplateProxyRejectsUnsupportedMethodWithoutUpstreamFetch(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("unsupported method should not reach upstream")
	}))
	defer upstream.Close()

	proxy := NewTemplateProxy(ProxyOptions{UpstreamURL: upstream.URL, HTTPClient: upstream.Client(), M: 2, StripProof: true})
	local := httptest.NewServer(proxy)
	defer local.Close()

	body := bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"quai_getBalance","params":[]}`)
	resp, err := local.Client().Post(local.URL, "application/json", body)
	if err != nil {
		t.Fatalf("post local proxy: %v", err)
	}
	defer resp.Body.Close()
	var rpcResp struct {
		Error *jsonRPCError `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rpcResp); err != nil {
		t.Fatalf("decode proxy response: %v", err)
	}
	if rpcResp.Error == nil || rpcResp.Error.Code != -32601 {
		t.Fatalf("expected method-not-found error, got %+v", rpcResp.Error)
	}
	if stats := proxy.Stats(); stats.UpstreamFetches != 0 {
		t.Fatalf("unsupported method should not fetch upstream: %+v", stats)
	}
}

func callProxyTemplateExpectError(t *testing.T, rawURL string, params map[string]any) *jsonRPCError {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "quai_getBlockTemplate", "params": []any{params}})
	resp, err := http.Post(rawURL, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post local proxy: %v", err)
	}
	defer resp.Body.Close()
	var rpcResp struct {
		Result map[string]json.RawMessage `json:"result"`
		Error  *jsonRPCError              `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rpcResp); err != nil {
		t.Fatalf("decode proxy response: %v", err)
	}
	if rpcResp.Error == nil {
		t.Fatalf("expected proxy error, got result=%+v", rpcResp.Result)
	}
	return rpcResp.Error
}
