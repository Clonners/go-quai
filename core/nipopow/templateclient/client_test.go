package templateclient

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFetchVerifiedBlockTemplateRequestsOptInAndFailsClosedWhenProofMissing(t *testing.T) {
	var seenRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			JSONRPC string           `json:"jsonrpc"`
			ID      int              `json:"id"`
			Method  string           `json:"method"`
			Params  []map[string]any `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if req.Method != "quai_getBlockTemplate" {
			t.Fatalf("unexpected method: %s", req.Method)
		}
		if len(req.Params) != 1 {
			t.Fatalf("expected one params object, got %d", len(req.Params))
		}
		seenRequest = req.Params[0]
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      req.ID,
			"result":  map[string]any{"height": 1, "quairoot": "abcdef"},
		})
	}))
	defer server.Close()

	_, err := FetchVerifiedBlockTemplate(context.Background(), server.URL, FetchOptions{
		HTTPClient: server.Client(),
		M:          2,
		Rules:      []string{"kawpow"},
	})
	if !errors.Is(err, ErrMissingNiPoPoWProof) {
		t.Fatalf("expected fail-closed missing proof error, got %v", err)
	}
	if got := seenRequest["nipopowProof"]; got != true {
		t.Fatalf("expected explicit nipopowProof opt-in, got %#v", got)
	}
	if got := uint64(seenRequest["nipopowProofM"].(float64)); got != 2 {
		t.Fatalf("expected m=2 request, got %d", got)
	}
	if got := seenRequest["rules"].([]any)[0]; got != "kawpow" {
		t.Fatalf("expected kawpow rule forwarded, got %#v", got)
	}
}

func TestVerifyBlockTemplateResponseFailsClosedWhenProofMissing(t *testing.T) {
	_, err := VerifyBlockTemplateResponse(map[string]json.RawMessage{"height": []byte(`1`)}, VerifyOptions{})
	if !errors.Is(err, ErrMissingNiPoPoWProof) {
		t.Fatalf("expected missing proof error, got %v", err)
	}
}

func TestSanitizeSourceURLStripsCredentialsQueryAndFragment(t *testing.T) {
	got := sanitizeSourceURL("https://user:pass@example.invalid/rpc?token=secret#frag")
	if got != "https://example.invalid/rpc" {
		t.Fatalf("unexpected sanitized URL: %s", got)
	}
}
