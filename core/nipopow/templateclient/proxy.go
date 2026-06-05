package templateclient

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/dominant-strategies/go-quai/internal/quaiapi"
)

type ProxyOptions struct {
	UpstreamURL      string
	HTTPClient       *http.Client
	Timeout          time.Duration
	M                uint64
	Rules            []string
	StripProof       bool
	MinFetchInterval time.Duration
	Policy           quaiapi.BlockTemplateNiPoPoWRequestPolicy
	SourceLabel      string
	Now              func() time.Time
}

type ProxyStats struct {
	LocalRequests     uint64 `json:"localRequests"`
	UpstreamFetches   uint64 `json:"upstreamFetches"`
	CacheHits         uint64 `json:"cacheHits"`
	AcceptedResponses uint64 `json:"acceptedResponses"`
	RejectedResponses uint64 `json:"rejectedResponses"`
	LastError         string `json:"lastError,omitempty"`
	LastTemplateHash  string `json:"lastTemplateHash,omitempty"`
}

type TemplateProxy struct {
	opts ProxyOptions

	mu    sync.Mutex
	cache map[string]cachedProxyResult
	stats ProxyStats
}

type cachedProxyResult struct {
	lastFetch time.Time
	result    FetchResult
}

type proxyRPCRequest struct {
	JSONRPC string            `json:"jsonrpc"`
	ID      json.RawMessage   `json:"id"`
	Method  string            `json:"method"`
	Params  []json.RawMessage `json:"params"`
}

type proxyRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *jsonRPCError   `json:"error,omitempty"`
}

func NewTemplateProxy(opts ProxyOptions) *TemplateProxy {
	if opts.Timeout == 0 {
		opts.Timeout = 5 * time.Second
	}
	if opts.HTTPClient == nil {
		opts.HTTPClient = &http.Client{Timeout: opts.Timeout}
	} else if opts.HTTPClient.Timeout == 0 && opts.Timeout > 0 {
		opts.HTTPClient.Timeout = opts.Timeout
	}
	if !opts.StripProof {
		// A local pool/miner proxy should not forward the bulky proof payload to
		// downstream miner-facing consumers by default. Callers that need the raw
		// proof can use FetchVerifiedBlockTemplate directly.
		opts.StripProof = true
	}
	return &TemplateProxy{opts: opts, cache: make(map[string]cachedProxyResult)}
}

func (p *TemplateProxy) Stats() ProxyStats {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.stats
}

func (p *TemplateProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(proxyRPCResponse{JSONRPC: "2.0", Error: &jsonRPCError{Code: -32600, Message: "only POST is supported"}})
		return
	}
	var req proxyRPCRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		_ = json.NewEncoder(w).Encode(proxyRPCResponse{JSONRPC: "2.0", Error: &jsonRPCError{Code: -32700, Message: fmt.Sprintf("parse error: %v", err)}})
		return
	}
	p.recordLocalRequest()
	if req.Method != "quai_getBlockTemplate" {
		_ = json.NewEncoder(w).Encode(proxyRPCResponse{JSONRPC: "2.0", ID: req.ID, Error: &jsonRPCError{Code: -32601, Message: "method not found"}})
		return
	}
	templateRequest, err := decodeTemplateRequest(req.Params)
	if err != nil {
		p.recordRejected(err)
		_ = json.NewEncoder(w).Encode(proxyRPCResponse{JSONRPC: "2.0", ID: req.ID, Error: &jsonRPCError{Code: -32602, Message: err.Error()}})
		return
	}
	result, err := p.Fetch(r.Context(), templateRequest)
	if err != nil {
		_ = json.NewEncoder(w).Encode(proxyRPCResponse{JSONRPC: "2.0", ID: req.ID, Error: &jsonRPCError{Code: -32000, Message: err.Error()}})
		return
	}
	_ = json.NewEncoder(w).Encode(proxyRPCResponse{JSONRPC: "2.0", ID: req.ID, Result: result.Template})
}

func (p *TemplateProxy) Fetch(ctx context.Context, downstreamRequest map[string]any) (FetchResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	cacheKey, err := p.cacheKey(downstreamRequest)
	if err != nil {
		p.recordRejected(err)
		return FetchResult{}, err
	}
	if result, ok := p.cachedWithinInterval(cacheKey); ok {
		p.mu.Lock()
		p.stats.CacheHits++
		p.stats.AcceptedResponses++
		p.mu.Unlock()
		result.FromCache = true
		result.Template = copyTemplate(result.Template, false)
		return result, nil
	}
	result, err := FetchVerifiedBlockTemplate(ctx, p.opts.UpstreamURL, FetchOptions{
		HTTPClient:  p.opts.HTTPClient,
		Timeout:     p.opts.Timeout,
		M:           p.opts.M,
		Rules:       p.opts.Rules,
		Request:     downstreamRequest,
		StripProof:  p.opts.StripProof,
		Policy:      p.opts.Policy,
		SourceLabel: p.opts.SourceLabel,
	})
	p.mu.Lock()
	defer p.mu.Unlock()
	p.stats.UpstreamFetches++
	if err != nil {
		p.stats.RejectedResponses++
		p.stats.LastError = err.Error()
		return result, err
	}
	if p.cache == nil {
		p.cache = make(map[string]cachedProxyResult)
	}
	cachedResult := result
	cachedResult.FromCache = false
	cachedResult.Template = copyTemplate(result.Template, false)
	now := p.now()
	p.pruneExpiredLocked(now)
	p.cache[cacheKey] = cachedProxyResult{lastFetch: now, result: cachedResult}
	p.stats.AcceptedResponses++
	p.stats.LastError = ""
	p.stats.LastTemplateHash = result.TemplateHash
	return result, nil
}

func (p *TemplateProxy) cachedWithinInterval(cacheKey string) (FetchResult, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	cached, exists := p.cache[cacheKey]
	if !exists || !cached.result.Accepted || len(cached.result.Template) == 0 || p.opts.MinFetchInterval <= 0 || cached.lastFetch.IsZero() {
		return FetchResult{}, false
	}
	if p.now().Sub(cached.lastFetch) >= p.opts.MinFetchInterval {
		delete(p.cache, cacheKey)
		return FetchResult{}, false
	}
	result := cached.result
	result.Template = copyTemplate(cached.result.Template, false)
	return result, true
}

func (p *TemplateProxy) recordLocalRequest() {
	p.mu.Lock()
	p.stats.LocalRequests++
	p.mu.Unlock()
}

func (p *TemplateProxy) recordRejected(err error) {
	p.mu.Lock()
	p.stats.RejectedResponses++
	if err != nil {
		p.stats.LastError = err.Error()
	}
	p.mu.Unlock()
}

func (p *TemplateProxy) now() time.Time {
	if p != nil && p.opts.Now != nil {
		return p.opts.Now()
	}
	return time.Now()
}

func (p *TemplateProxy) cacheKey(downstreamRequest map[string]any) (string, error) {
	effectiveRequest := copyRequest(downstreamRequest)
	if len(p.opts.Rules) > 0 {
		rules := make([]string, len(p.opts.Rules))
		copy(rules, p.opts.Rules)
		effectiveRequest["rules"] = rules
	} else if _, ok := effectiveRequest["rules"]; !ok {
		effectiveRequest["rules"] = []string{"kawpow"}
	}
	data, err := json.Marshal(effectiveRequest)
	if err != nil {
		return "", fmt.Errorf("encode cache key: %w", err)
	}
	return string(data), nil
}

func (p *TemplateProxy) pruneExpiredLocked(now time.Time) {
	if p.opts.MinFetchInterval <= 0 {
		p.cache = make(map[string]cachedProxyResult)
		return
	}
	for key, cached := range p.cache {
		if cached.lastFetch.IsZero() || now.Sub(cached.lastFetch) >= p.opts.MinFetchInterval {
			delete(p.cache, key)
		}
	}
}

func copyRequest(request map[string]any) map[string]any {
	if request == nil {
		return map[string]any{}
	}
	out := make(map[string]any, len(request))
	for key, value := range request {
		out[key] = value
	}
	return out
}

func decodeTemplateRequest(params []json.RawMessage) (map[string]any, error) {
	if len(params) == 0 || len(params[0]) == 0 || string(params[0]) == "null" {
		return map[string]any{}, nil
	}
	var request map[string]any
	if err := json.Unmarshal(params[0], &request); err != nil {
		return nil, fmt.Errorf("decode getblocktemplate params: %w", err)
	}
	if request == nil {
		return map[string]any{}, nil
	}
	return request, nil
}
