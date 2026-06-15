package templateclient

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/core/nipopow"
	"github.com/dominant-strategies/go-quai/core/types"
	"github.com/dominant-strategies/go-quai/internal/quaiapi"
)

var (
	ErrMissingNiPoPoWProof         = errors.New("missing nipopowProof")
	ErrTemplateQuaiRootMissing     = errors.New("block template missing quairoot binding")
	ErrTemplateSealPrefixMismatch  = errors.New("block template quairoot does not match nipopowProof template seal hash prefix")
	ErrJSONRPCMissingResult        = errors.New("json-rpc response missing result")
	ErrJSONRPCUnexpectedResultType = errors.New("json-rpc result is not a block template object")
)

type FetchOptions struct {
	HTTPClient  *http.Client
	Timeout     time.Duration
	M           uint64
	Rules       []string
	Request     map[string]any
	StripProof  bool
	Policy      quaiapi.BlockTemplateNiPoPoWRequestPolicy
	SourceLabel string
}

type VerifyOptions struct {
	StripProof bool
	Policy     quaiapi.BlockTemplateNiPoPoWRequestPolicy
}

type FetchResult struct {
	StartedAtUTC       string                                       `json:"startedAtUtc,omitempty"`
	FinishedAtUTC      string                                       `json:"finishedAtUtc,omitempty"`
	RPCSource          string                                       `json:"rpcSource,omitempty"`
	SourceLabel        string                                       `json:"sourceLabel,omitempty"`
	RequestedM         uint64                                       `json:"requestedM,omitempty"`
	Rules              []string                                     `json:"rules,omitempty"`
	ElapsedMS          int64                                        `json:"elapsedMs,omitempty"`
	Accepted           bool                                         `json:"accepted"`
	OK                 bool                                         `json:"ok"`
	VerifiedClientSide bool                                         `json:"verifiedClientSide"`
	BudgetOK           bool                                         `json:"budgetOk"`
	RequiresDB         bool                                         `json:"requiresDb"`
	RequiresRPC        bool                                         `json:"requiresRpc"`
	ProofPresent       bool                                         `json:"proofPresent"`
	ProofStripped      bool                                         `json:"proofStripped"`
	FromCache          bool                                         `json:"fromCache,omitempty"`
	TemplateHash       string                                       `json:"templateHash,omitempty"`
	TemplateSealHash   string                                       `json:"templateSealHash,omitempty"`
	TemplateParentHash string                                       `json:"templateParentHash,omitempty"`
	ZoneHash           string                                       `json:"zoneHash,omitempty"`
	RegionHash         string                                       `json:"regionHash,omitempty"`
	PrimeAnchor        string                                       `json:"primeAnchor,omitempty"`
	PrimeTip           string                                       `json:"primeTip,omitempty"`
	ProofStats         quaiapi.BlockTemplateNiPoPoWProofBudgetStats `json:"proofStats,omitempty"`
	Template           map[string]json.RawMessage                   `json:"template,omitempty"`
	Error              string                                       `json:"error,omitempty"`
}

type jsonRPCError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

type jsonRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int             `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *jsonRPCError   `json:"error,omitempty"`
}

func FetchVerifiedBlockTemplate(ctx context.Context, rawURL string, opts FetchOptions) (FetchResult, error) {
	startedAt := time.Now()
	if ctx == nil {
		ctx = context.Background()
	}
	m := opts.M
	if m == 0 {
		m = nipopow.DefaultTemplateHierarchyProofM
	}
	rules := opts.Rules
	request := copyRequestMap(opts.Request)
	if len(rules) > 0 {
		request["rules"] = rules
	} else if _, ok := request["rules"]; !ok {
		rules = []string{"kawpow"}
		request["rules"] = rules
	} else {
		rules = rulesFromRequestValue(request["rules"])
	}
	out := FetchResult{
		StartedAtUTC:  startedAt.UTC().Format(time.RFC3339Nano),
		RPCSource:     sanitizeSourceURL(rawURL),
		SourceLabel:   opts.SourceLabel,
		RequestedM:    m,
		Rules:         append([]string(nil), rules...),
		RequiresDB:    false,
		RequiresRPC:   true,
		ProofStripped: opts.StripProof,
	}
	finish := func(result FetchResult) FetchResult {
		if result.FinishedAtUTC == "" {
			result.FinishedAtUTC = time.Now().UTC().Format(time.RFC3339Nano)
		}
		return result
	}
	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{}
	}
	if opts.Timeout > 0 && client.Timeout == 0 {
		client.Timeout = opts.Timeout
	}
	request["nipopowProof"] = true
	request["nipopowProofM"] = m
	template, elapsed, err := fetchBlockTemplate(ctx, client, rawURL, request)
	out.ElapsedMS = elapsed
	if err != nil {
		out.Error = err.Error()
		return finish(out), err
	}
	verifyOpts := VerifyOptions{StripProof: opts.StripProof, Policy: opts.Policy}
	verified, err := VerifyBlockTemplateResponse(template, verifyOpts)
	verified.StartedAtUTC = out.StartedAtUTC
	verified.FinishedAtUTC = time.Now().UTC().Format(time.RFC3339Nano)
	verified.RPCSource = out.RPCSource
	verified.SourceLabel = out.SourceLabel
	verified.RequestedM = out.RequestedM
	verified.Rules = out.Rules
	verified.ElapsedMS = out.ElapsedMS
	verified.RequiresRPC = true
	if err != nil {
		verified.Error = err.Error()
		return verified, err
	}
	return verified, nil
}

func VerifyBlockTemplateResponse(template map[string]json.RawMessage, opts VerifyOptions) (FetchResult, error) {
	out := FetchResult{
		RequiresDB:         false,
		RequiresRPC:        false,
		VerifiedClientSide: true,
		ProofStripped:      opts.StripProof,
	}
	proof, err := ExtractProofFromBlockTemplate(template)
	if err != nil {
		out.Error = err.Error()
		return out, err
	}
	out.ProofPresent = true
	populateProofMetadata(&out, proof)
	if err := verifyTemplateVisibleBindings(template, proof); err != nil {
		out.Error = err.Error()
		return out, err
	}
	if err := nipopow.VerifyTemplateHierarchyProofArtifact(proof, nipopow.TemplateHierarchyProofVerificationOptions{}); err != nil {
		out.Error = err.Error()
		return out, err
	}
	stats, err := quaiapi.ValidateBlockTemplateNiPoPoWProofBudget(proof, opts.Policy)
	out.ProofStats = stats
	if err != nil {
		out.Error = err.Error()
		return out, err
	}
	out.BudgetOK = true
	out.Accepted = true
	out.OK = true
	out.Template = copyTemplate(template, opts.StripProof)
	return out, nil
}

func ExtractProofFromBlockTemplate(template map[string]json.RawMessage) (*nipopow.TemplateHierarchyProof, error) {
	if template == nil {
		return nil, ErrJSONRPCUnexpectedResultType
	}
	rawProof, ok := template["nipopowProof"]
	if !ok || len(rawProof) == 0 || string(rawProof) == "null" {
		return nil, ErrMissingNiPoPoWProof
	}
	return DecodeTemplateProof(rawProof)
}

func DecodeTemplateProof(raw json.RawMessage) (*nipopow.TemplateHierarchyProof, error) {
	normalized, err := normalizeProofJSON(raw)
	if err != nil {
		return nil, err
	}
	var proof nipopow.TemplateHierarchyProof
	if err := json.Unmarshal(normalized, &proof); err != nil {
		return nil, err
	}
	return &proof, nil
}

func copyRequestMap(in map[string]any) map[string]any {
	out := make(map[string]any, len(in)+3)
	for key, value := range in {
		out[key] = value
	}
	return out
}

func rulesFromRequestValue(value any) []string {
	switch typed := value.(type) {
	case []string:
		return append([]string(nil), typed...)
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			if rule, ok := item.(string); ok {
				out = append(out, rule)
			}
		}
		return out
	default:
		return nil
	}
}

func fetchBlockTemplate(ctx context.Context, client *http.Client, rawURL string, request map[string]any) (map[string]json.RawMessage, int64, error) {
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "quai_getBlockTemplate",
		"params":  []any{request},
	})
	if err != nil {
		return nil, 0, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	started := time.Now()
	resp, err := client.Do(httpReq)
	elapsed := elapsedMilliseconds(started)
	if err != nil {
		return nil, elapsed, err
	}
	defer resp.Body.Close()
	data, readErr := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if readErr != nil {
		return nil, elapsed, readErr
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, elapsed, fmt.Errorf("http status %d: %s", resp.StatusCode, truncateForReport(string(data), 512))
	}
	var rpcResp jsonRPCResponse
	if err := json.Unmarshal(data, &rpcResp); err != nil {
		return nil, elapsed, fmt.Errorf("decode json-rpc response: %w", err)
	}
	if rpcResp.Error != nil {
		return nil, elapsed, fmt.Errorf("json-rpc error %d: %s", rpcResp.Error.Code, rpcResp.Error.Message)
	}
	if len(rpcResp.Result) == 0 || string(rpcResp.Result) == "null" {
		return nil, elapsed, ErrJSONRPCMissingResult
	}
	var template map[string]json.RawMessage
	if err := json.Unmarshal(rpcResp.Result, &template); err != nil {
		return nil, elapsed, fmt.Errorf("%w: %v", ErrJSONRPCUnexpectedResultType, err)
	}
	return template, elapsed, nil
}

func verifyTemplateVisibleBindings(template map[string]json.RawMessage, proof *nipopow.TemplateHierarchyProof) error {
	if proof == nil {
		return nipopow.ErrTemplateProofMissing
	}
	rawRoot, ok := template["quairoot"]
	if !ok || len(rawRoot) == 0 || string(rawRoot) == "null" {
		return ErrTemplateQuaiRootMissing
	}
	var quaiRoot string
	if err := json.Unmarshal(rawRoot, &quaiRoot); err != nil {
		return fmt.Errorf("decode quairoot: %w", err)
	}
	quaiRoot = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(quaiRoot)), "0x")
	if len(proof.TemplateSealHash.Bytes()) < 6 {
		return ErrTemplateSealPrefixMismatch
	}
	expected := hex.EncodeToString(proof.TemplateSealHash.Bytes()[:6])
	if quaiRoot != expected {
		return fmt.Errorf("%w: template quairoot %s expected %s", ErrTemplateSealPrefixMismatch, quaiRoot, expected)
	}
	return nil
}

func populateProofMetadata(out *FetchResult, proof *nipopow.TemplateHierarchyProof) {
	if out == nil || proof == nil {
		return
	}
	out.TemplateHash = proof.TemplateHash.Hex()
	out.TemplateSealHash = proof.TemplateSealHash.Hex()
	out.TemplateParentHash = proof.TemplateParentHash.Hex()
	out.ZoneHash = proof.Request.ZoneHash.Hex()
	out.RegionHash = proof.Request.RegionHash.Hex()
	out.PrimeAnchor = proof.Request.PrimeAnchor.Hex()
	out.PrimeTip = proof.Request.PrimeTip.Hex()
}

func copyTemplate(template map[string]json.RawMessage, stripProof bool) map[string]json.RawMessage {
	out := make(map[string]json.RawMessage, len(template))
	for key, value := range template {
		if stripProof && key == "nipopowProof" {
			continue
		}
		out[key] = append(json.RawMessage(nil), value...)
	}
	return out
}

func normalizeProofJSON(raw json.RawMessage) ([]byte, error) {
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, err
	}
	pruneEmptyOptionalWorkObjectFields(value)
	return json.Marshal(value)
}

func pruneEmptyOptionalWorkObjectFields(value any) {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if key == "manifestHash" && child == nil {
				typed[key] = zeroManifestHashArray()
				continue
			}
			if isEmptyObject(child) && isOptionalEmptyWorkObjectField(key) {
				delete(typed, key)
				continue
			}
			pruneEmptyOptionalWorkObjectFields(child)
		}
	case []any:
		for _, child := range typed {
			pruneEmptyOptionalWorkObjectFields(child)
		}
	}
}

func isOptionalEmptyWorkObjectField(key string) bool {
	switch key {
	case "auxpow", "scryptDiffAndCount", "shaDiffAndCount":
		return true
	default:
		return false
	}
}

func isEmptyObject(value any) bool {
	object, ok := value.(map[string]any)
	return ok && len(object) == 0
}

func zeroManifestHashArray() []string {
	out := make([]string, common.HierarchyDepth)
	for i := range out {
		out[i] = types.EmptyRootHash.Hex()
	}
	return out
}

func elapsedMilliseconds(started time.Time) int64 {
	ms := time.Since(started).Milliseconds()
	if ms == 0 {
		return 1
	}
	return ms
}

func sanitizeSourceURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	parsed.User = nil
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String()
}

func truncateForReport(value string, max int) string {
	value = strings.TrimSpace(value)
	if len(value) <= max {
		return value
	}
	return value[:max] + "..."
}
