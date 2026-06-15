package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/dominant-strategies/go-quai/core/nipopow"
	"github.com/dominant-strategies/go-quai/internal/quaiapi"
)

type observeConfig struct {
	RPCURL         string
	OutPath        string
	Samples        int
	M              uint64
	Timeout        time.Duration
	NegativeOverM  bool
	SourceLabel    string
	ClientCommit   string
	GatewayPolicy  string
	PublicExposure string
}

type observeOutput struct {
	StartedAtUTC                string                     `json:"startedAtUtc"`
	FinishedAtUTC               string                     `json:"finishedAtUtc"`
	RPCSource                   string                     `json:"rpcSource"`
	SourceLabel                 string                     `json:"sourceLabel,omitempty"`
	ClientCommit                string                     `json:"clientCommit,omitempty"`
	SamplesRequested            int                        `json:"samplesRequested"`
	M                           uint64                     `json:"m"`
	BudgetPolicy                budgetPolicyOutput         `json:"budgetPolicy"`
	GatewayRateLimitScope       string                     `json:"gatewayRateLimitScope"`
	PublicExposure              string                     `json:"publicExposure"`
	EconomicReliance            string                     `json:"economicReliance"`
	DefaultRequests             int                        `json:"defaultRequests"`
	OptInRequests               int                        `json:"optInRequests"`
	NegativeRequests            int                        `json:"negativeRequests,omitempty"`
	NegativeOverMRequested      bool                       `json:"negativeOverMRequested"`
	DefaultProofCount           int                        `json:"defaultProofCount"`
	OptInProofCount             int                        `json:"optInProofCount"`
	DefaultHealthy              bool                       `json:"defaultHealthy"`
	DeployedOptInAvailable      bool                       `json:"deployedOptInAvailable"`
	NegativeOverMErrorContained bool                       `json:"negativeOverMErrorContained"`
	OptInLatencyMS              latencyStats               `json:"optInLatencyMs"`
	Samples                     []templateSample           `json:"samples"`
	BlockTemplateResponse       map[string]json.RawMessage `json:"blockTemplateResponse,omitempty"`
	OK                          bool                       `json:"ok"`
	Error                       string                     `json:"error,omitempty"`
}

type budgetPolicyOutput struct {
	BuildTimeoutMs     int64  `json:"buildTimeoutMs"`
	MaxM               uint64 `json:"maxM"`
	MaxChainLength     uint64 `json:"maxChainLength"`
	MaxProofHeaders    uint64 `json:"maxProofHeaders"`
	MaxManifestHashes  uint64 `json:"maxManifestHashes"`
	MaxSerializedBytes uint64 `json:"maxSerializedBytes"`
	CacheTTLSeconds    int64  `json:"cacheTtlSeconds"`
	RateLimitScope     string `json:"rateLimitScope"`
	FailureSemantics   string `json:"failureSemantics"`
}

type latencyStats struct {
	Count int   `json:"count"`
	P50   int64 `json:"p50"`
	P95   int64 `json:"p95"`
	Max   int64 `json:"max"`
}

type templateSample struct {
	Kind              string                     `json:"kind"`
	Index             int                        `json:"index"`
	Request           map[string]any             `json:"request"`
	ElapsedMS         int64                      `json:"elapsedMs"`
	HTTPStatus        int                        `json:"httpStatus,omitempty"`
	Error             string                     `json:"error,omitempty"`
	RPCError          *jsonRPCError              `json:"rpcError,omitempty"`
	HasResult         bool                       `json:"hasResult"`
	ResultKeys        []string                   `json:"resultKeys,omitempty"`
	HasNiPoPoWProof   bool                       `json:"hasNiPoPoWProof"`
	NiPoPoWProofStats *proofPayloadStats         `json:"nipopowProofStats,omitempty"`
	rawResult         map[string]json.RawMessage `json:"-"`
}

type proofPayloadStats struct {
	PrimeProofHeaders int `json:"primeProofHeaders"`
	RegionManifestLen int `json:"regionManifestLen"`
	PrimeManifestLen  int `json:"primeManifestLen"`
	SerializedBytes   int `json:"serializedBytes"`
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

func main() {
	os.Exit(runCLI(os.Args[1:], os.Stdout, os.Stderr))
}

func runCLI(args []string, stdout io.Writer, stderr io.Writer) int {
	cfg, err := parseCLI(args, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}
	client := &http.Client{Timeout: cfg.Timeout}
	out := runObservation(cfg, client)
	if err := writeObserveReport(stdout, cfg.OutPath, out); err != nil {
		fmt.Fprintf(stderr, "error writing report: %v\n", err)
		return 1
	}
	if !out.OK {
		return 1
	}
	return 0
}

func parseCLI(args []string, stderr io.Writer) (observeConfig, error) {
	cfg := observeConfig{
		Samples:        3,
		M:              2,
		Timeout:        5 * time.Second,
		GatewayPolicy:  "external RPC gateway / local mining client; no in-process per-IP identity at the API layer",
		PublicExposure: "no new public exposure; nipopowProof remains explicit opt-in",
	}
	fs := flag.NewFlagSet("nipopow-template-observe", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&cfg.RPCURL, "rpc", "", "RPC URL to sample, e.g. https://zone.example")
	fs.StringVar(&cfg.OutPath, "out", "", "Optional JSON report path; stdout is used when empty")
	fs.IntVar(&cfg.Samples, "samples", cfg.Samples, "Number of default and opt-in samples to run")
	fs.Uint64Var(&cfg.M, "m", cfg.M, "NiPoPoW proof m requested for opt-in samples")
	fs.DurationVar(&cfg.Timeout, "timeout", cfg.Timeout, "Per-request HTTP timeout")
	fs.BoolVar(&cfg.NegativeOverM, "negative-over-m", false, "Run one over-max-m opt-in request and require an explicit contained error")
	fs.StringVar(&cfg.SourceLabel, "source-label", "", "Non-secret node/source label for evidence")
	fs.StringVar(&cfg.ClientCommit, "client-commit", "", "Local client commit or build identifier for evidence")
	fs.StringVar(&cfg.GatewayPolicy, "gateway-policy", cfg.GatewayPolicy, "Gateway/local-miner rate-limit scope note")
	fs.StringVar(&cfg.PublicExposure, "public-exposure", cfg.PublicExposure, "Public exposure caveat")
	if err := fs.Parse(args); err != nil {
		return cfg, err
	}
	if strings.TrimSpace(cfg.RPCURL) == "" {
		return cfg, errors.New("missing required --rpc")
	}
	if cfg.Samples < 1 {
		cfg.Samples = 1
	}
	if cfg.Timeout <= 0 {
		return cfg, errors.New("--timeout must be positive")
	}
	return cfg, nil
}

func runObservation(cfg observeConfig, client *http.Client) *observeOutput {
	if client == nil {
		client = &http.Client{}
	}
	if cfg.Timeout > 0 && client.Timeout == 0 {
		client.Timeout = cfg.Timeout
	}
	if cfg.Samples < 1 {
		cfg.Samples = 1
	}
	if cfg.M == 0 {
		cfg.M = 2
	}
	out := &observeOutput{
		StartedAtUTC:           time.Now().UTC().Format(time.RFC3339Nano),
		RPCSource:              sanitizeSourceURL(cfg.RPCURL),
		SourceLabel:            cfg.SourceLabel,
		ClientCommit:           cfg.ClientCommit,
		SamplesRequested:       cfg.Samples,
		M:                      cfg.M,
		BudgetPolicy:           defaultBudgetPolicyOutput(),
		GatewayRateLimitScope:  cfg.GatewayPolicy,
		PublicExposure:         cfg.PublicExposure,
		EconomicReliance:       "disabled for this gate; observation only",
		NegativeOverMRequested: cfg.NegativeOverM,
	}
	defer func() {
		out.FinishedAtUTC = time.Now().UTC().Format(time.RFC3339Nano)
		summarizeObservation(out, cfg)
	}()

	ctx := context.Background()
	for i := 0; i < cfg.Samples; i++ {
		sample := callBlockTemplate(ctx, client, cfg.RPCURL, "default", i+1, map[string]any{"rules": []string{"kawpow"}})
		out.Samples = append(out.Samples, sample)
	}
	for i := 0; i < cfg.Samples; i++ {
		req := map[string]any{"rules": []string{"kawpow"}, "nipopowProof": true, "nipopowProofM": cfg.M}
		sample := callBlockTemplate(ctx, client, cfg.RPCURL, "opt-in", i+1, req)
		out.Samples = append(out.Samples, sample)
		if sample.HasNiPoPoWProof && len(out.BlockTemplateResponse) == 0 {
			out.BlockTemplateResponse = sample.rawResult
		}
	}
	if cfg.NegativeOverM {
		req := map[string]any{"rules": []string{"kawpow"}, "nipopowProof": true, "nipopowProofM": quaiapi.DefaultBlockTemplateNiPoPoWProofMaxM + 1}
		sample := callBlockTemplate(ctx, client, cfg.RPCURL, "negative-over-m", 1, req)
		out.Samples = append(out.Samples, sample)
	}
	return out
}

func defaultBudgetPolicyOutput() budgetPolicyOutput {
	return budgetPolicyOutput{
		BuildTimeoutMs:     int64(quaiapi.DefaultBlockTemplateNiPoPoWProofTimeout / time.Millisecond),
		MaxM:               quaiapi.DefaultBlockTemplateNiPoPoWProofMaxM,
		MaxChainLength:     nipopow.DefaultMaxProofChainLength,
		MaxProofHeaders:    nipopow.DefaultMaxProofHeaders,
		MaxManifestHashes:  quaiapi.DefaultBlockTemplateNiPoPoWProofMaxManifestLen,
		MaxSerializedBytes: quaiapi.DefaultBlockTemplateNiPoPoWProofMaxBytes,
		CacheTTLSeconds:    0,
		RateLimitScope:     "external RPC gateway / local mining client; no in-process per-IP identity is available at this API layer",
		FailureSemantics:   "default templates omit nipopowProof; opted-in budget/proof failures return an explicit error and no unverifiable proof payload",
	}
}

func summarizeObservation(out *observeOutput, cfg observeConfig) {
	if out == nil {
		return
	}
	var defaultOK, optInOK, negativeOK bool
	defaultOK = true
	optInOK = true
	negativeOK = !cfg.NegativeOverM
	var optInLatencies []int64
	for _, sample := range out.Samples {
		success := sample.Error == "" && sample.RPCError == nil && sample.HasResult
		switch sample.Kind {
		case "default":
			out.DefaultRequests++
			if sample.HasNiPoPoWProof {
				out.DefaultProofCount++
			}
			if !success || sample.HasNiPoPoWProof {
				defaultOK = false
			}
		case "opt-in":
			out.OptInRequests++
			optInLatencies = append(optInLatencies, sample.ElapsedMS)
			if sample.HasNiPoPoWProof {
				out.OptInProofCount++
			}
			if !success || !sample.HasNiPoPoWProof {
				optInOK = false
			}
		case "negative-over-m":
			out.NegativeRequests++
			negativeOK = (sample.Error != "" || sample.RPCError != nil) && !sample.HasNiPoPoWProof
		}
	}
	if out.DefaultRequests == 0 {
		defaultOK = false
	}
	if out.OptInRequests == 0 {
		optInOK = false
	}
	out.DefaultHealthy = defaultOK
	out.DeployedOptInAvailable = optInOK
	out.NegativeOverMErrorContained = cfg.NegativeOverM && negativeOK
	out.OptInLatencyMS = computeLatencyStats(optInLatencies)
	out.OK = defaultOK && optInOK && negativeOK
	if !out.OK {
		var reasons []string
		if !defaultOK {
			reasons = append(reasons, "default templates unhealthy or unexpectedly include nipopowProof")
		}
		if !optInOK {
			reasons = append(reasons, "deployed opt-in nipopowProof path unavailable or returned no proof")
		}
		if !negativeOK {
			reasons = append(reasons, "negative over-m request did not fail closed with an explicit contained error")
		}
		out.Error = strings.Join(reasons, "; ")
	}
}

func computeLatencyStats(values []int64) latencyStats {
	if len(values) == 0 {
		return latencyStats{}
	}
	sorted := append([]int64(nil), values...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	return latencyStats{
		Count: len(sorted),
		P50:   percentileNearestRank(sorted, 50),
		P95:   percentileNearestRank(sorted, 95),
		Max:   sorted[len(sorted)-1],
	}
}

func percentileNearestRank(sorted []int64, pct int) int64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := (pct*len(sorted) + 99) / 100
	if idx < 1 {
		idx = 1
	}
	if idx > len(sorted) {
		idx = len(sorted)
	}
	return sorted[idx-1]
}

func callBlockTemplate(ctx context.Context, client *http.Client, rawURL, kind string, index int, request map[string]any) templateSample {
	sample := templateSample{Kind: kind, Index: index, Request: request}
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      index,
		"method":  "quai_getBlockTemplate",
		"params":  []any{request},
	})
	if err != nil {
		sample.Error = err.Error()
		return sample
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, bytes.NewReader(body))
	if err != nil {
		sample.Error = err.Error()
		return sample
	}
	httpReq.Header.Set("Content-Type", "application/json")
	started := time.Now()
	resp, err := client.Do(httpReq)
	sample.ElapsedMS = elapsedMilliseconds(started)
	if err != nil {
		sample.Error = err.Error()
		return sample
	}
	defer resp.Body.Close()
	sample.HTTPStatus = resp.StatusCode
	data, readErr := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if readErr != nil {
		sample.Error = readErr.Error()
		return sample
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		sample.Error = fmt.Sprintf("http status %d: %s", resp.StatusCode, truncateForReport(string(data), 512))
		return sample
	}
	var rpcResp jsonRPCResponse
	if err := json.Unmarshal(data, &rpcResp); err != nil {
		sample.Error = fmt.Sprintf("decode json-rpc response: %v", err)
		return sample
	}
	if rpcResp.Error != nil {
		sample.RPCError = rpcResp.Error
		return sample
	}
	if len(rpcResp.Result) == 0 || string(rpcResp.Result) == "null" {
		sample.Error = "json-rpc response missing result"
		return sample
	}
	var result map[string]json.RawMessage
	if err := json.Unmarshal(rpcResp.Result, &result); err != nil {
		sample.Error = fmt.Sprintf("decode block template result: %v", err)
		return sample
	}
	sample.HasResult = true
	sample.rawResult = result
	sample.ResultKeys = sortedRawMessageKeys(result)
	if rawProof, ok := result["nipopowProof"]; ok && len(rawProof) > 0 && string(rawProof) != "null" {
		sample.HasNiPoPoWProof = true
		sample.NiPoPoWProofStats = extractProofPayloadStats(rawProof)
	}
	return sample
}

func elapsedMilliseconds(started time.Time) int64 {
	ms := time.Since(started).Milliseconds()
	if ms == 0 {
		return 1
	}
	return ms
}

func sortedRawMessageKeys(fields map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func extractProofPayloadStats(raw json.RawMessage) *proofPayloadStats {
	stats := &proofPayloadStats{SerializedBytes: len(raw)}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return stats
	}
	stats.PrimeProofHeaders = lenAtPath(value, "proof", "primeProof", "headers")
	stats.RegionManifestLen = lenAtPath(value, "proof", "regionHeader", "manifest")
	stats.PrimeManifestLen = lenAtPath(value, "proof", "primeHeader", "manifest")
	return stats
}

func lenAtPath(value any, path ...string) int {
	current := value
	for _, key := range path {
		object, ok := current.(map[string]any)
		if !ok {
			return 0
		}
		current = object[key]
	}
	array, ok := current.([]any)
	if !ok {
		return 0
	}
	return len(array)
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

func writeObserveReport(stdout io.Writer, outPath string, out *observeOutput) error {
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if strings.TrimSpace(outPath) == "" {
		_, err = stdout.Write(data)
		return err
	}
	return os.WriteFile(outPath, data, 0o644)
}
