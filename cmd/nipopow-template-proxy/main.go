package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/dominant-strategies/go-quai/core/nipopow/templateclient"
)

type cliConfig struct {
	UpstreamURL      string
	ListenAddr       string
	OutPath          string
	M                uint64
	Rules            string
	Timeout          time.Duration
	MinFetchInterval time.Duration
	SelfTestSamples  int
	SelfTestInterval time.Duration
}

type proxyReport struct {
	StartedAtUTC       string `json:"startedAtUtc"`
	FinishedAtUTC      string `json:"finishedAtUtc"`
	UpstreamRPC        string `json:"upstreamRpc"`
	ListenAddr         string `json:"listenAddr"`
	SamplesRequested   int    `json:"samplesRequested"`
	RequestedM         uint64 `json:"requestedM"`
	MinFetchIntervalMS int64  `json:"minFetchIntervalMs"`
	SelfTestIntervalMS int64  `json:"selfTestIntervalMs"`
	ObservedDurationMS int64  `json:"observedDurationMs"`
	EconomicReliance   string `json:"economicReliance"`

	LocalRequests     uint64 `json:"localRequests"`
	UpstreamFetches   uint64 `json:"upstreamFetches"`
	CacheHits         uint64 `json:"cacheHits"`
	AcceptedResponses uint64 `json:"acceptedResponses"`
	RejectedResponses uint64 `json:"rejectedResponses"`

	VerifiedClientSide bool           `json:"verifiedClientSide"`
	BudgetOK           bool           `json:"budgetOk"`
	RequiresDB         bool           `json:"requiresDb"`
	RequiresRPC        bool           `json:"requiresRpc"`
	ProofStripped      bool           `json:"proofStripped"`
	LatencyMS          []int64        `json:"latencyMs"`
	LatencySummary     latencySummary `json:"latencySummary"`
	LastTemplateHash   string         `json:"lastTemplateHash,omitempty"`
	OK                 bool           `json:"ok"`
	Error              string         `json:"error,omitempty"`
}

type latencySummary struct {
	Min int64 `json:"min"`
	P50 int64 `json:"p50"`
	P95 int64 `json:"p95"`
	Max int64 `json:"max"`
}

type selfTestRPCResponse struct {
	Result map[string]json.RawMessage  `json:"result,omitempty"`
	Error  *templateclientJSONRPCError `json:"error,omitempty"`
}

type templateclientJSONRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func main() {
	os.Exit(runCLI(os.Args[1:], os.Stdout, os.Stderr, nil))
}

func runCLI(args []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	cfg, err := parseCLI(args, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}
	if client == nil {
		client = &http.Client{Timeout: cfg.Timeout}
	} else if client.Timeout == 0 && cfg.Timeout > 0 {
		client.Timeout = cfg.Timeout
	}
	listener, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		fmt.Fprintf(stderr, "error: listen: %v\n", err)
		return 1
	}
	defer listener.Close()

	proxy := templateclient.NewTemplateProxy(templateclient.ProxyOptions{
		UpstreamURL:      cfg.UpstreamURL,
		HTTPClient:       client,
		Timeout:          cfg.Timeout,
		M:                cfg.M,
		Rules:            splitRules(cfg.Rules),
		StripProof:       true,
		MinFetchInterval: cfg.MinFetchInterval,
	})
	server := &http.Server{Handler: proxy}
	serveErr := make(chan error, 1)
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
			return
		}
		serveErr <- nil
	}()

	if cfg.SelfTestSamples <= 0 {
		fmt.Fprintf(stderr, "serving NiPoPoW template proxy on %s -> %s\n", listener.Addr().String(), sanitizeSourceURL(cfg.UpstreamURL))
		err := <-serveErr
		if err != nil {
			fmt.Fprintf(stderr, "error: serve: %v\n", err)
			return 1
		}
		return 0
	}

	report := runSelfTest(cfg, listener.Addr().String(), proxy, client)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = server.Shutdown(shutdownCtx)
	if err := <-serveErr; err != nil {
		report.OK = false
		report.Error = fmt.Sprintf("serve: %v", err)
	}
	if writeErr := writeReport(stdout, cfg.OutPath, report); writeErr != nil {
		fmt.Fprintf(stderr, "error writing report: %v\n", writeErr)
		return 1
	}
	if !report.OK {
		return 1
	}
	return 0
}

func parseCLI(args []string, stderr io.Writer) (cliConfig, error) {
	cfg := cliConfig{
		ListenAddr:       "127.0.0.1:0",
		M:                2,
		Timeout:          5 * time.Second,
		MinFetchInterval: 2 * time.Second,
	}
	fs := flag.NewFlagSet("nipopow-template-proxy", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&cfg.UpstreamURL, "upstream", "", "Upstream RPC URL to fetch opt-in templates from")
	fs.StringVar(&cfg.ListenAddr, "listen", cfg.ListenAddr, "Local proxy listen address")
	fs.StringVar(&cfg.OutPath, "out", "", "Optional JSON self-test report output path; stdout is used when empty")
	fs.Uint64Var(&cfg.M, "m", cfg.M, "NiPoPoW proof m requested upstream")
	fs.StringVar(&cfg.Rules, "rules", cfg.Rules, "Comma-separated getblocktemplate rules to enforce upstream; empty preserves downstream/default")
	fs.DurationVar(&cfg.Timeout, "timeout", cfg.Timeout, "HTTP timeout")
	fs.DurationVar(&cfg.MinFetchInterval, "min-fetch-interval", cfg.MinFetchInterval, "Minimum interval between upstream opt-in fetches for equivalent downstream requests; cached verified templates are served within this window")
	fs.IntVar(&cfg.SelfTestSamples, "self-test-samples", 0, "If >0, start the proxy, send this many local getblocktemplate requests, write a report, then exit")
	fs.DurationVar(&cfg.SelfTestInterval, "self-test-interval", 0, "Delay between local self-test getblocktemplate requests; use with --self-test-samples for shadow/canary cadence")
	if err := fs.Parse(args); err != nil {
		return cfg, err
	}
	if strings.TrimSpace(cfg.UpstreamURL) == "" {
		return cfg, errors.New("missing required --upstream")
	}
	if cfg.Timeout <= 0 {
		return cfg, errors.New("--timeout must be positive")
	}
	if cfg.MinFetchInterval < 0 {
		return cfg, errors.New("--min-fetch-interval cannot be negative")
	}
	if cfg.SelfTestInterval < 0 {
		return cfg, errors.New("--self-test-interval cannot be negative")
	}
	return cfg, nil
}

func runSelfTest(cfg cliConfig, listenAddr string, proxy *templateclient.TemplateProxy, client *http.Client) proxyReport {
	started := time.Now().UTC()
	report := proxyReport{
		StartedAtUTC:       started.Format(time.RFC3339Nano),
		UpstreamRPC:        sanitizeSourceURL(cfg.UpstreamURL),
		ListenAddr:         listenAddr,
		SamplesRequested:   cfg.SelfTestSamples,
		RequestedM:         cfg.M,
		MinFetchIntervalMS: cfg.MinFetchInterval.Milliseconds(),
		SelfTestIntervalMS: cfg.SelfTestInterval.Milliseconds(),
		EconomicReliance:   "disabled; local proxy shadow/canary self-test only",
		RequiresDB:         false,
		RequiresRPC:        true,
	}
	localURL := "http://" + listenAddr
	if strings.HasPrefix(listenAddr, "[::]") {
		localURL = "http://127.0.0.1" + strings.TrimPrefix(listenAddr, "[::]")
	}
	var firstError string
	proofStripped := true
	observedStarted := time.Now()
	for i := 0; i < cfg.SelfTestSamples; i++ {
		requestStarted := time.Now()
		result, err := callLocalTemplate(client, localURL, i+1)
		report.LatencyMS = append(report.LatencyMS, time.Since(requestStarted).Milliseconds())
		if err != nil {
			if firstError == "" {
				firstError = err.Error()
			}
		} else if _, hasProof := result["nipopowProof"]; hasProof {
			proofStripped = false
		}
		if cfg.SelfTestInterval > 0 && i+1 < cfg.SelfTestSamples {
			time.Sleep(cfg.SelfTestInterval)
		}
	}
	report.ObservedDurationMS = time.Since(observedStarted).Milliseconds()
	report.LatencySummary = summarizeLatencies(report.LatencyMS)
	stats := proxy.Stats()
	report.LocalRequests = stats.LocalRequests
	report.UpstreamFetches = stats.UpstreamFetches
	report.CacheHits = stats.CacheHits
	report.AcceptedResponses = stats.AcceptedResponses
	report.RejectedResponses = stats.RejectedResponses
	report.LastTemplateHash = stats.LastTemplateHash
	report.VerifiedClientSide = report.AcceptedResponses > 0 && firstError == ""
	report.BudgetOK = report.AcceptedResponses > 0 && firstError == ""
	report.ProofStripped = proofStripped && report.AcceptedResponses > 0
	report.OK = firstError == "" && report.AcceptedResponses == uint64(cfg.SelfTestSamples) && report.RejectedResponses == 0
	if !report.OK {
		if firstError != "" {
			report.Error = firstError
		} else if stats.LastError != "" {
			report.Error = stats.LastError
		} else {
			report.Error = "proxy self-test did not accept all local requests"
		}
	}
	report.FinishedAtUTC = time.Now().UTC().Format(time.RFC3339Nano)
	return report
}

func callLocalTemplate(client *http.Client, localURL string, id int) (map[string]json.RawMessage, error) {
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"method":  "quai_getBlockTemplate",
		"params":  []any{map[string]any{"rules": []string{"kawpow"}}},
	})
	if err != nil {
		return nil, err
	}
	resp, err := client.Post(localURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var rpcResp selfTestRPCResponse
	if err := json.NewDecoder(resp.Body).Decode(&rpcResp); err != nil {
		return nil, err
	}
	if rpcResp.Error != nil {
		return nil, fmt.Errorf("json-rpc error %d: %s", rpcResp.Error.Code, rpcResp.Error.Message)
	}
	if len(rpcResp.Result) == 0 {
		return nil, errors.New("missing local proxy result")
	}
	return rpcResp.Result, nil
}

func splitRules(raw string) []string {
	var out []string
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func summarizeLatencies(values []int64) latencySummary {
	if len(values) == 0 {
		return latencySummary{}
	}
	sorted := append([]int64(nil), values...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	percentile := func(numerator int) int64 {
		idx := (len(sorted)*numerator + 99) / 100
		if idx <= 0 {
			idx = 1
		}
		if idx > len(sorted) {
			idx = len(sorted)
		}
		return sorted[idx-1]
	}
	return latencySummary{
		Min: sorted[0],
		P50: percentile(50),
		P95: percentile(95),
		Max: sorted[len(sorted)-1],
	}
}

func writeReport(stdout io.Writer, outPath string, report proxyReport) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if strings.TrimSpace(outPath) != "" {
		return os.WriteFile(outPath, data, 0o644)
	}
	_, err = stdout.Write(data)
	return err
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
