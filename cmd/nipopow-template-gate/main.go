package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dominant-strategies/go-quai/core/nipopow/templateclient"
)

type cliConfig struct {
	RPCURL     string
	OutPath    string
	M          uint64
	Rules      string
	Timeout    time.Duration
	StripProof bool
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
	} else if cfg.Timeout > 0 && client.Timeout == 0 {
		client.Timeout = cfg.Timeout
	}
	result, err := templateclient.FetchVerifiedBlockTemplate(nil, cfg.RPCURL, templateclient.FetchOptions{
		HTTPClient: client,
		Timeout:    cfg.Timeout,
		M:          cfg.M,
		Rules:      splitRules(cfg.Rules),
		StripProof: cfg.StripProof,
	})
	if err != nil && result.Error == "" {
		result.Error = err.Error()
	}
	if writeErr := writeResult(stdout, cfg.OutPath, result); writeErr != nil {
		fmt.Fprintf(stderr, "error writing report: %v\n", writeErr)
		return 1
	}
	if err != nil || !result.OK || !result.Accepted {
		return 1
	}
	return 0
}

func parseCLI(args []string, stderr io.Writer) (cliConfig, error) {
	cfg := cliConfig{
		M:       2,
		Rules:   "kawpow",
		Timeout: 5 * time.Second,
	}
	fs := flag.NewFlagSet("nipopow-template-gate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&cfg.RPCURL, "rpc", "", "RPC URL to fetch an opt-in quai_getBlockTemplate from")
	fs.StringVar(&cfg.OutPath, "out", "", "Optional JSON report path; stdout is used when empty")
	fs.Uint64Var(&cfg.M, "m", cfg.M, "NiPoPoW proof m requested for the opt-in template")
	fs.StringVar(&cfg.Rules, "rules", cfg.Rules, "Comma-separated getblocktemplate rules, e.g. kawpow")
	fs.DurationVar(&cfg.Timeout, "timeout", cfg.Timeout, "Per-request HTTP timeout")
	fs.BoolVar(&cfg.StripProof, "strip-proof", false, "Strip nipopowProof from the accepted miner-facing template in the output report")
	if err := fs.Parse(args); err != nil {
		return cfg, err
	}
	if strings.TrimSpace(cfg.RPCURL) == "" {
		return cfg, errors.New("missing required --rpc")
	}
	if cfg.Timeout <= 0 {
		return cfg, errors.New("--timeout must be positive")
	}
	return cfg, nil
}

func splitRules(raw string) []string {
	var out []string
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	if len(out) == 0 {
		return []string{"kawpow"}
	}
	return out
}

func writeResult(stdout io.Writer, outPath string, result templateclient.FetchResult) error {
	data, err := json.MarshalIndent(result, "", "  ")
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
