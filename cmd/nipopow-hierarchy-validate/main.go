package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/core/nipopow"
	"github.com/dominant-strategies/go-quai/core/rawdb"
	"github.com/dominant-strategies/go-quai/core/types"
	"github.com/dominant-strategies/go-quai/ethdb"
	"github.com/dominant-strategies/go-quai/internal/quaiapi"
	"github.com/dominant-strategies/go-quai/log"
	"github.com/dominant-strategies/go-quai/quaiclient"
	"github.com/dominant-strategies/go-quai/rpc"
	"github.com/dominant-strategies/go-quai/trie"
)

type cliConfig struct {
	PrimeDBPath        string
	PrimeAncientPath   string
	RegionDBPath       string
	RegionAncientPath  string
	ZoneDBPath         string
	ZoneAncientPath    string
	DBEngine           string
	RegionLocation     common.Location
	ZoneLocation       common.Location
	OutPath            string
	Timeout            time.Duration
	Request            nipopow.HierarchyProofRequest
	AutoSelect         autoSelectConfig
	TemplateShadowRPC  string
	BlockTemplateOptIn bool
}

type autoSelectConfig struct {
	Enabled      bool
	RegionWindow uint64
	PrimeWindow  uint64
	Limits       nipopow.BuildLimits
}

type autoSelectStats struct {
	RegionBlocksScanned   uint64            `json:"regionBlocksScanned"`
	PrimeBlocksScanned    uint64            `json:"primeBlocksScanned"`
	RegionManifestEntries uint64            `json:"regionManifestEntries"`
	PrimeManifestEntries  uint64            `json:"primeManifestEntries"`
	CandidatesConsidered  uint64            `json:"candidatesConsidered"`
	CandidatesRejected    uint64            `json:"candidatesRejected"`
	SelectedChainLength   uint64            `json:"selectedChainLength,omitempty"`
	RejectReasons         map[string]uint64 `json:"rejectReasons,omitempty"`
}

var ErrNoHierarchyCandidate = errors.New("no hierarchy proof candidate found")

type hierarchyOutput struct {
	StartedAtUTC                        string                        `json:"startedAtUtc"`
	FinishedAtUTC                       string                        `json:"finishedAtUtc"`
	ReadOnly                            bool                          `json:"readOnly"`
	LocalPathsRedacted                  bool                          `json:"localPathsRedacted"`
	PrimeDBPath                         string                        `json:"primeDbPath,omitempty"`
	RegionDBPath                        string                        `json:"regionDbPath,omitempty"`
	ZoneDBPath                          string                        `json:"zoneDbPath,omitempty"`
	PrimeAncientPath                    string                        `json:"primeAncientPath,omitempty"`
	RegionAncientPath                   string                        `json:"regionAncientPath,omitempty"`
	ZoneAncientPath                     string                        `json:"zoneAncientPath,omitempty"`
	RegionLocation                      string                        `json:"regionLocation"`
	ZoneLocation                        string                        `json:"zoneLocation"`
	Request                             nipopow.HierarchyProofRequest `json:"request"`
	AutoSelect                          bool                          `json:"autoSelect"`
	AutoSelectStats                     *autoSelectStats              `json:"autoSelectStats,omitempty"`
	TemplateShadow                      bool                          `json:"templateShadow"`
	TemplateShadowRPC                   string                        `json:"templateShadowRpc,omitempty"`
	TemplateLocation                    string                        `json:"templateLocation,omitempty"`
	TemplateHash                        common.Hash                   `json:"templateHash,omitempty"`
	TemplateSealHash                    common.Hash                   `json:"templateSealHash,omitempty"`
	TemplateParentHash                  common.Hash                   `json:"templateParentHash,omitempty"`
	TemplateRegionContextHash           common.Hash                   `json:"templateRegionContextHash,omitempty"`
	TemplatePrimeContextHash            common.Hash                   `json:"templatePrimeContextHash,omitempty"`
	TemplateNumber                      uint64                        `json:"templateNumber,omitempty"`
	BlockTemplateOptIn                  bool                          `json:"blockTemplateOptIn"`
	FetchBlockTemplateElapsedMS         int64                         `json:"fetchBlockTemplateElapsedMs,omitempty"`
	BlockTemplateDefaultHadNiPoPoWProof bool                          `json:"blockTemplateDefaultHadNiPoPoWProof"`
	BlockTemplateBuildElapsedMS         int64                         `json:"blockTemplateBuildElapsedMs,omitempty"`
	BlockTemplateHasNiPoPoWProof        bool                          `json:"blockTemplateHasNiPoPoWProof,omitempty"`
	BlockTemplateResponseKeys           []string                      `json:"blockTemplateResponseKeys,omitempty"`
	BlockTemplateProofTemplateHash      common.Hash                   `json:"blockTemplateProofTemplateHash,omitempty"`
	BlockTemplateProofPrimeProofHeaders int                           `json:"blockTemplateProofPrimeProofHeaders,omitempty"`
	BlockTemplateResponse               map[string]interface{}        `json:"blockTemplateResponse,omitempty"`
	OpenElapsedMS                       int64                         `json:"openElapsedMs,omitempty"`
	FetchPendingElapsedMS               int64                         `json:"fetchPendingElapsedMs,omitempty"`
	CollectElapsedMS                    int64                         `json:"collectElapsedMs,omitempty"`
	ZoneNumber                          uint64                        `json:"zoneNumber,omitempty"`
	RegionNumber                        uint64                        `json:"regionNumber,omitempty"`
	PrimeTipNumber                      uint64                        `json:"primeTipNumber,omitempty"`
	PrimeProofHeaders                   int                           `json:"primeProofHeaders,omitempty"`
	RegionManifestLen                   int                           `json:"regionManifestLen,omitempty"`
	PrimeManifestLen                    int                           `json:"primeManifestLen,omitempty"`
	OK                                  bool                          `json:"ok"`
	Error                               string                        `json:"error,omitempty"`
}
type rawHierarchySource struct {
	prime   ethdb.Database
	region  ethdb.Database
	zone    ethdb.Database
	genesis map[common.Hash]struct{}
}

func main() {
	os.Exit(runCLI(os.Args[1:], os.Stdout, os.Stderr))
}

func runCLI(args []string, stdout io.Writer, stderr io.Writer) int {
	log.Global.SetOutput(io.Discard)
	log.Global.SetLevel(logrus.ErrorLevel)

	cfg, err := parseCLI(args, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}
	out := hierarchyOutput{
		StartedAtUTC:       time.Now().UTC().Format(time.RFC3339Nano),
		ReadOnly:           true,
		LocalPathsRedacted: true,
		PrimeDBPath:        redactLocalPath(cfg.PrimeDBPath),
		RegionDBPath:       redactLocalPath(cfg.RegionDBPath),
		ZoneDBPath:         redactLocalPath(cfg.ZoneDBPath),
		PrimeAncientPath:   redactLocalPath(cfg.PrimeAncientPath),
		RegionAncientPath:  redactLocalPath(cfg.RegionAncientPath),
		ZoneAncientPath:    redactLocalPath(cfg.ZoneAncientPath),
		RegionLocation:     cfg.RegionLocation.Name(),
		ZoneLocation:       cfg.ZoneLocation.Name(),
		Request:            cfg.Request,
		AutoSelect:         cfg.AutoSelect.Enabled,
		BlockTemplateOptIn: cfg.BlockTemplateOptIn,
	}
	defer func() {
		out.FinishedAtUTC = time.Now().UTC().Format(time.RFC3339Nano)
	}()

	openStarted := time.Now()
	source, closeFn, err := openRawHierarchySource(cfg)
	out.OpenElapsedMS = time.Since(openStarted).Milliseconds()
	if err != nil {
		out.Error = fmt.Sprintf("open readonly dbs: %v", err)
		_ = writeFinalReport(stdout, cfg.OutPath, &out)
		return 1
	}
	defer closeFn()

	ctx := context.Background()
	if cfg.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cfg.Timeout)
		defer cancel()
	}
	if cfg.TemplateShadowRPC != "" {
		out.TemplateShadow = true
		out.TemplateShadowRPC = sanitizeSourceURL(cfg.TemplateShadowRPC)
		fetchStarted := time.Now()
		pending, err := fetchPendingHeaderFromRPC(ctx, cfg.TemplateShadowRPC)
		out.FetchPendingElapsedMS = time.Since(fetchStarted).Milliseconds()
		if err != nil {
			out.Error = fmt.Sprintf("fetch pending template: %v", err)
			_ = writeFinalReport(stdout, cfg.OutPath, &out)
			return 1
		}
		var baseBlockTemplate map[string]interface{}
		if cfg.BlockTemplateOptIn {
			fetchBlockTemplateStarted := time.Now()
			baseBlockTemplate, err = fetchBlockTemplateFromRPC(ctx, cfg.TemplateShadowRPC)
			out.FetchBlockTemplateElapsedMS = time.Since(fetchBlockTemplateStarted).Milliseconds()
			if err != nil {
				out.Error = fmt.Sprintf("fetch block template: %v", err)
				_ = writeFinalReport(stdout, cfg.OutPath, &out)
				return 1
			}
			_, out.BlockTemplateDefaultHadNiPoPoWProof = baseBlockTemplate["nipopowProof"]
		}
		collectStarted := time.Now()
		result, err := collectTemplateShadowProof(ctx, source, pending, nipopow.TemplateHierarchyProofOptions{
			M:      cfg.Request.M,
			Limits: cfg.Request.Limits,
		})
		out.CollectElapsedMS = time.Since(collectStarted).Milliseconds()
		if err != nil {
			out.Error = err.Error()
			_ = writeFinalReport(stdout, cfg.OutPath, &out)
			return 1
		}
		populateTemplateShadowOutput(&out, pending, result)
		if cfg.BlockTemplateOptIn {
			buildStarted := time.Now()
			response, err := buildBlockTemplateOptInResponse(ctx, source, pending, nipopow.TemplateHierarchyProofOptions{
				M:           cfg.Request.M,
				PrimeAnchor: cfg.Request.PrimeAnchor,
				Limits:      cfg.Request.Limits,
			}, baseBlockTemplate)
			out.BlockTemplateBuildElapsedMS = time.Since(buildStarted).Milliseconds()
			if err != nil {
				out.Error = fmt.Sprintf("block template opt-in: %v", err)
				_ = writeFinalReport(stdout, cfg.OutPath, &out)
				return 1
			}
			populateBlockTemplateOptInOutput(&out, response)
		}
		if err := writeFinalReport(stdout, cfg.OutPath, &out); err != nil {
			fmt.Fprintf(stderr, "error writing report: %v\n", err)
			return 1
		}
		return 0
	}
	if cfg.AutoSelect.Enabled {
		selected, stats, err := selectHierarchyProofRequest(ctx, source, autoSelectConfig{
			Enabled:      true,
			RegionWindow: cfg.AutoSelect.RegionWindow,
			PrimeWindow:  cfg.AutoSelect.PrimeWindow,
			Limits:       cfg.Request.Limits,
		})
		out.AutoSelectStats = &stats
		if err != nil {
			out.Error = fmt.Sprintf("auto-select: %v", err)
			_ = writeFinalReport(stdout, cfg.OutPath, &out)
			return 1
		}
		cfg.Request = selected
		out.Request = selected
	}
	collectStarted := time.Now()
	proof, err := nipopow.CollectHierarchyProofWithContext(ctx, source, cfg.Request)
	out.CollectElapsedMS = time.Since(collectStarted).Milliseconds()
	if err != nil {
		out.Error = err.Error()
		_ = writeFinalReport(stdout, cfg.OutPath, &out)
		return 1
	}

	out.ZoneNumber = proof.ZoneHeader.NumberU64(common.ZONE_CTX)
	out.RegionNumber = proof.RegionHeader.NumberU64(common.REGION_CTX)
	out.PrimeTipNumber = proof.PrimeHeader.NumberU64(common.PRIME_CTX)
	out.PrimeProofHeaders = len(proof.PrimeProof.Headers)
	out.RegionManifestLen = len(proof.RegionHeader.Manifest())
	out.PrimeManifestLen = len(proof.PrimeHeader.Manifest())
	out.OK = true
	if err := writeFinalReport(stdout, cfg.OutPath, &out); err != nil {
		fmt.Fprintf(stderr, "error writing report: %v\n", err)
		return 1
	}
	return 0
}

func fetchPendingHeaderFromRPC(ctx context.Context, rawURL string) (*types.WorkObject, error) {
	if strings.TrimSpace(rawURL) == "" {
		return nil, errors.New("empty pending template RPC URL")
	}
	client, err := rpc.DialContext(ctx, rawURL)
	if err != nil {
		return nil, err
	}
	defer client.Close()
	pending, err := quaiclient.NewClient(client).GetPendingHeader(ctx)
	if err != nil {
		return nil, err
	}
	if pending == nil {
		return nil, errors.New("pending header RPC returned nil")
	}
	return pending, nil
}

func fetchBlockTemplateFromRPC(ctx context.Context, rawURL string) (map[string]interface{}, error) {
	if strings.TrimSpace(rawURL) == "" {
		return nil, errors.New("empty block template RPC URL")
	}
	client, err := rpc.DialContext(ctx, rawURL)
	if err != nil {
		return nil, err
	}
	defer client.Close()
	var template map[string]interface{}
	if err := client.CallContext(ctx, &template, "quai_getBlockTemplate", map[string]interface{}{"rules": []string{"kawpow"}}); err != nil {
		return nil, err
	}
	if template == nil {
		return nil, errors.New("block template RPC returned nil")
	}
	return template, nil
}

func collectTemplateShadowProof(ctx context.Context, source nipopow.HierarchyProofSource, pending *types.WorkObject, opts nipopow.TemplateHierarchyProofOptions) (*nipopow.TemplateHierarchyProof, error) {
	return nipopow.BuildTemplateHierarchyProofWithContext(ctx, source, pending, opts)
}

func populateTemplateShadowOutput(out *hierarchyOutput, pending *types.WorkObject, result *nipopow.TemplateHierarchyProof) {
	if out == nil || pending == nil || result == nil || result.Proof == nil {
		return
	}
	out.Request = result.Request
	out.TemplateLocation = pending.Location().Name()
	out.TemplateHash = result.TemplateHash
	out.TemplateSealHash = result.TemplateSealHash
	out.TemplateParentHash = result.TemplateParentHash
	out.TemplateRegionContextHash = pending.ParentHash(common.REGION_CTX)
	out.TemplatePrimeContextHash = pending.ParentHash(common.PRIME_CTX)
	out.TemplateNumber = pending.NumberU64(common.ZONE_CTX)
	out.ZoneNumber = result.Proof.ZoneHeader.NumberU64(common.ZONE_CTX)
	out.RegionNumber = result.Proof.RegionHeader.NumberU64(common.REGION_CTX)
	out.PrimeTipNumber = result.Proof.PrimeHeader.NumberU64(common.PRIME_CTX)
	out.PrimeProofHeaders = len(result.Proof.PrimeProof.Headers)
	out.RegionManifestLen = len(result.Proof.RegionHeader.Manifest())
	out.PrimeManifestLen = len(result.Proof.PrimeHeader.Manifest())
	out.OK = true
}

func buildBlockTemplateOptInResponse(ctx context.Context, source nipopow.HierarchyProofSource, pending *types.WorkObject, opts nipopow.TemplateHierarchyProofOptions, baseTemplate map[string]interface{}) (map[string]interface{}, error) {
	template := make(map[string]interface{}, len(baseTemplate)+1)
	if baseTemplate != nil {
		for key, value := range baseTemplate {
			template[key] = value
		}
		if _, ok := template["nipopowProof"]; ok {
			return nil, errors.New("default block template unexpectedly already contains nipopowProof")
		}
	} else {
		var err error
		template, err = quaiapi.MarshalAuxPowTemplate(pending, &quaiapi.BlockTemplateRequest{
			NiPoPoWProof:       true,
			NiPoPoWProofM:      opts.M,
			NiPoPoWPrimeAnchor: opts.PrimeAnchor,
		})
		if err != nil {
			return nil, err
		}
	}
	proof, err := collectTemplateShadowProof(ctx, source, pending, opts)
	if err != nil {
		return nil, err
	}
	template["nipopowProof"] = proof
	return template, nil
}

func populateBlockTemplateOptInOutput(out *hierarchyOutput, response map[string]interface{}) {
	if out == nil || response == nil {
		return
	}
	out.BlockTemplateResponse = response
	out.BlockTemplateResponseKeys = make([]string, 0, len(response))
	for key := range response {
		out.BlockTemplateResponseKeys = append(out.BlockTemplateResponseKeys, key)
	}
	sort.Strings(out.BlockTemplateResponseKeys)
	proof, ok := response["nipopowProof"].(*nipopow.TemplateHierarchyProof)
	if !ok || proof == nil {
		return
	}
	out.BlockTemplateHasNiPoPoWProof = true
	out.BlockTemplateProofTemplateHash = proof.TemplateHash
	if proof.Proof != nil {
		out.BlockTemplateProofPrimeProofHeaders = len(proof.Proof.PrimeProof.Headers)
	}
}

func parseCLI(args []string, stderr io.Writer) (cliConfig, error) {
	cfg := cliConfig{
		RegionLocation: common.Location{0},
		ZoneLocation:   common.Location{0, 0},
	}
	var regionLocation string
	var zoneLocation string
	var zoneHash string
	var regionHash string
	var primeAnchor string
	var primeTip string
	fs := flag.NewFlagSet("nipopow-hierarchy-validate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&cfg.PrimeDBPath, "prime.db", "", "Prime chaindata path to open read-only")
	fs.StringVar(&cfg.PrimeAncientPath, "prime.ancient", "", "Prime ancient path; defaults to <prime.db>/ancient when present")
	fs.StringVar(&cfg.RegionDBPath, "region.db", "", "Region chaindata path to open read-only")
	fs.StringVar(&cfg.RegionAncientPath, "region.ancient", "", "Region ancient path; defaults to <region.db>/ancient when present")
	fs.StringVar(&cfg.ZoneDBPath, "zone.db", "", "Zone chaindata path to open read-only")
	fs.StringVar(&cfg.ZoneAncientPath, "zone.ancient", "", "Zone ancient path; defaults to <zone.db>/ancient when present")
	fs.StringVar(&cfg.DBEngine, "db.engine", "leveldb", "Database engine: leveldb or pebble")
	fs.StringVar(&cfg.OutPath, "out", "", "Optional JSON report output path; stdout is used when empty")
	fs.StringVar(&regionLocation, "region.location", "0", "Region location, e.g. 0")
	fs.StringVar(&zoneLocation, "zone.location", "0,0", "Zone location, e.g. 0,0")
	fs.StringVar(&zoneHash, "zone-hash", "", "Zone header hash to bind into the Region manifest")
	fs.StringVar(&regionHash, "region-hash", "", "Region header hash to bind into the Prime manifest")
	fs.StringVar(&primeAnchor, "prime-anchor", "", "Prime proof anchor hash")
	fs.StringVar(&primeTip, "prime-tip", "", "Prime manifest carrier / proof tip hash")
	fs.StringVar(&cfg.TemplateShadowRPC, "template-shadow-rpc", "", "Fetch quai_getPendingHeader from this RPC and validate the pending template's shadow hierarchy proof")
	fs.BoolVar(&cfg.BlockTemplateOptIn, "block-template-optin", false, "Also build a snapshot-backed quai_getBlockTemplate response with explicit nipopowProof opt-in")
	fs.BoolVar(&cfg.AutoSelect.Enabled, "auto-select", false, "Derive Zone/Region/Prime hashes by scanning read-only manifests instead of requiring explicit hashes")
	fs.Uint64Var(&cfg.AutoSelect.RegionWindow, "auto.region-window", nipopow.DefaultMaxProofChainLength, "Maximum canonical Region blocks to scan backwards for a Zone manifest entry")
	fs.Uint64Var(&cfg.AutoSelect.PrimeWindow, "auto.prime-window", nipopow.DefaultMaxProofChainLength, "Maximum canonical Prime blocks to scan backwards for a Region manifest entry")
	fs.Uint64Var(&cfg.Request.M, "m", 16, "NiPoPoW suffix length for explicit mode; auto-select derives a full suffix for the selected range")
	fs.Uint64Var(&cfg.Request.Limits.MaxChainLength, "max-chain", nipopow.DefaultMaxProofChainLength, "Maximum Prime canonical chain walk length")
	fs.Uint64Var(&cfg.Request.Limits.MaxProofHeaders, "max-headers", nipopow.DefaultMaxProofHeaders, "Maximum compressed Prime proof header count")
	fs.Uint64Var(&cfg.Request.Limits.MaxM, "max-m", nipopow.DefaultMaxProofM, "Maximum allowed m")
	fs.DurationVar(&cfg.Timeout, "timeout", 2*time.Minute, "Collection timeout")
	if err := fs.Parse(args); err != nil {
		return cfg, err
	}
	if cfg.PrimeDBPath == "" || cfg.RegionDBPath == "" || cfg.ZoneDBPath == "" {
		return cfg, errors.New("missing required --prime.db, --region.db, or --zone.db")
	}
	var err error
	cfg.RegionLocation, err = parseLocation(regionLocation, common.REGION_CTX)
	if err != nil {
		return cfg, fmt.Errorf("region.location: %w", err)
	}
	cfg.ZoneLocation, err = parseLocation(zoneLocation, common.ZONE_CTX)
	if err != nil {
		return cfg, fmt.Errorf("zone.location: %w", err)
	}
	if cfg.PrimeAncientPath == "" {
		cfg.PrimeAncientPath = defaultAncientPath(cfg.PrimeDBPath)
	}
	if cfg.RegionAncientPath == "" {
		cfg.RegionAncientPath = defaultAncientPath(cfg.RegionDBPath)
	}
	if cfg.ZoneAncientPath == "" {
		cfg.ZoneAncientPath = defaultAncientPath(cfg.ZoneDBPath)
	}
	if cfg.AutoSelect.Enabled && strings.TrimSpace(cfg.TemplateShadowRPC) != "" {
		return cfg, errors.New("--auto-select cannot be combined with --template-shadow-rpc")
	}
	if cfg.BlockTemplateOptIn && strings.TrimSpace(cfg.TemplateShadowRPC) == "" {
		return cfg, errors.New("--block-template-optin requires --template-shadow-rpc")
	}
	if strings.TrimSpace(cfg.TemplateShadowRPC) != "" {
		cfg.TemplateShadowRPC = strings.TrimSpace(cfg.TemplateShadowRPC)
		cfg.AutoSelect.Limits = cfg.Request.Limits
		return cfg, nil
	}
	if cfg.AutoSelect.Enabled {
		cfg.AutoSelect.Limits = cfg.Request.Limits
		return cfg, nil
	}
	if cfg.Request.ZoneHash, err = parseRequiredHash("zone-hash", zoneHash); err != nil {
		return cfg, err
	}
	if cfg.Request.RegionHash, err = parseRequiredHash("region-hash", regionHash); err != nil {
		return cfg, err
	}
	if cfg.Request.PrimeAnchor, err = parseRequiredHash("prime-anchor", primeAnchor); err != nil {
		return cfg, err
	}
	if cfg.Request.PrimeTip, err = parseRequiredHash("prime-tip", primeTip); err != nil {
		return cfg, err
	}
	cfg.AutoSelect.Limits = cfg.Request.Limits
	return cfg, nil
}

func parseRequiredHash(name string, spec string) (common.Hash, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return common.Hash{}, fmt.Errorf("missing required --%s", name)
	}
	if !strings.HasPrefix(spec, "0x") || len(spec) != 2+common.HashLength*2 {
		return common.Hash{}, fmt.Errorf("--%s must be a 0x-prefixed 32-byte hash", name)
	}
	raw, err := hex.DecodeString(spec[2:])
	if err != nil || len(raw) != common.HashLength {
		return common.Hash{}, fmt.Errorf("--%s must be a 0x-prefixed 32-byte hash", name)
	}
	hash := common.BytesToHash(raw)
	if hash == (common.Hash{}) {
		return common.Hash{}, fmt.Errorf("invalid zero --%s", name)
	}
	return hash, nil
}

func redactLocalPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	base := filepath.Base(path)
	if base == "." || base == string(filepath.Separator) {
		return "<redacted>"
	}
	return base
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

func parseLocation(spec string, wantCtx int) (common.Location, error) {
	if strings.TrimSpace(spec) == "" {
		return nil, errors.New("empty location")
	}
	parts := strings.Split(spec, ",")
	if len(parts) != wantCtx {
		return nil, fmt.Errorf("expected %d comma-separated components, got %d", wantCtx, len(parts))
	}
	loc := make(common.Location, 0, len(parts))
	for _, part := range parts {
		value, err := strconv.ParseUint(strings.TrimSpace(part), 10, 8)
		if err != nil {
			return nil, err
		}
		loc = append(loc, byte(value))
	}
	return loc, nil
}

func defaultAncientPath(dbPath string) string {
	candidate := filepath.Join(dbPath, "ancient")
	if info, err := os.Stat(candidate); err == nil && info.IsDir() {
		return candidate
	}
	return ""
}

type hierarchySelectionSource interface {
	Head(nodeCtx int) (common.Hash, uint64, bool)
	CanonicalHash(number uint64, nodeCtx int) common.Hash
	HeaderNumber(hash common.Hash, nodeCtx int) (uint64, bool)
	Header(hash common.Hash, nodeCtx int) (*types.WorkObject, error)
	Manifest(hash common.Hash, nodeCtx int) (types.BlockManifest, error)
}

type primeCarrier struct {
	Hash   common.Hash
	Number uint64
}

func selectHierarchyProofRequest(ctx context.Context, source hierarchySelectionSource, cfg autoSelectConfig) (nipopow.HierarchyProofRequest, autoSelectStats, error) {
	stats := autoSelectStats{RejectReasons: make(map[string]uint64)}
	if ctx == nil {
		ctx = context.Background()
	}
	if source == nil {
		return nipopow.HierarchyProofRequest{}, stats, ErrNoHierarchyCandidate
	}
	cfg = normalizeAutoSelectConfig(cfg)
	primeCarriers, err := indexPrimeManifestCarriers(ctx, source, cfg, &stats)
	if err != nil {
		return nipopow.HierarchyProofRequest{}, stats, err
	}
	_, regionHeadNumber, ok := source.Head(common.REGION_CTX)
	if !ok {
		return nipopow.HierarchyProofRequest{}, stats, fmt.Errorf("%w: missing region head", ErrNoHierarchyCandidate)
	}

	for number := regionHeadNumber; ; number-- {
		if err := ctx.Err(); err != nil {
			return nipopow.HierarchyProofRequest{}, stats, err
		}
		if stats.RegionBlocksScanned >= cfg.RegionWindow {
			break
		}
		regionHash := source.CanonicalHash(number, common.REGION_CTX)
		if regionHash != (common.Hash{}) {
			stats.RegionBlocksScanned++
			request, found, err := selectFromRegionCandidate(ctx, source, primeCarriers, regionHash, cfg, &stats)
			if err != nil {
				return nipopow.HierarchyProofRequest{}, stats, err
			}
			if found {
				return request, stats, nil
			}
		}
		if number == 0 {
			break
		}
	}
	if len(stats.RejectReasons) == 0 {
		stats.RejectReasons = nil
	}
	return nipopow.HierarchyProofRequest{}, stats, ErrNoHierarchyCandidate
}

func selectFromRegionCandidate(ctx context.Context, source hierarchySelectionSource, primeCarriers map[common.Hash][]primeCarrier, regionHash common.Hash, cfg autoSelectConfig, stats *autoSelectStats) (nipopow.HierarchyProofRequest, bool, error) {
	regionHeader, err := source.Header(regionHash, common.REGION_CTX)
	if err != nil || regionHeader == nil {
		rejectCandidate(stats, "region-header")
		return nipopow.HierarchyProofRequest{}, false, nil
	}
	regionTerminus := regionHeader.PrimeTerminusHash()
	regionTerminusNumber, ok := source.HeaderNumber(regionTerminus, common.PRIME_CTX)
	if !ok || regionTerminus == (common.Hash{}) {
		rejectCandidate(stats, "region-prime-terminus")
		return nipopow.HierarchyProofRequest{}, false, nil
	}
	if source.CanonicalHash(regionTerminusNumber, common.PRIME_CTX) != regionTerminus {
		rejectCandidate(stats, "region-prime-terminus-noncanonical")
		return nipopow.HierarchyProofRequest{}, false, nil
	}
	manifest, err := source.Manifest(regionHash, common.REGION_CTX)
	if err != nil || manifest == nil {
		rejectCandidate(stats, "region-manifest")
		return nipopow.HierarchyProofRequest{}, false, nil
	}
	for _, zoneHash := range manifest {
		if err := ctx.Err(); err != nil {
			return nipopow.HierarchyProofRequest{}, false, err
		}
		stats.RegionManifestEntries++
		zoneHeader, err := source.Header(zoneHash, common.ZONE_CTX)
		if err != nil || zoneHeader == nil {
			continue
		}
		if zoneHeader.Location().Context() != common.ZONE_CTX || zoneHeader.Location().Region() != regionHeader.Location().Region() {
			rejectCandidate(stats, "location-mismatch")
			continue
		}
		zoneTerminus := zoneHeader.PrimeTerminusHash()
		zoneTerminusNumber, ok := source.HeaderNumber(zoneTerminus, common.PRIME_CTX)
		if !ok || zoneTerminus == (common.Hash{}) {
			rejectCandidate(stats, "zone-prime-terminus")
			continue
		}
		if source.CanonicalHash(zoneTerminusNumber, common.PRIME_CTX) != zoneTerminus {
			rejectCandidate(stats, "zone-prime-terminus-noncanonical")
			continue
		}
		anchorHash := regionTerminus
		anchorNumber := regionTerminusNumber
		if zoneTerminusNumber < anchorNumber {
			anchorHash = zoneTerminus
			anchorNumber = zoneTerminusNumber
		}
		request, found := selectPrimeCarrier(primeCarriers, regionHash, zoneHash, anchorHash, anchorNumber, cfg, stats)
		if found {
			return request, true, nil
		}
	}
	return nipopow.HierarchyProofRequest{}, false, nil
}

func indexPrimeManifestCarriers(ctx context.Context, source hierarchySelectionSource, cfg autoSelectConfig, stats *autoSelectStats) (map[common.Hash][]primeCarrier, error) {
	_, primeHeadNumber, ok := source.Head(common.PRIME_CTX)
	if !ok {
		return nil, fmt.Errorf("%w: missing prime head", ErrNoHierarchyCandidate)
	}
	carriers := make(map[common.Hash][]primeCarrier)
	localScanned := uint64(0)
	for number := primeHeadNumber; ; number-- {
		if err := ctx.Err(); err != nil {
			return carriers, err
		}
		if localScanned >= cfg.PrimeWindow {
			break
		}
		primeHash := source.CanonicalHash(number, common.PRIME_CTX)
		if primeHash != (common.Hash{}) {
			localScanned++
			stats.PrimeBlocksScanned++
			manifest, err := source.Manifest(primeHash, common.PRIME_CTX)
			if err == nil && manifest != nil {
				for _, regionHash := range manifest {
					stats.PrimeManifestEntries++
					carriers[regionHash] = append(carriers[regionHash], primeCarrier{Hash: primeHash, Number: number})
				}
			}
		}
		if number == 0 {
			break
		}
	}
	return carriers, nil
}

func selectPrimeCarrier(primeCarriers map[common.Hash][]primeCarrier, regionHash common.Hash, zoneHash common.Hash, anchorHash common.Hash, anchorNumber uint64, cfg autoSelectConfig, stats *autoSelectStats) (nipopow.HierarchyProofRequest, bool) {
	for _, carrier := range primeCarriers[regionHash] {
		stats.CandidatesConsidered++
		if carrier.Number < anchorNumber {
			rejectCandidate(stats, "prime-before-anchor")
			continue
		}
		chainLength := carrier.Number - anchorNumber + 1
		if !chainLengthWithinLimits(chainLength, cfg.Limits) {
			rejectCandidate(stats, "proof-limits")
			continue
		}
		stats.SelectedChainLength = chainLength
		if len(stats.RejectReasons) == 0 {
			stats.RejectReasons = nil
		}
		return nipopow.HierarchyProofRequest{
			ZoneHash:    zoneHash,
			RegionHash:  regionHash,
			PrimeAnchor: anchorHash,
			PrimeTip:    carrier.Hash,
			M:           chainLength,
			Limits:      cfg.Limits,
		}, true
	}
	return nipopow.HierarchyProofRequest{}, false
}

func normalizeAutoSelectConfig(cfg autoSelectConfig) autoSelectConfig {
	cfg.Limits = normalizeBuildLimits(cfg.Limits)
	if cfg.RegionWindow == 0 {
		cfg.RegionWindow = cfg.Limits.MaxChainLength
	}
	if cfg.PrimeWindow == 0 {
		cfg.PrimeWindow = cfg.Limits.MaxChainLength
	}
	return cfg
}

func normalizeBuildLimits(limits nipopow.BuildLimits) nipopow.BuildLimits {
	if limits.MaxChainLength == 0 {
		limits.MaxChainLength = nipopow.DefaultMaxProofChainLength
	}
	if limits.MaxProofHeaders == 0 {
		limits.MaxProofHeaders = nipopow.DefaultMaxProofHeaders
	}
	if limits.MaxM == 0 {
		limits.MaxM = nipopow.DefaultMaxProofM
	}
	return limits
}

func chainLengthWithinLimits(chainLength uint64, limits nipopow.BuildLimits) bool {
	limits = normalizeBuildLimits(limits)
	return chainLength > 0 && chainLength <= limits.MaxChainLength && chainLength <= limits.MaxProofHeaders && chainLength <= limits.MaxM
}

func rejectCandidate(stats *autoSelectStats, reason string) {
	stats.CandidatesRejected++
	if stats.RejectReasons == nil {
		stats.RejectReasons = make(map[string]uint64)
	}
	stats.RejectReasons[reason]++
}

func writeFinalReport(stdout io.Writer, outPath string, report *hierarchyOutput) error {
	if report.FinishedAtUTC == "" {
		report.FinishedAtUTC = time.Now().UTC().Format(time.RFC3339Nano)
	}
	return writeReport(stdout, outPath, *report)
}

func writeReport(stdout io.Writer, outPath string, report hierarchyOutput) error {
	payload, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	payload = append(payload, '\n')
	if outPath == "" {
		_, err = stdout.Write(payload)
		return err
	}
	return os.WriteFile(outPath, payload, 0o644)
}

func openRawHierarchySource(cfg cliConfig) (*rawHierarchySource, func(), error) {
	opened := make([]ethdb.Database, 0, 3)
	closeFn := func() {
		for i := len(opened) - 1; i >= 0; i-- {
			opened[i].Close()
		}
	}
	openOne := func(path string, ancient string, nodeCtx int, location common.Location, namespace string) (ethdb.Database, error) {
		db, err := rawdb.Open(rawdb.OpenOptions{
			Type:              cfg.DBEngine,
			Directory:         path,
			AncientsDirectory: ancient,
			Namespace:         namespace,
			Cache:             64,
			Handles:           64,
			ReadOnly:          true,
		}, nodeCtx, log.Global, location)
		if err != nil {
			return nil, err
		}
		opened = append(opened, db)
		return db, nil
	}
	prime, err := openOne(cfg.PrimeDBPath, cfg.PrimeAncientPath, common.PRIME_CTX, common.Location{}, "nipopow/hierarchy-prime/")
	if err != nil {
		closeFn()
		return nil, nil, fmt.Errorf("prime: %w", err)
	}
	region, err := openOne(cfg.RegionDBPath, cfg.RegionAncientPath, common.REGION_CTX, cfg.RegionLocation, "nipopow/hierarchy-region/")
	if err != nil {
		closeFn()
		return nil, nil, fmt.Errorf("region: %w", err)
	}
	zone, err := openOne(cfg.ZoneDBPath, cfg.ZoneAncientPath, common.ZONE_CTX, cfg.ZoneLocation, "nipopow/hierarchy-zone/")
	if err != nil {
		closeFn()
		return nil, nil, fmt.Errorf("zone: %w", err)
	}
	return newRawHierarchySource(prime, region, zone), closeFn, nil
}

func newRawHierarchySource(prime ethdb.Database, region ethdb.Database, zone ethdb.Database) *rawHierarchySource {
	genesis := make(map[common.Hash]struct{})
	for _, hash := range rawdb.ReadGenesisHashes(prime) {
		if hash != (common.Hash{}) {
			genesis[hash] = struct{}{}
		}
	}
	if hash := rawdb.ReadCanonicalHash(prime, 0); hash != (common.Hash{}) {
		genesis[hash] = struct{}{}
	}
	return &rawHierarchySource{prime: prime, region: region, zone: zone, genesis: genesis}
}

func (s *rawHierarchySource) Header(hash common.Hash, nodeCtx int) (*types.WorkObject, error) {
	db, err := s.dbForContext(nodeCtx)
	if err != nil {
		return nil, err
	}
	number := rawdb.ReadHeaderNumber(db, hash)
	if number == nil {
		return nil, fmt.Errorf("header number not found ctx=%d hash=%s", nodeCtx, hash.Hex())
	}
	header := rawdb.ReadHeader(db, *number, hash)
	if header == nil {
		return nil, fmt.Errorf("header not found ctx=%d number=%d hash=%s", nodeCtx, *number, hash.Hex())
	}
	return types.CopyWorkObject(header), nil
}

func (s *rawHierarchySource) Manifest(hash common.Hash, nodeCtx int) (types.BlockManifest, error) {
	db, err := s.dbForContext(nodeCtx)
	if err != nil {
		return nil, err
	}
	var manifest types.BlockManifest
	number := rawdb.ReadHeaderNumber(db, hash)
	if number != nil {
		if block := rawdb.ReadWorkObject(db, *number, hash, types.BlockObject); block != nil && block.Manifest() != nil {
			manifest = block.Manifest()
		}
	}
	if manifest == nil {
		manifest = rawdb.ReadManifest(db, hash)
	}
	if manifest == nil {
		return nil, fmt.Errorf("manifest not found ctx=%d hash=%s", nodeCtx, hash.Hex())
	}
	return append(types.BlockManifest(nil), manifest...), nil
}

func (s *rawHierarchySource) Head(nodeCtx int) (common.Hash, uint64, bool) {
	db, err := s.dbForContext(nodeCtx)
	if err != nil {
		return common.Hash{}, 0, false
	}
	hash := rawdb.ReadHeadBlockHash(db)
	if hash == (common.Hash{}) {
		hash = rawdb.ReadHeadHeaderHash(db)
	}
	if hash == (common.Hash{}) {
		return common.Hash{}, 0, false
	}
	number := rawdb.ReadHeaderNumber(db, hash)
	if number == nil {
		return common.Hash{}, 0, false
	}
	return hash, *number, true
}

func (s *rawHierarchySource) CanonicalHash(number uint64, nodeCtx int) common.Hash {
	db, err := s.dbForContext(nodeCtx)
	if err != nil {
		return common.Hash{}
	}
	return rawdb.ReadCanonicalHash(db, number)
}

func (s *rawHierarchySource) HeaderNumber(hash common.Hash, nodeCtx int) (uint64, bool) {
	db, err := s.dbForContext(nodeCtx)
	if err != nil {
		return 0, false
	}
	number := rawdb.ReadHeaderNumber(db, hash)
	if number == nil {
		return 0, false
	}
	return *number, true
}

func (s *rawHierarchySource) ProofHeader(hash common.Hash) (*types.WorkObject, error) {
	number := rawdb.ReadHeaderNumber(s.prime, hash)
	if number == nil {
		return nil, fmt.Errorf("prime header number not found for %s", hash.Hex())
	}
	header := rawdb.ReadHeader(s.prime, *number, hash)
	if header == nil {
		return nil, fmt.Errorf("prime header not found number=%d hash=%s", *number, hash.Hex())
	}
	if header.Hash() != hash {
		return nil, fmt.Errorf("prime header hash mismatch number=%d expected=%s got=%s", *number, hash.Hex(), header.Hash().Hex())
	}
	proofHeader := types.CopyWorkObject(header)
	interlinkSource := proofHeader.ParentHash(common.PRIME_CTX)
	if s.isGenesis(hash) {
		interlinkSource = hash
	}
	interlinks := rawdb.ReadInterlinkHashes(s.prime, interlinkSource)
	if interlinks == nil {
		if !s.isGenesis(hash) {
			return nil, fmt.Errorf("interlink hashes not found source=%s header=%s number=%d", interlinkSource.Hex(), hash.Hex(), *number)
		}
		interlinks = common.Hashes{}
	}
	proofHeader.Body().SetInterlinkHashes(interlinks)
	expected := types.DeriveSha(interlinks, trie.NewStackTrie(nil))
	if proofHeader.InterlinkRootHash() != expected {
		return nil, fmt.Errorf("interlink root mismatch header=%s number=%d source=%s expected=%s got=%s interlinks=%d", hash.Hex(), *number, interlinkSource.Hex(), expected.Hex(), proofHeader.InterlinkRootHash().Hex(), len(interlinks))
	}
	return proofHeader, nil
}

func (s *rawHierarchySource) dbForContext(nodeCtx int) (ethdb.Database, error) {
	switch nodeCtx {
	case common.PRIME_CTX:
		return s.prime, nil
	case common.REGION_CTX:
		return s.region, nil
	case common.ZONE_CTX:
		return s.zone, nil
	default:
		return nil, fmt.Errorf("unsupported context %d", nodeCtx)
	}
}

func (s *rawHierarchySource) isGenesis(hash common.Hash) bool {
	_, ok := s.genesis[hash]
	return ok
}

func (s *rawHierarchySource) genesisHashes() []common.Hash {
	hashes := make([]common.Hash, 0, len(s.genesis))
	for hash := range s.genesis {
		hashes = append(hashes, hash)
	}
	sort.Slice(hashes, func(i, j int) bool { return hashes[i].Hex() < hashes[j].Hex() })
	return hashes
}
