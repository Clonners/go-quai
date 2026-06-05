package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/core/nipopow"
	"github.com/dominant-strategies/go-quai/core/types"
	"github.com/dominant-strategies/go-quai/internal/quaiapi"
)

var errMissingNiPoPoWProof = errors.New("missing nipopowProof")

type cliConfig struct {
	InputPath                  string
	OutPath                    string
	ExpectedTemplateHash       common.Hash
	ExpectedTemplateSealHash   common.Hash
	ExpectedTemplateParentHash common.Hash
}

type verifyOutput struct {
	StartedAtUTC       string                                       `json:"startedAtUtc"`
	FinishedAtUTC      string                                       `json:"finishedAtUtc"`
	InputPath          string                                       `json:"inputPath,omitempty"`
	Source             string                                       `json:"source,omitempty"`
	TemplateHash       common.Hash                                  `json:"templateHash,omitempty"`
	TemplateSealHash   common.Hash                                  `json:"templateSealHash,omitempty"`
	TemplateParentHash common.Hash                                  `json:"templateParentHash,omitempty"`
	ZoneHash           common.Hash                                  `json:"zoneHash,omitempty"`
	RegionHash         common.Hash                                  `json:"regionHash,omitempty"`
	PrimeAnchor        common.Hash                                  `json:"primeAnchor,omitempty"`
	PrimeTip           common.Hash                                  `json:"primeTip,omitempty"`
	M                  uint64                                       `json:"m,omitempty"`
	ZoneNumber         uint64                                       `json:"zoneNumber,omitempty"`
	RegionNumber       uint64                                       `json:"regionNumber,omitempty"`
	PrimeTipNumber     uint64                                       `json:"primeTipNumber,omitempty"`
	PrimeProofHeaders  int                                          `json:"primeProofHeaders,omitempty"`
	RegionManifestLen  int                                          `json:"regionManifestLen,omitempty"`
	PrimeManifestLen   int                                          `json:"primeManifestLen,omitempty"`
	BudgetPolicy       budgetPolicyOutput                           `json:"budgetPolicy"`
	BudgetStats        quaiapi.BlockTemplateNiPoPoWProofBudgetStats `json:"budgetStats,omitempty"`
	BudgetOK           bool                                         `json:"budgetOk"`
	VerifiedClientSide bool                                         `json:"verifiedClientSide"`
	RequiresDB         bool                                         `json:"requiresDb"`
	RequiresRPC        bool                                         `json:"requiresRpc"`
	OK                 bool                                         `json:"ok"`
	Error              string                                       `json:"error,omitempty"`
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

func main() {
	os.Exit(runCLI(os.Args[1:], os.Stdout, os.Stderr))
}

func runCLI(args []string, stdout io.Writer, stderr io.Writer) int {
	cfg, err := parseCLI(args, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}
	out := verifyOutput{
		StartedAtUTC:       time.Now().UTC().Format(time.RFC3339Nano),
		InputPath:          cfg.InputPath,
		BudgetPolicy:       defaultBudgetPolicyOutput(),
		VerifiedClientSide: true,
		RequiresDB:         false,
		RequiresRPC:        false,
	}
	defer func() {
		out.FinishedAtUTC = time.Now().UTC().Format(time.RFC3339Nano)
	}()

	data, err := os.ReadFile(cfg.InputPath)
	if err != nil {
		out.Error = fmt.Sprintf("read input: %v", err)
		_ = writeVerifyReport(stdout, cfg.OutPath, &out)
		return 1
	}
	artifact, opts, source, err := extractTemplateProof(data)
	if err != nil {
		out.Error = err.Error()
		_ = writeVerifyReport(stdout, cfg.OutPath, &out)
		return 1
	}
	out.Source = source
	mergeExpectedOptions(&opts, cfg)
	if err := nipopow.VerifyTemplateHierarchyProofArtifact(artifact, opts); err != nil {
		populateVerifyOutput(&out, artifact)
		out.Error = err.Error()
		_ = writeVerifyReport(stdout, cfg.OutPath, &out)
		return 1
	}
	populateVerifyOutput(&out, artifact)
	budgetStats, err := quaiapi.ValidateBlockTemplateNiPoPoWProofBudget(artifact, quaiapi.BlockTemplateNiPoPoWRequestPolicy{})
	out.BudgetStats = budgetStats
	if err != nil {
		out.Error = err.Error()
		_ = writeVerifyReport(stdout, cfg.OutPath, &out)
		return 1
	}
	out.BudgetOK = true
	out.OK = true
	if err := writeVerifyReport(stdout, cfg.OutPath, &out); err != nil {
		fmt.Fprintf(stderr, "error writing report: %v\n", err)
		return 1
	}
	return 0
}

func parseCLI(args []string, stderr io.Writer) (cliConfig, error) {
	var cfg cliConfig
	var templateHash string
	var templateSealHash string
	var templateParentHash string
	fs := flag.NewFlagSet("nipopow-template-verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&cfg.InputPath, "in", "", "JSON input: opt-in block template response, hierarchy validator report, or nipopowProof artifact")
	fs.StringVar(&cfg.OutPath, "out", "", "Optional JSON verification report output path; stdout is used when empty")
	fs.StringVar(&templateHash, "template-hash", "", "Optional expected template hash to bind against nipopowProof.templateHash")
	fs.StringVar(&templateSealHash, "template-seal-hash", "", "Optional expected template seal hash to bind against nipopowProof.templateSealHash")
	fs.StringVar(&templateParentHash, "template-parent-hash", "", "Optional expected template parent hash to bind against nipopowProof.templateParentHash")
	if err := fs.Parse(args); err != nil {
		return cfg, err
	}
	if strings.TrimSpace(cfg.InputPath) == "" {
		return cfg, errors.New("missing required --in")
	}
	var err error
	if cfg.ExpectedTemplateHash, err = parseOptionalHash(templateHash, "template-hash"); err != nil {
		return cfg, err
	}
	if cfg.ExpectedTemplateSealHash, err = parseOptionalHash(templateSealHash, "template-seal-hash"); err != nil {
		return cfg, err
	}
	if cfg.ExpectedTemplateParentHash, err = parseOptionalHash(templateParentHash, "template-parent-hash"); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func extractTemplateProof(data []byte) (*nipopow.TemplateHierarchyProof, nipopow.TemplateHierarchyProofVerificationOptions, string, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return nil, nipopow.TemplateHierarchyProofVerificationOptions{}, "", err
	}
	if rawTemplate, ok := fields["blockTemplateResponse"]; ok {
		proof, err := extractProofFromBlockTemplate(rawTemplate)
		if err != nil {
			return nil, nipopow.TemplateHierarchyProofVerificationOptions{}, "blockTemplateResponse", err
		}
		return proof, expectedOptionsFromFields(fields), "blockTemplateResponse.nipopowProof", nil
	}
	if rawProof, ok := fields["nipopowProof"]; ok {
		proof, err := decodeTemplateProof(rawProof)
		if err != nil {
			return nil, nipopow.TemplateHierarchyProofVerificationOptions{}, "nipopowProof", err
		}
		return proof, nipopow.TemplateHierarchyProofVerificationOptions{}, "nipopowProof", nil
	}
	if _, ok := fields["proof"]; ok {
		proof, err := decodeTemplateProof(data)
		if err != nil {
			return nil, nipopow.TemplateHierarchyProofVerificationOptions{}, "proof", err
		}
		return proof, nipopow.TemplateHierarchyProofVerificationOptions{}, "proof", nil
	}
	return nil, nipopow.TemplateHierarchyProofVerificationOptions{}, "", errMissingNiPoPoWProof
}

func extractProofFromBlockTemplate(rawTemplate json.RawMessage) (*nipopow.TemplateHierarchyProof, error) {
	var template map[string]json.RawMessage
	if err := json.Unmarshal(rawTemplate, &template); err != nil {
		return nil, err
	}
	rawProof, ok := template["nipopowProof"]
	if !ok || len(rawProof) == 0 || string(rawProof) == "null" {
		return nil, errMissingNiPoPoWProof
	}
	return decodeTemplateProof(rawProof)
}

func decodeTemplateProof(raw json.RawMessage) (*nipopow.TemplateHierarchyProof, error) {
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

func normalizeProofJSON(raw json.RawMessage) ([]byte, error) {
	var value interface{}
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, err
	}
	pruneEmptyOptionalWorkObjectFields(value)
	return json.Marshal(value)
}

func pruneEmptyOptionalWorkObjectFields(value interface{}) {
	switch typed := value.(type) {
	case map[string]interface{}:
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
	case []interface{}:
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

func isEmptyObject(value interface{}) bool {
	object, ok := value.(map[string]interface{})
	return ok && len(object) == 0
}

func zeroManifestHashArray() []string {
	out := make([]string, common.HierarchyDepth)
	for i := range out {
		out[i] = types.EmptyRootHash.Hex()
	}
	return out
}

func expectedOptionsFromFields(fields map[string]json.RawMessage) nipopow.TemplateHierarchyProofVerificationOptions {
	return nipopow.TemplateHierarchyProofVerificationOptions{
		ExpectedTemplateHash:       hashField(fields, "templateHash"),
		ExpectedTemplateSealHash:   hashField(fields, "templateSealHash"),
		ExpectedTemplateParentHash: hashField(fields, "templateParentHash"),
	}
}

func hashField(fields map[string]json.RawMessage, name string) common.Hash {
	raw, ok := fields[name]
	if !ok || len(raw) == 0 || string(raw) == "null" {
		return common.Hash{}
	}
	var hash common.Hash
	if err := json.Unmarshal(raw, &hash); err != nil {
		return common.Hash{}
	}
	return hash
}

func mergeExpectedOptions(opts *nipopow.TemplateHierarchyProofVerificationOptions, cfg cliConfig) {
	if opts.ExpectedTemplateHash == (common.Hash{}) {
		opts.ExpectedTemplateHash = cfg.ExpectedTemplateHash
	}
	if opts.ExpectedTemplateSealHash == (common.Hash{}) {
		opts.ExpectedTemplateSealHash = cfg.ExpectedTemplateSealHash
	}
	if opts.ExpectedTemplateParentHash == (common.Hash{}) {
		opts.ExpectedTemplateParentHash = cfg.ExpectedTemplateParentHash
	}
}

func parseOptionalHash(raw string, label string) (common.Hash, error) {
	if strings.TrimSpace(raw) == "" {
		return common.Hash{}, nil
	}
	hash := common.HexToHash(raw)
	if hash == (common.Hash{}) {
		return common.Hash{}, fmt.Errorf("%s cannot be zero", label)
	}
	return hash, nil
}

func populateVerifyOutput(out *verifyOutput, artifact *nipopow.TemplateHierarchyProof) {
	if out == nil || artifact == nil {
		return
	}
	out.TemplateHash = artifact.TemplateHash
	out.TemplateSealHash = artifact.TemplateSealHash
	out.TemplateParentHash = artifact.TemplateParentHash
	out.ZoneHash = artifact.Request.ZoneHash
	out.RegionHash = artifact.Request.RegionHash
	out.PrimeAnchor = artifact.Request.PrimeAnchor
	out.PrimeTip = artifact.Request.PrimeTip
	out.M = artifact.Request.M
	if artifact.Proof == nil {
		return
	}
	if artifact.Proof.ZoneHeader != nil {
		out.ZoneNumber = artifact.Proof.ZoneHeader.NumberU64(common.ZONE_CTX)
	}
	if artifact.Proof.RegionHeader != nil {
		out.RegionNumber = artifact.Proof.RegionHeader.NumberU64(common.REGION_CTX)
		out.RegionManifestLen = len(artifact.Proof.RegionHeader.Manifest())
	}
	if artifact.Proof.PrimeHeader != nil {
		out.PrimeTipNumber = artifact.Proof.PrimeHeader.NumberU64(common.PRIME_CTX)
		out.PrimeManifestLen = len(artifact.Proof.PrimeHeader.Manifest())
	}
	if artifact.Proof.PrimeProof != nil {
		out.PrimeProofHeaders = len(artifact.Proof.PrimeProof.Headers)
	}
}

func writeVerifyReport(stdout io.Writer, outPath string, out *verifyOutput) error {
	if out != nil && out.FinishedAtUTC == "" {
		out.FinishedAtUTC = time.Now().UTC().Format(time.RFC3339Nano)
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if outPath != "" {
		return os.WriteFile(outPath, data, 0o644)
	}
	_, err = stdout.Write(data)
	return err
}
