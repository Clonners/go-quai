package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"testing"

	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/core/nipopow"
	"github.com/dominant-strategies/go-quai/core/rawdb"
	"github.com/dominant-strategies/go-quai/core/types"
	"github.com/dominant-strategies/go-quai/log"
	"github.com/dominant-strategies/go-quai/trie"
)

func TestWriteFinalReportSetsFinishedAt(t *testing.T) {
	var buf bytes.Buffer
	if err := writeFinalReport(&buf, "", &hierarchyOutput{StartedAtUTC: "2026-01-01T00:00:00Z"}); err != nil {
		t.Fatalf("write final report: %v", err)
	}
	var decoded hierarchyOutput
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("decode report: %v", err)
	}
	if decoded.FinishedAtUTC == "" {
		t.Fatalf("expected finishedAtUtc to be set in written report: %s", buf.String())
	}
}

func TestParseCLIRequiresReadOnlyDBsAndHashes(t *testing.T) {
	_, err := parseCLI(nil, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected missing flags to return an error")
	}
}

func TestParseCLIAcceptsExplicitHierarchyInputs(t *testing.T) {
	cfg, err := parseCLI([]string{
		"--prime.db", "/tmp/prime",
		"--region.db", "/tmp/region",
		"--zone.db", "/tmp/zone",
		"--zone-hash", common.HexToHash("0x01").Hex(),
		"--region-hash", common.HexToHash("0x02").Hex(),
		"--prime-anchor", common.HexToHash("0x03").Hex(),
		"--prime-tip", common.HexToHash("0x04").Hex(),
		"--m", "16",
	}, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("expected parse success: %v", err)
	}
	if cfg.PrimeDBPath != "/tmp/prime" || cfg.RegionDBPath != "/tmp/region" || cfg.ZoneDBPath != "/tmp/zone" {
		t.Fatalf("db paths not parsed: %+v", cfg)
	}
	if cfg.Request.ZoneHash != common.HexToHash("0x01") || cfg.Request.RegionHash != common.HexToHash("0x02") {
		t.Fatalf("hierarchy hashes not parsed: %+v", cfg.Request)
	}
	if cfg.Request.M != 16 {
		t.Fatalf("m not parsed: %+v", cfg.Request.M)
	}
}

func TestParseCLIRejectsShortHashInputs(t *testing.T) {
	_, err := parseCLI([]string{
		"--prime.db", "/tmp/prime",
		"--region.db", "/tmp/region",
		"--zone.db", "/tmp/zone",
		"--zone-hash", "0x01",
		"--region-hash", common.HexToHash("0x02").Hex(),
		"--prime-anchor", common.HexToHash("0x03").Hex(),
		"--prime-tip", common.HexToHash("0x04").Hex(),
	}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected short hash to be rejected")
	}
}

func TestRedactLocalPathKeepsReportsLocalPathSafe(t *testing.T) {
	if got := redactLocalPath("/home/user/private/chaindata"); got != "chaindata" {
		t.Fatalf("unexpected redacted path: %s", got)
	}
	if got := redactLocalPath(""); got != "" {
		t.Fatalf("empty path should stay empty, got %q", got)
	}
}

func TestParseLocation(t *testing.T) {
	region, err := parseLocation("0", common.REGION_CTX)
	if err != nil {
		t.Fatalf("region parse: %v", err)
	}
	if region.Context() != common.REGION_CTX || region.Region() != 0 {
		t.Fatalf("bad region location: %v", region)
	}
	zone, err := parseLocation("0,0", common.ZONE_CTX)
	if err != nil {
		t.Fatalf("zone parse: %v", err)
	}
	if zone.Context() != common.ZONE_CTX || zone.Region() != 0 || zone.Zone() != 0 {
		t.Fatalf("bad zone location: %v", zone)
	}
}

func TestParseCLIAcceptsAutoSelectWithoutHashes(t *testing.T) {
	cfg, err := parseCLI([]string{
		"--prime.db", "/tmp/prime",
		"--region.db", "/tmp/region",
		"--zone.db", "/tmp/zone",
		"--auto-select",
	}, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("expected auto-select parse success without explicit hashes: %v", err)
	}
	if !cfg.AutoSelect.Enabled {
		t.Fatalf("auto-select flag not parsed: %+v", cfg.AutoSelect)
	}
}

func TestParseCLIAcceptsTemplateShadowRPCWithoutExplicitHashes(t *testing.T) {
	cfg, err := parseCLI([]string{
		"--prime.db", "/tmp/prime",
		"--region.db", "/tmp/region",
		"--zone.db", "/tmp/zone",
		"--template-shadow-rpc", "https://zone.example.invalid",
		"--block-template-optin",
		"--m", "3",
	}, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("expected template shadow parse success without explicit hashes: %v", err)
	}
	if cfg.TemplateShadowRPC != "https://zone.example.invalid" {
		t.Fatalf("template shadow rpc flag not parsed: %+v", cfg)
	}
	if !cfg.BlockTemplateOptIn {
		t.Fatalf("block template opt-in flag not parsed: %+v", cfg)
	}
	if cfg.Request.M != 3 {
		t.Fatalf("m not preserved for template shadow mode: %+v", cfg.Request)
	}
}

func TestBuildBlockTemplateOptInResponseAttachesProof(t *testing.T) {
	source := newAutoSelectTestSource(t)
	primeAnchor := cliTestPrimeBlock(t, 1, nil, nil)
	primeTip := cliTestPrimeBlock(t, 2, primeAnchor, nil)
	zone := cliTestHierarchyHeader(t, common.ZONE_CTX, common.Location{0, 0}, 100, primeAnchor.Hash(), nil)
	region := cliTestHierarchyHeader(t, common.REGION_CTX, common.Location{0}, 50, primeAnchor.Hash(), types.BlockManifest{zone.Hash()})
	primeTip.Body().SetManifest(types.BlockManifest{region.Hash()})
	setCLITestManifestCommitment(t, primeTip, common.PRIME_CTX)

	source.add(common.PRIME_CTX, 1, primeAnchor, nil)
	source.add(common.PRIME_CTX, 2, primeTip, primeTip.Manifest())
	source.add(common.REGION_CTX, 50, region, region.Manifest())
	source.add(common.ZONE_CTX, 100, zone, nil)

	pending := cliTestHierarchyHeader(t, common.ZONE_CTX, common.Location{0, 0}, 101, primeAnchor.Hash(), nil)
	pending.SetParentHash(zone.Hash(), common.ZONE_CTX)
	pending.SetParentHash(region.Hash(), common.REGION_CTX)
	pending.SetParentHash(primeTip.Hash(), common.PRIME_CTX)
	pending.WorkObjectHeader().SetAuxPow(cliTestAuxPow(types.SHA_BCH))
	pending.WorkObjectHeader().SetHeaderHash(pending.Header().Hash())

	response, err := buildBlockTemplateOptInResponse(context.Background(), source, pending, nipopow.TemplateHierarchyProofOptions{M: 1}, nil)
	if err != nil {
		t.Fatalf("expected block template opt-in response: %v", err)
	}
	if _, ok := response["nipopowProof"]; !ok {
		t.Fatalf("expected nipopowProof in response: %+v", response)
	}
	if _, ok := response["coinb1"]; !ok {
		t.Fatalf("expected normal block template fields in response: %+v", response)
	}
}

func TestBuildBlockTemplateOptInResponseUsesFetchedTemplateWhenPendingHasNoAuxPow(t *testing.T) {
	source := newAutoSelectTestSource(t)
	primeAnchor := cliTestPrimeBlock(t, 1, nil, nil)
	primeTip := cliTestPrimeBlock(t, 2, primeAnchor, nil)
	zone := cliTestHierarchyHeader(t, common.ZONE_CTX, common.Location{0, 0}, 100, primeAnchor.Hash(), nil)
	region := cliTestHierarchyHeader(t, common.REGION_CTX, common.Location{0}, 50, primeAnchor.Hash(), types.BlockManifest{zone.Hash()})
	primeTip.Body().SetManifest(types.BlockManifest{region.Hash()})
	setCLITestManifestCommitment(t, primeTip, common.PRIME_CTX)

	source.add(common.PRIME_CTX, 1, primeAnchor, nil)
	source.add(common.PRIME_CTX, 2, primeTip, primeTip.Manifest())
	source.add(common.REGION_CTX, 50, region, region.Manifest())
	source.add(common.ZONE_CTX, 100, zone, nil)

	pending := cliTestHierarchyHeader(t, common.ZONE_CTX, common.Location{0, 0}, 101, primeAnchor.Hash(), nil)
	pending.SetParentHash(zone.Hash(), common.ZONE_CTX)
	pending.SetParentHash(region.Hash(), common.REGION_CTX)
	pending.SetParentHash(primeTip.Hash(), common.PRIME_CTX)
	pending.WorkObjectHeader().SetHeaderHash(pending.Header().Hash())

	baseTemplate := map[string]interface{}{"coinb1": "default-template", "quaiheight": float64(101)}
	response, err := buildBlockTemplateOptInResponse(context.Background(), source, pending, nipopow.TemplateHierarchyProofOptions{M: 1}, baseTemplate)
	if err != nil {
		t.Fatalf("expected fetched block template to be used when pending has no auxpow: %v", err)
	}
	if response["coinb1"] != "default-template" {
		t.Fatalf("expected fetched template fields preserved: %+v", response)
	}
	if _, ok := response["nipopowProof"]; !ok {
		t.Fatalf("expected nipopowProof in response: %+v", response)
	}
	if _, ok := baseTemplate["nipopowProof"]; ok {
		t.Fatalf("base default template should not be mutated with proof: %+v", baseTemplate)
	}
}

func TestCollectTemplateShadowProofDerivesReportFromPendingHeader(t *testing.T) {
	source := newAutoSelectTestSource(t)
	primeAnchor := cliTestPrimeBlock(t, 1, nil, nil)
	primeTip := cliTestPrimeBlock(t, 2, primeAnchor, nil)
	zone := cliTestHierarchyHeader(t, common.ZONE_CTX, common.Location{0, 0}, 100, primeAnchor.Hash(), nil)
	region := cliTestHierarchyHeader(t, common.REGION_CTX, common.Location{0}, 50, primeAnchor.Hash(), types.BlockManifest{zone.Hash()})
	primeTip.Body().SetManifest(types.BlockManifest{region.Hash()})
	setCLITestManifestCommitment(t, primeTip, common.PRIME_CTX)

	source.add(common.PRIME_CTX, 1, primeAnchor, nil)
	source.add(common.PRIME_CTX, 2, primeTip, primeTip.Manifest())
	source.add(common.REGION_CTX, 50, region, region.Manifest())
	source.add(common.ZONE_CTX, 100, zone, nil)

	pending := cliTestHierarchyHeader(t, common.ZONE_CTX, common.Location{0, 0}, 101, primeAnchor.Hash(), nil)
	pending.SetParentHash(zone.Hash(), common.ZONE_CTX)
	pending.SetParentHash(region.Hash(), common.REGION_CTX)
	pending.SetParentHash(primeTip.Hash(), common.PRIME_CTX)
	pending.WorkObjectHeader().SetHeaderHash(pending.Header().Hash())

	result, err := collectTemplateShadowProof(context.Background(), source, pending, nipopow.TemplateHierarchyProofOptions{M: 1})
	if err != nil {
		t.Fatalf("expected template shadow proof to build: %v", err)
	}
	if result.Request.ZoneHash != zone.Hash() || result.Request.RegionHash != region.Hash() || result.Request.PrimeTip != primeTip.Hash() {
		t.Fatalf("unexpected derived request: %+v", result.Request)
	}
	if result.TemplateParentHash != zone.Hash() {
		t.Fatalf("unexpected template parent: got %s want %s", result.TemplateParentHash, zone.Hash())
	}
}

func TestSelectHierarchyProofRequestDerivesRecentTuple(t *testing.T) {
	source := newAutoSelectTestSource(t)
	prime10 := cliTestHierarchyHeader(t, common.PRIME_CTX, common.Location{}, 10, common.Hash{}, nil)
	prime11 := cliTestHierarchyHeader(t, common.PRIME_CTX, common.Location{}, 11, common.Hash{}, nil)
	zone := cliTestHierarchyHeader(t, common.ZONE_CTX, common.Location{0, 0}, 100, prime10.Hash(), nil)
	region := cliTestHierarchyHeader(t, common.REGION_CTX, common.Location{0}, 50, prime10.Hash(), types.BlockManifest{zone.Hash()})
	prime11.Body().SetManifest(types.BlockManifest{region.Hash()})
	setCLITestManifestCommitment(t, prime11, common.PRIME_CTX)

	source.add(common.PRIME_CTX, 10, prime10, nil)
	source.add(common.PRIME_CTX, 11, prime11, prime11.Manifest())
	source.add(common.REGION_CTX, 50, region, region.Manifest())
	source.add(common.ZONE_CTX, 100, zone, nil)

	req, stats, err := selectHierarchyProofRequest(context.Background(), source, autoSelectConfig{
		RegionWindow: 8,
		PrimeWindow:  8,
		Limits: nipopow.BuildLimits{
			MaxChainLength:  8,
			MaxProofHeaders: 8,
			MaxM:            8,
		},
	})
	if err != nil {
		t.Fatalf("expected selection success: %v", err)
	}
	if req.ZoneHash != zone.Hash() || req.RegionHash != region.Hash() || req.PrimeAnchor != prime10.Hash() || req.PrimeTip != prime11.Hash() {
		t.Fatalf("unexpected request: %+v", req)
	}
	if req.M != 2 {
		t.Fatalf("expected full suffix m=2, got %d", req.M)
	}
	if stats.RegionBlocksScanned != 1 || stats.PrimeBlocksScanned != 2 || stats.CandidatesRejected != 0 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
}

func TestSelectHierarchyProofRequestIndexesPrimeManifestOnce(t *testing.T) {
	source := newAutoSelectTestSource(t)
	prime10 := cliTestHierarchyHeader(t, common.PRIME_CTX, common.Location{}, 10, common.Hash{}, nil)
	prime11 := cliTestHierarchyHeader(t, common.PRIME_CTX, common.Location{}, 11, common.Hash{}, nil)
	zoneOlder := cliTestHierarchyHeader(t, common.ZONE_CTX, common.Location{0, 0}, 100, prime10.Hash(), nil)
	regionOlder := cliTestHierarchyHeader(t, common.REGION_CTX, common.Location{0}, 50, prime10.Hash(), types.BlockManifest{zoneOlder.Hash()})
	zoneHead := cliTestHierarchyHeader(t, common.ZONE_CTX, common.Location{0, 0}, 101, prime10.Hash(), nil)
	regionHead := cliTestHierarchyHeader(t, common.REGION_CTX, common.Location{0}, 51, prime10.Hash(), types.BlockManifest{zoneHead.Hash()})
	prime11.Body().SetManifest(types.BlockManifest{regionOlder.Hash()})
	setCLITestManifestCommitment(t, prime11, common.PRIME_CTX)

	source.add(common.PRIME_CTX, 10, prime10, nil)
	source.add(common.PRIME_CTX, 11, prime11, prime11.Manifest())
	source.add(common.REGION_CTX, 51, regionHead, regionHead.Manifest())
	source.add(common.REGION_CTX, 50, regionOlder, regionOlder.Manifest())
	source.add(common.ZONE_CTX, 101, zoneHead, nil)
	source.add(common.ZONE_CTX, 100, zoneOlder, nil)

	req, stats, err := selectHierarchyProofRequest(context.Background(), source, autoSelectConfig{
		RegionWindow: 8,
		PrimeWindow:  8,
		Limits: nipopow.BuildLimits{
			MaxChainLength:  8,
			MaxProofHeaders: 8,
			MaxM:            8,
		},
	})
	if err != nil {
		t.Fatalf("expected selection success: %v", err)
	}
	if req.RegionHash != regionOlder.Hash() {
		t.Fatalf("expected older region selected, got %+v", req)
	}
	if stats.PrimeManifestEntries != 1 || stats.CandidatesConsidered != 1 {
		t.Fatalf("expected one indexed prime manifest candidate, got stats %+v", stats)
	}
}

func TestSelectHierarchyProofRequestSkipsRangesBeyondLimits(t *testing.T) {
	source := newAutoSelectTestSource(t)
	prime10 := cliTestHierarchyHeader(t, common.PRIME_CTX, common.Location{}, 10, common.Hash{}, nil)
	prime12 := cliTestHierarchyHeader(t, common.PRIME_CTX, common.Location{}, 12, common.Hash{}, nil)
	zone := cliTestHierarchyHeader(t, common.ZONE_CTX, common.Location{0, 0}, 100, prime10.Hash(), nil)
	region := cliTestHierarchyHeader(t, common.REGION_CTX, common.Location{0}, 50, prime10.Hash(), types.BlockManifest{zone.Hash()})
	prime12.Body().SetManifest(types.BlockManifest{region.Hash()})
	setCLITestManifestCommitment(t, prime12, common.PRIME_CTX)

	source.add(common.PRIME_CTX, 10, prime10, nil)
	source.add(common.PRIME_CTX, 12, prime12, prime12.Manifest())
	source.add(common.REGION_CTX, 50, region, region.Manifest())
	source.add(common.ZONE_CTX, 100, zone, nil)

	_, stats, err := selectHierarchyProofRequest(context.Background(), source, autoSelectConfig{
		RegionWindow: 8,
		PrimeWindow:  8,
		Limits: nipopow.BuildLimits{
			MaxChainLength:  2,
			MaxProofHeaders: 2,
			MaxM:            2,
		},
	})
	if !errors.Is(err, ErrNoHierarchyCandidate) {
		t.Fatalf("expected no candidate after range rejection, got %v", err)
	}
	if stats.CandidatesRejected == 0 {
		t.Fatalf("expected rejected candidate stats: %+v", stats)
	}
}

func TestRawHierarchySourceManifestPrefersCommittedWorkObjectBody(t *testing.T) {
	db := rawdb.NewMemoryDatabase(log.Global)
	bodyManifest := types.BlockManifest{common.HexToHash("0x1234")}
	standaloneManifest := types.BlockManifest{common.HexToHash("0xabcd")}
	block := cliTestHierarchyHeader(t, common.REGION_CTX, common.Location{0}, 7, common.Hash{}, bodyManifest)
	rawdb.WriteWorkObject(db, block.Hash(), block, types.BlockObject, common.REGION_CTX)
	rawdb.WriteManifest(db, block.Hash(), standaloneManifest)

	source := newRawHierarchySource(db, db, db)
	got, err := source.Manifest(block.Hash(), common.REGION_CTX)
	if err != nil {
		t.Fatalf("expected manifest from body: %v", err)
	}
	if len(got) != len(bodyManifest) || got[0] != bodyManifest[0] {
		t.Fatalf("expected body manifest over standalone record: got %v want %v", got, bodyManifest)
	}
}

func TestRawHierarchySourceManifestFallsBackToWorkObjectBody(t *testing.T) {
	db := rawdb.NewMemoryDatabase(log.Global)
	manifest := types.BlockManifest{common.HexToHash("0x1234")}
	block := cliTestHierarchyHeader(t, common.PRIME_CTX, common.Location{}, 7, common.Hash{}, manifest)
	rawdb.WriteWorkObject(db, block.Hash(), block, types.BlockObject, common.PRIME_CTX)
	if persisted := rawdb.ReadManifest(db, block.Hash()); persisted != nil {
		t.Fatalf("test fixture should not have a standalone manifest record: %v", persisted)
	}

	source := newRawHierarchySource(db, db, db)
	got, err := source.Manifest(block.Hash(), common.PRIME_CTX)
	if err != nil {
		t.Fatalf("expected body manifest fallback: %v", err)
	}
	if len(got) != len(manifest) || got[0] != manifest[0] {
		t.Fatalf("unexpected manifest fallback: got %v want %v", got, manifest)
	}
}

type autoSelectTestSource struct {
	headers   map[int]map[common.Hash]*types.WorkObject
	numbers   map[int]map[common.Hash]uint64
	canonical map[int]map[uint64]common.Hash
	manifests map[int]map[common.Hash]types.BlockManifest
}

func newAutoSelectTestSource(t *testing.T) *autoSelectTestSource {
	t.Helper()
	return &autoSelectTestSource{
		headers:   map[int]map[common.Hash]*types.WorkObject{common.PRIME_CTX: {}, common.REGION_CTX: {}, common.ZONE_CTX: {}},
		numbers:   map[int]map[common.Hash]uint64{common.PRIME_CTX: {}, common.REGION_CTX: {}, common.ZONE_CTX: {}},
		canonical: map[int]map[uint64]common.Hash{common.PRIME_CTX: {}, common.REGION_CTX: {}, common.ZONE_CTX: {}},
		manifests: map[int]map[common.Hash]types.BlockManifest{common.PRIME_CTX: {}, common.REGION_CTX: {}, common.ZONE_CTX: {}},
	}
}

func (s *autoSelectTestSource) add(nodeCtx int, number uint64, header *types.WorkObject, manifest types.BlockManifest) {
	hash := header.Hash()
	s.headers[nodeCtx][hash] = types.CopyWorkObject(header)
	s.numbers[nodeCtx][hash] = number
	s.canonical[nodeCtx][number] = hash
	if manifest != nil {
		s.manifests[nodeCtx][hash] = append(types.BlockManifest(nil), manifest...)
	}
}

func (s *autoSelectTestSource) Head(nodeCtx int) (common.Hash, uint64, bool) {
	var bestNumber uint64
	var bestHash common.Hash
	for number, hash := range s.canonical[nodeCtx] {
		if bestHash == (common.Hash{}) || number > bestNumber {
			bestNumber = number
			bestHash = hash
		}
	}
	return bestHash, bestNumber, bestHash != (common.Hash{})
}

func (s *autoSelectTestSource) CanonicalHash(number uint64, nodeCtx int) common.Hash {
	return s.canonical[nodeCtx][number]
}

func (s *autoSelectTestSource) HeaderNumber(hash common.Hash, nodeCtx int) (uint64, bool) {
	number, ok := s.numbers[nodeCtx][hash]
	return number, ok
}

func (s *autoSelectTestSource) Header(hash common.Hash, nodeCtx int) (*types.WorkObject, error) {
	header := s.headers[nodeCtx][hash]
	if header == nil {
		return nil, errors.New("missing header")
	}
	return types.CopyWorkObject(header), nil
}

func (s *autoSelectTestSource) Manifest(hash common.Hash, nodeCtx int) (types.BlockManifest, error) {
	manifest := s.manifests[nodeCtx][hash]
	if manifest == nil {
		return nil, errors.New("missing manifest")
	}
	return append(types.BlockManifest(nil), manifest...), nil
}

func (s *autoSelectTestSource) ProofHeader(hash common.Hash) (*types.WorkObject, error) {
	return s.Header(hash, common.PRIME_CTX)
}

func cliTestPrimeBlock(t *testing.T, number uint64, parent *types.WorkObject, interlinks common.Hashes) *types.WorkObject {
	t.Helper()
	wo := types.EmptyWorkObject(common.PRIME_CTX)
	wo.WorkObjectHeader().SetNumber(new(big.Int).SetUint64(number))
	wo.WorkObjectHeader().SetPrimeTerminusNumber(new(big.Int).SetUint64(number))
	wo.WorkObjectHeader().SetTime(number)
	wo.Header().SetNumber(new(big.Int).SetUint64(number), common.PRIME_CTX)
	wo.Header().SetParentDeltaEntropy(big.NewInt(1), common.PRIME_CTX)
	wo.Header().SetExpansionNumber(0)
	if parent != nil {
		wo.SetParentHash(parent.Hash(), common.PRIME_CTX)
	}
	wo.Body().SetInterlinkHashes(interlinks)
	wo.Header().SetInterlinkRootHash(types.DeriveSha(interlinks, trie.NewStackTrie(nil)))
	wo.WorkObjectHeader().SetHeaderHash(wo.Header().Hash())
	return wo
}

func cliTestHierarchyHeader(t *testing.T, nodeCtx int, location common.Location, number uint64, primeTerminus common.Hash, manifest types.BlockManifest) *types.WorkObject {
	t.Helper()
	wo := types.EmptyWorkObject(nodeCtx)
	wo.WorkObjectHeader().SetLocation(location)
	wo.WorkObjectHeader().SetNumber(new(big.Int).SetUint64(number))
	wo.WorkObjectHeader().SetPrimeTerminusNumber(new(big.Int).SetUint64(1))
	wo.WorkObjectHeader().SetTime(number)
	wo.WorkObjectHeader().SetDifficulty(big.NewInt(1))
	wo.WorkObjectHeader().SetShaDiffAndCount(types.NewPowShareDiffAndCount(big.NewInt(1), big.NewInt(0), big.NewInt(0)))
	wo.WorkObjectHeader().SetScryptDiffAndCount(types.NewPowShareDiffAndCount(big.NewInt(1), big.NewInt(0), big.NewInt(0)))
	wo.WorkObjectHeader().SetKawpowDifficulty(big.NewInt(1))
	if nodeCtx < common.ZONE_CTX {
		wo.Header().SetNumber(new(big.Int).SetUint64(number), nodeCtx)
	}
	wo.Header().SetPrimeTerminusHash(primeTerminus)
	wo.Body().SetManifest(manifest)
	setCLITestManifestCommitment(t, wo, nodeCtx)
	return wo
}

func cliTestAuxPow(powID types.PowID) *types.AuxPow {
	var prevBlock [32]byte
	prevBlock[0] = 1
	var merkleRoot [32]byte
	merkleRoot[0] = 2
	auxMerkleRoot := common.Hash{0x03}
	coinbaseOut := []byte{0x00, 0x00, 0x00, 0x00, 0x00}
	tx := types.NewAuxPowCoinbaseTx(powID, 101, coinbaseOut, auxMerkleRoot, 1234567890)
	return types.NewAuxPow(
		powID,
		types.NewBlockHeader(powID, 0x20000000, prevBlock, merkleRoot, 1234567890, 0x1d00ffff, 0, 101),
		nil,
		nil,
		nil,
		tx,
	)
}

func setCLITestManifestCommitment(t *testing.T, wo *types.WorkObject, nodeCtx int) {
	t.Helper()
	switch nodeCtx {
	case common.PRIME_CTX:
		wo.Header().SetManifestHash(types.DeriveSha(wo.Manifest(), trie.NewStackTrie(nil)), common.REGION_CTX)
	case common.REGION_CTX:
		wo.Header().SetManifestHash(types.DeriveSha(wo.Manifest(), trie.NewStackTrie(nil)), common.ZONE_CTX)
	}
	wo.WorkObjectHeader().SetHeaderHash(wo.Header().Hash())
}
