package core

import (
	"context"
	"math/big"
	"testing"

	lru "github.com/hashicorp/golang-lru/v2"

	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/core/nipopow"
	"github.com/dominant-strategies/go-quai/core/rawdb"
	"github.com/dominant-strategies/go-quai/core/types"
	"github.com/dominant-strategies/go-quai/log"
	"github.com/dominant-strategies/go-quai/params"
	"github.com/dominant-strategies/go-quai/trie"
)

func TestGetBlockTemplateNiPoPoWProofBuildsFromDominantZoneContext(t *testing.T) {
	primeCore, primeHC := testTemplateCore(t, common.Location{})
	regionCore, regionHC := testTemplateCore(t, common.Location{0})
	zoneCore, zoneHC := testTemplateCore(t, common.Location{0, 0})
	regionCore.sl.domInterface = templateCoreBackend{Core: primeCore}
	zoneCore.sl.domInterface = templateCoreBackend{Core: regionCore}

	primeInterlinks := common.Hashes{common.HexToHash("0x01")}
	primeAnchor := testPrimeNiPoPoWBlock(t, 0, nil, primeInterlinks)
	zoneParent := testTemplateHierarchyBlock(t, common.ZONE_CTX, common.Location{0, 0}, 7, primeAnchor.Hash(), types.BlockManifest(nil))
	regionCarrier := testTemplateHierarchyBlock(t, common.REGION_CTX, common.Location{0}, 5, primeAnchor.Hash(), types.BlockManifest{zoneParent.Hash()})
	primeTip := testPrimeNiPoPoWBlock(t, 1, primeAnchor, primeInterlinks)
	primeTip.Body().SetManifest(types.BlockManifest{regionCarrier.Hash()})
	setTemplateManifestCommitment(t, primeTip, common.PRIME_CTX)

	rawdb.WriteGenesisHashes(primeHC.headerDb, common.Hashes{primeAnchor.Hash()})
	rawdb.WriteInterlinkHashes(primeHC.headerDb, primeAnchor.Hash(), primeInterlinks)
	writeTemplateBlock(t, primeHC, primeAnchor, common.PRIME_CTX)
	writeTemplateBlock(t, primeHC, primeTip, common.PRIME_CTX)
	writeTemplateBlock(t, regionHC, regionCarrier, common.REGION_CTX)
	writeTemplateBlock(t, zoneHC, zoneParent, common.ZONE_CTX)

	pending := testTemplateHierarchyBlock(t, common.ZONE_CTX, common.Location{0, 0}, 8, primeAnchor.Hash(), nil)
	pending.SetParentHash(zoneParent.Hash(), common.ZONE_CTX)
	pending.SetParentHash(regionCarrier.Hash(), common.REGION_CTX)
	pending.SetParentHash(primeTip.Hash(), common.PRIME_CTX)
	pending.WorkObjectHeader().SetHeaderHash(pending.Header().Hash())

	result, err := zoneCore.GetBlockTemplateNiPoPoWProof(context.Background(), pending, nipopow.TemplateHierarchyProofOptions{M: 1})
	if err != nil {
		t.Fatalf("expected template proof from dominant context: %v", err)
	}
	if result.Request.ZoneHash != zoneParent.Hash() {
		t.Fatalf("zone parent mismatch: want %s got %s", zoneParent.Hash(), result.Request.ZoneHash)
	}
	if result.Request.RegionHash != regionCarrier.Hash() {
		t.Fatalf("region carrier mismatch: want %s got %s", regionCarrier.Hash(), result.Request.RegionHash)
	}
	if result.Request.PrimeTip != primeTip.Hash() {
		t.Fatalf("prime tip mismatch: want %s got %s", primeTip.Hash(), result.Request.PrimeTip)
	}
	if result.Request.PrimeAnchor != primeAnchor.Hash() {
		t.Fatalf("prime anchor mismatch: want %s got %s", primeAnchor.Hash(), result.Request.PrimeAnchor)
	}
	if err := nipopow.VerifyHierarchyProof(result.Proof); err != nil {
		t.Fatalf("expected hierarchy proof to verify: %v", err)
	}
}

type templateCoreBackend struct {
	*Core
}

func (b templateCoreBackend) NewGenesisPendingHeader(pendingHeader *types.WorkObject, domTerminus common.Hash, genesisHash common.Hash) error {
	return b.Core.NewGenesisPendigHeader(pendingHeader, domTerminus, genesisHash)
}

func (b templateCoreBackend) ReceiveMinedHeader(header *types.WorkObject) error {
	_, err := b.Core.ReceiveMinedHeader(header)
	return err
}

func testTemplateCore(t *testing.T, location common.Location) (*Core, *HeaderChain) {
	t.Helper()

	db := rawdb.NewMemoryDatabase(log.Global)
	chainConfig := *params.TestChainConfig
	chainConfig.Location = location

	headerCache, err := lru.New[common.Hash, types.WorkObject](headerCacheLimit)
	if err != nil {
		t.Fatal(err)
	}
	numberCache, err := lru.New[common.Hash, uint64](numberCacheLimit)
	if err != nil {
		t.Fatal(err)
	}

	hc := NewTestHeaderChain()
	hc.config = &chainConfig
	hc.headerDb = db
	hc.bc = NewTestBodyDb(db)
	hc.bc.chainConfig = &chainConfig
	hc.headerCache = headerCache
	hc.numberCache = numberCache
	hc.logger = log.Global
	return &Core{sl: &Slice{hc: hc, sliceDb: db}}, hc
}

func testTemplateHierarchyBlock(t *testing.T, nodeCtx int, location common.Location, number uint64, primeTerminus common.Hash, manifest types.BlockManifest) *types.WorkObject {
	t.Helper()

	wo := types.EmptyWorkObject(nodeCtx)
	wo.WorkObjectHeader().SetLocation(location)
	wo.WorkObjectHeader().SetNumber(new(big.Int).SetUint64(number))
	wo.WorkObjectHeader().SetPrimeTerminusNumber(new(big.Int).SetUint64(0))
	wo.WorkObjectHeader().SetTime(number)
	if nodeCtx < common.ZONE_CTX {
		wo.Header().SetNumber(new(big.Int).SetUint64(number), nodeCtx)
	}
	wo.Header().SetPrimeTerminusHash(primeTerminus)
	wo.Body().SetManifest(manifest)
	setTemplateManifestCommitment(t, wo, nodeCtx)
	return wo
}

func setTemplateManifestCommitment(t *testing.T, wo *types.WorkObject, nodeCtx int) {
	t.Helper()
	switch nodeCtx {
	case common.PRIME_CTX:
		wo.Header().SetManifestHash(types.DeriveSha(wo.Manifest(), trie.NewStackTrie(nil)), common.REGION_CTX)
	case common.REGION_CTX:
		wo.Header().SetManifestHash(types.DeriveSha(wo.Manifest(), trie.NewStackTrie(nil)), common.ZONE_CTX)
	}
	wo.WorkObjectHeader().SetHeaderHash(wo.Header().Hash())
}

func writeTemplateBlock(t *testing.T, hc *HeaderChain, wo *types.WorkObject, nodeCtx int) {
	t.Helper()
	rawdb.WriteTermini(hc.headerDb, wo.Hash(), types.EmptyTermini())
	rawdb.WriteCanonicalHash(hc.headerDb, wo.Hash(), wo.NumberU64(nodeCtx))
	hc.bc.WriteBlock(wo, nodeCtx)
	hc.headerCache.Add(wo.Hash(), *wo)
	if wo.Manifest() != nil {
		rawdb.WriteManifest(hc.headerDb, wo.Hash(), wo.Manifest())
	}
}
