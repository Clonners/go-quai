package nipopow

import (
	"context"
	"errors"
	"testing"

	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/core/types"
)

func TestBuildTemplateHierarchyProofDerivesZoneParentContext(t *testing.T) {
	fixture := testHierarchyProof(t)
	source := newHierarchyCollectTestSource(t, fixture)
	pending := testZoneTemplatePendingHeader(t, fixture)

	result, err := BuildTemplateHierarchyProofWithContext(context.Background(), source, pending, TemplateHierarchyProofOptions{M: 1})
	if err != nil {
		t.Fatalf("expected template hierarchy proof to build: %v", err)
	}
	if result.TemplateParentHash != fixture.ZoneHeader.Hash() {
		t.Fatalf("template parent hash mismatch: want %s got %s", fixture.ZoneHeader.Hash(), result.TemplateParentHash)
	}
	if result.Request.ZoneHash != fixture.ZoneHeader.Hash() {
		t.Fatalf("zone hash mismatch: want %s got %s", fixture.ZoneHeader.Hash(), result.Request.ZoneHash)
	}
	if result.Request.RegionHash != fixture.RegionHeader.Hash() {
		t.Fatalf("region hash mismatch: want %s got %s", fixture.RegionHeader.Hash(), result.Request.RegionHash)
	}
	if result.Request.PrimeTip != fixture.PrimeHeader.Hash() {
		t.Fatalf("prime tip mismatch: want %s got %s", fixture.PrimeHeader.Hash(), result.Request.PrimeTip)
	}
	if result.Request.PrimeAnchor != fixture.PrimeProof.Anchor {
		t.Fatalf("prime anchor mismatch: want %s got %s", fixture.PrimeProof.Anchor, result.Request.PrimeAnchor)
	}
	if result.Proof == nil {
		t.Fatalf("expected hierarchy proof")
	}
	if err := VerifyHierarchyProof(result.Proof); err != nil {
		t.Fatalf("expected hierarchy proof to verify: %v", err)
	}
}

func TestBuildTemplateHierarchyProofFallsBackToManifestBackedTemplateContext(t *testing.T) {
	primeAnchor := testPrimeBlock(t, 1, nil, nil)
	manifestZone := testHierarchyBlock(t, common.ZONE_CTX, common.Location{0, 0}, 7, primeAnchor.Hash(), nil)
	manifestRegion := testHierarchyBlock(t, common.REGION_CTX, common.Location{0}, 5, primeAnchor.Hash(), types.BlockManifest{manifestZone.Hash()})
	primeTip := testPrimeBlock(t, 2, primeAnchor, nil)
	primeTip.Body().SetManifest(types.BlockManifest{manifestRegion.Hash()})
	setHierarchyManifestCommitment(t, primeTip, common.PRIME_CTX)

	regionContext := testHierarchyBlock(t, common.REGION_CTX, common.Location{0}, 6, primeAnchor.Hash(), types.BlockManifest{manifestRegion.Hash()})
	regionContext.SetParentHash(manifestRegion.Hash(), common.REGION_CTX)
	regionContext.SetParentHash(primeAnchor.Hash(), common.PRIME_CTX)
	regionContext.WorkObjectHeader().SetHeaderHash(regionContext.Header().Hash())

	zoneParent := testHierarchyBlock(t, common.ZONE_CTX, common.Location{0, 0}, 8, primeTip.Hash(), nil)
	zoneParent.SetParentHash(regionContext.Hash(), common.REGION_CTX)
	zoneParent.SetParentHash(primeTip.Hash(), common.PRIME_CTX)
	zoneParent.WorkObjectHeader().SetHeaderHash(zoneParent.Header().Hash())

	pending := testHierarchyBlock(t, common.ZONE_CTX, common.Location{0, 0}, 9, primeTip.Hash(), nil)
	pending.SetParentHash(zoneParent.Hash(), common.ZONE_CTX)
	pending.SetParentHash(regionContext.Hash(), common.REGION_CTX)
	pending.SetParentHash(primeTip.Hash(), common.PRIME_CTX)
	pending.WorkObjectHeader().SetHeaderHash(pending.Header().Hash())

	source := newHierarchyCollectTestSource(t, &HierarchyProof{
		ZoneHeader:   manifestZone,
		RegionHeader: manifestRegion,
		PrimeHeader:  primeTip,
		PrimeProof: &Proof{
			Anchor:  primeAnchor.Hash(),
			M:       1,
			Headers: []*types.WorkObject{primeAnchor, primeTip},
		},
	})
	source.headers[common.REGION_CTX][regionContext.Hash()] = types.CopyWorkObject(regionContext)
	source.headers[common.ZONE_CTX][zoneParent.Hash()] = types.CopyWorkObject(zoneParent)
	source.manifests[common.REGION_CTX][regionContext.Hash()] = regionContext.Manifest()

	result, err := BuildTemplateHierarchyProofWithContext(context.Background(), source, pending, TemplateHierarchyProofOptions{M: 1})
	if err != nil {
		t.Fatalf("expected template hierarchy proof to use manifest-backed context: %v", err)
	}
	if result.TemplateParentHash != zoneParent.Hash() {
		t.Fatalf("template parent hash mismatch: got %s want %s", result.TemplateParentHash, zoneParent.Hash())
	}
	if result.Request.ZoneHash != manifestZone.Hash() || result.Request.RegionHash != manifestRegion.Hash() {
		t.Fatalf("expected manifest-backed request, got %+v", result.Request)
	}
	if err := VerifyHierarchyProof(result.Proof); err != nil {
		t.Fatalf("expected fallback hierarchy proof to verify: %v", err)
	}
}

func TestBuildTemplateHierarchyProofRejectsNonZonePendingHeader(t *testing.T) {
	fixture := testHierarchyProof(t)
	source := newHierarchyCollectTestSource(t, fixture)
	pending := testHierarchyBlock(t, common.REGION_CTX, common.Location{0}, 8, fixture.PrimeProof.Anchor, nil)

	_, err := BuildTemplateHierarchyProofWithContext(context.Background(), source, pending, TemplateHierarchyProofOptions{M: 1})
	if !errors.Is(err, ErrTemplateHierarchyProofRequiresZone) {
		t.Fatalf("expected zone-only error, got %v", err)
	}
}

func TestBuildTemplateHierarchyProofRejectsMissingTemplateContext(t *testing.T) {
	fixture := testHierarchyProof(t)
	source := newHierarchyCollectTestSource(t, fixture)
	pending := testZoneTemplatePendingHeader(t, fixture)
	pending.SetParentHash(common.Hash{}, common.REGION_CTX)
	pending.WorkObjectHeader().SetHeaderHash(pending.Header().Hash())

	_, err := BuildTemplateHierarchyProofWithContext(context.Background(), source, pending, TemplateHierarchyProofOptions{M: 1})
	if !errors.Is(err, ErrTemplateHierarchyProofMissingContext) {
		t.Fatalf("expected missing context error, got %v", err)
	}
}

func testZoneTemplatePendingHeader(t *testing.T, fixture *HierarchyProof) *types.WorkObject {
	t.Helper()
	pending := testHierarchyBlock(t, common.ZONE_CTX, common.Location{0, 0}, fixture.ZoneHeader.NumberU64(common.ZONE_CTX)+1, fixture.PrimeProof.Anchor, nil)
	pending.SetParentHash(fixture.ZoneHeader.Hash(), common.ZONE_CTX)
	pending.SetParentHash(fixture.RegionHeader.Hash(), common.REGION_CTX)
	pending.SetParentHash(fixture.PrimeHeader.Hash(), common.PRIME_CTX)
	pending.WorkObjectHeader().SetHeaderHash(pending.Header().Hash())
	return pending
}
