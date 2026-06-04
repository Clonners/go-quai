package nipopow

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/core/types"
)

func TestCollectHierarchyProofFromSourceBuildsVerifiableWrapper(t *testing.T) {
	fixture := testHierarchyProof(t)
	source := newHierarchyCollectTestSource(t, fixture)

	proof, err := CollectHierarchyProofWithContext(context.Background(), source, HierarchyProofRequest{
		ZoneHash:    fixture.ZoneHeader.Hash(),
		RegionHash:  fixture.RegionHeader.Hash(),
		PrimeAnchor: fixture.PrimeProof.Anchor,
		PrimeTip:    fixture.PrimeHeader.Hash(),
		M:           fixture.PrimeProof.M,
		Limits:      DefaultBuildLimits,
	})
	if err != nil {
		t.Fatalf("expected collect to succeed: %v", err)
	}
	if err := VerifyHierarchyProof(proof); err != nil {
		t.Fatalf("collected proof should verify: %v", err)
	}
	if proof.RegionHeader.Manifest()[0] != fixture.ZoneHeader.Hash() {
		t.Fatalf("region manifest not hydrated with zone hash")
	}
	if proof.PrimeHeader.Manifest()[0] != fixture.RegionHeader.Hash() {
		t.Fatalf("prime manifest not hydrated with region hash")
	}
}

func TestCollectHierarchyProofFromSourceRejectsMissingManifest(t *testing.T) {
	fixture := testHierarchyProof(t)
	source := newHierarchyCollectTestSource(t, fixture)
	delete(source.manifests[common.REGION_CTX], fixture.RegionHeader.Hash())

	_, err := CollectHierarchyProofWithContext(context.Background(), source, HierarchyProofRequest{
		ZoneHash:    fixture.ZoneHeader.Hash(),
		RegionHash:  fixture.RegionHeader.Hash(),
		PrimeAnchor: fixture.PrimeProof.Anchor,
		PrimeTip:    fixture.PrimeHeader.Hash(),
		M:           fixture.PrimeProof.M,
		Limits:      DefaultBuildLimits,
	})
	if !errors.Is(err, ErrHierarchyMissingManifest) {
		t.Fatalf("expected missing manifest error, got %v", err)
	}
}

func TestCollectHierarchyProofFromSourceRejectsHashMismatch(t *testing.T) {
	fixture := testHierarchyProof(t)
	source := newHierarchyCollectTestSource(t, fixture)
	source.headers[common.ZONE_CTX][fixture.ZoneHeader.Hash()] = testHierarchyBlock(t, common.ZONE_CTX, common.Location{0, 0}, 99, fixture.PrimeProof.Anchor, nil)

	_, err := CollectHierarchyProofWithContext(context.Background(), source, HierarchyProofRequest{
		ZoneHash:    fixture.ZoneHeader.Hash(),
		RegionHash:  fixture.RegionHeader.Hash(),
		PrimeAnchor: fixture.PrimeProof.Anchor,
		PrimeTip:    fixture.PrimeHeader.Hash(),
		M:           fixture.PrimeProof.M,
		Limits:      DefaultBuildLimits,
	})
	if !errors.Is(err, ErrHierarchyHeaderHashMismatch) {
		t.Fatalf("expected source hash mismatch error, got %v", err)
	}
}

type hierarchyCollectTestSource struct {
	headers   map[int]map[common.Hash]*types.WorkObject
	manifests map[int]map[common.Hash]types.BlockManifest
}

func newHierarchyCollectTestSource(t *testing.T, proof *HierarchyProof) *hierarchyCollectTestSource {
	t.Helper()

	source := &hierarchyCollectTestSource{
		headers: map[int]map[common.Hash]*types.WorkObject{
			common.PRIME_CTX:  {},
			common.REGION_CTX: {},
			common.ZONE_CTX:   {},
		},
		manifests: map[int]map[common.Hash]types.BlockManifest{
			common.PRIME_CTX:  {},
			common.REGION_CTX: {},
			common.ZONE_CTX:   {},
		},
	}
	for _, header := range proof.PrimeProof.Headers {
		source.headers[common.PRIME_CTX][header.Hash()] = types.CopyWorkObject(header)
	}
	source.headers[common.PRIME_CTX][proof.PrimeHeader.Hash()] = types.CopyWorkObject(proof.PrimeHeader)
	source.headers[common.REGION_CTX][proof.RegionHeader.Hash()] = types.CopyWorkObject(proof.RegionHeader)
	source.headers[common.ZONE_CTX][proof.ZoneHeader.Hash()] = types.CopyWorkObject(proof.ZoneHeader)
	source.manifests[common.PRIME_CTX][proof.PrimeHeader.Hash()] = types.BlockManifest{proof.RegionHeader.Hash()}
	source.manifests[common.REGION_CTX][proof.RegionHeader.Hash()] = types.BlockManifest{proof.ZoneHeader.Hash()}
	return source
}

func (s *hierarchyCollectTestSource) Header(hash common.Hash, nodeCtx int) (*types.WorkObject, error) {
	byHash := s.headers[nodeCtx]
	if byHash == nil || byHash[hash] == nil {
		return nil, fmt.Errorf("missing header ctx=%d hash=%s", nodeCtx, hash.Hex())
	}
	return types.CopyWorkObject(byHash[hash]), nil
}

func (s *hierarchyCollectTestSource) Manifest(hash common.Hash, nodeCtx int) (types.BlockManifest, error) {
	byHash := s.manifests[nodeCtx]
	if byHash == nil || byHash[hash] == nil {
		return nil, fmt.Errorf("missing manifest ctx=%d hash=%s", nodeCtx, hash.Hex())
	}
	return append(types.BlockManifest(nil), byHash[hash]...), nil
}

func (s *hierarchyCollectTestSource) ProofHeader(hash common.Hash) (*types.WorkObject, error) {
	return s.Header(hash, common.PRIME_CTX)
}
