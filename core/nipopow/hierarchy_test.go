package nipopow

import (
	"errors"
	"math/big"
	"testing"

	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/core/types"
	"github.com/dominant-strategies/go-quai/trie"
)

func TestVerifyHierarchyProofAcceptsZoneRegionPrimeManifestBinding(t *testing.T) {
	proof := testHierarchyProof(t)

	if err := VerifyHierarchyProof(proof); err != nil {
		t.Fatalf("expected hierarchy proof to verify: %v", err)
	}
}

func TestVerifyHierarchyProofRejectsBrokenManifestCommitments(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*HierarchyProof)
		want   error
	}{
		{
			name: "zone missing from region manifest",
			mutate: func(proof *HierarchyProof) {
				proof.RegionHeader.Body().SetManifest(types.BlockManifest{common.HexToHash("0xabc")})
				setHierarchyManifestCommitment(t, proof.RegionHeader, common.REGION_CTX)
			},
			want: ErrHierarchyManifestMissingHash,
		},
		{
			name: "region manifest hash mismatch",
			mutate: func(proof *HierarchyProof) {
				proof.RegionHeader.Header().SetManifestHash(common.HexToHash("0xdeadbeef"), common.ZONE_CTX)
				proof.RegionHeader.WorkObjectHeader().SetHeaderHash(proof.RegionHeader.Header().Hash())
			},
			want: ErrHierarchyManifestMismatch,
		},
		{
			name: "region missing from prime manifest",
			mutate: func(proof *HierarchyProof) {
				proof.PrimeHeader.Body().SetManifest(types.BlockManifest{common.HexToHash("0xdef")})
				setHierarchyManifestCommitment(t, proof.PrimeHeader, common.PRIME_CTX)
				proof.PrimeProof.Headers[len(proof.PrimeProof.Headers)-1] = proof.PrimeHeader
			},
			want: ErrHierarchyManifestMissingHash,
		},
		{
			name: "prime manifest hash mismatch",
			mutate: func(proof *HierarchyProof) {
				proof.PrimeHeader.Header().SetManifestHash(common.HexToHash("0xfeed"), common.REGION_CTX)
				proof.PrimeHeader.WorkObjectHeader().SetHeaderHash(proof.PrimeHeader.Header().Hash())
				proof.PrimeProof.Headers[len(proof.PrimeProof.Headers)-1] = proof.PrimeHeader
			},
			want: ErrHierarchyManifestMismatch,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proof := testHierarchyProof(t)
			tt.mutate(proof)

			err := VerifyHierarchyProof(proof)
			if !errors.Is(err, tt.want) {
				t.Fatalf("expected %v, got %v", tt.want, err)
			}
		})
	}
}

func TestVerifyHierarchyProofRejectsUnboundPrimeContext(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*HierarchyProof)
		want   error
	}{
		{
			name: "prime manifest carrier is not proof tip",
			mutate: func(proof *HierarchyProof) {
				proof.PrimeProof.Headers = proof.PrimeProof.Headers[:len(proof.PrimeProof.Headers)-1]
			},
			want: ErrHierarchyPrimeProofTipMismatch,
		},
		{
			name: "zone prime terminus not proven",
			mutate: func(proof *HierarchyProof) {
				proof.ZoneHeader.Header().SetPrimeTerminusHash(common.HexToHash("0x1234"))
				proof.ZoneHeader.WorkObjectHeader().SetHeaderHash(proof.ZoneHeader.Header().Hash())
				rebindHierarchyManifests(t, proof)
			},
			want: ErrHierarchyPrimeTerminusMissing,
		},
		{
			name: "region prime terminus not proven",
			mutate: func(proof *HierarchyProof) {
				proof.RegionHeader.Header().SetPrimeTerminusHash(common.HexToHash("0x5678"))
				proof.RegionHeader.WorkObjectHeader().SetHeaderHash(proof.RegionHeader.Header().Hash())
				rebindHierarchyManifests(t, proof)
			},
			want: ErrHierarchyPrimeTerminusMissing,
		},
		{
			name: "zone and region locations diverge",
			mutate: func(proof *HierarchyProof) {
				proof.ZoneHeader.WorkObjectHeader().SetLocation(common.Location{1, 0})
				rebindHierarchyManifests(t, proof)
			},
			want: ErrHierarchyLocationMismatch,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proof := testHierarchyProof(t)
			tt.mutate(proof)

			err := VerifyHierarchyProof(proof)
			if !errors.Is(err, tt.want) {
				t.Fatalf("expected %v, got %v", tt.want, err)
			}
		})
	}
}

func testHierarchyProof(t *testing.T) *HierarchyProof {
	t.Helper()

	primeAnchor := testPrimeBlock(t, 1, nil, nil)
	primeTerminus := primeAnchor.Hash()

	zone := testHierarchyBlock(t, common.ZONE_CTX, common.Location{0, 0}, 7, primeTerminus, nil)
	region := testHierarchyBlock(t, common.REGION_CTX, common.Location{0}, 5, primeTerminus, types.BlockManifest{zone.Hash()})
	primeTip := testPrimeBlock(t, 2, primeAnchor, nil)
	primeTip.Body().SetManifest(types.BlockManifest{region.Hash()})
	setHierarchyManifestCommitment(t, primeTip, common.PRIME_CTX)

	return &HierarchyProof{
		ZoneHeader:   zone,
		RegionHeader: region,
		PrimeHeader:  primeTip,
		PrimeProof: &Proof{
			Anchor:  primeAnchor.Hash(),
			M:       1,
			Headers: []*types.WorkObject{primeAnchor, primeTip},
		},
	}
}

func testHierarchyBlock(t *testing.T, nodeCtx int, location common.Location, number uint64, primeTerminus common.Hash, manifest types.BlockManifest) *types.WorkObject {
	t.Helper()

	wo := types.EmptyWorkObject(nodeCtx)
	wo.WorkObjectHeader().SetLocation(location)
	wo.WorkObjectHeader().SetNumber(new(big.Int).SetUint64(number))
	wo.WorkObjectHeader().SetPrimeTerminusNumber(new(big.Int).SetUint64(1))
	wo.WorkObjectHeader().SetTime(number)

	header := wo.Header()
	if nodeCtx < common.ZONE_CTX {
		header.SetNumber(new(big.Int).SetUint64(number), nodeCtx)
	}
	header.SetPrimeTerminusHash(primeTerminus)
	wo.Body().SetManifest(manifest)
	setHierarchyManifestCommitment(t, wo, nodeCtx)
	return wo
}

func rebindHierarchyManifests(t *testing.T, proof *HierarchyProof) {
	t.Helper()

	proof.RegionHeader.Body().SetManifest(types.BlockManifest{proof.ZoneHeader.Hash()})
	setHierarchyManifestCommitment(t, proof.RegionHeader, common.REGION_CTX)
	proof.PrimeHeader.Body().SetManifest(types.BlockManifest{proof.RegionHeader.Hash()})
	setHierarchyManifestCommitment(t, proof.PrimeHeader, common.PRIME_CTX)
	proof.PrimeProof.Headers[len(proof.PrimeProof.Headers)-1] = proof.PrimeHeader
}

func setHierarchyManifestCommitment(t *testing.T, wo *types.WorkObject, nodeCtx int) {
	t.Helper()

	switch nodeCtx {
	case common.PRIME_CTX:
		wo.Header().SetManifestHash(types.DeriveSha(wo.Manifest(), trie.NewStackTrie(nil)), common.REGION_CTX)
	case common.REGION_CTX:
		wo.Header().SetManifestHash(types.DeriveSha(wo.Manifest(), trie.NewStackTrie(nil)), common.ZONE_CTX)
	}
	wo.WorkObjectHeader().SetHeaderHash(wo.Header().Hash())
}
