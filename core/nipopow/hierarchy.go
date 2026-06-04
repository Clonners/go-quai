package nipopow

import (
	"errors"
	"fmt"

	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/core/types"
	"github.com/dominant-strategies/go-quai/trie"
)

var (
	ErrNilHierarchyProof              = errors.New("nil nipopow hierarchy proof")
	ErrHierarchyMissingZoneHeader     = errors.New("nipopow hierarchy proof missing zone header")
	ErrHierarchyMissingRegionHeader   = errors.New("nipopow hierarchy proof missing region header")
	ErrHierarchyMissingPrimeHeader    = errors.New("nipopow hierarchy proof missing prime header")
	ErrHierarchyMissingPrimeProof     = errors.New("nipopow hierarchy proof missing prime proof")
	ErrHierarchyLocationMismatch      = errors.New("nipopow hierarchy location mismatch")
	ErrHierarchyManifestMismatch      = errors.New("nipopow hierarchy manifest hash mismatch")
	ErrHierarchyManifestMissingHash   = errors.New("nipopow hierarchy manifest missing required hash")
	ErrHierarchyPrimeProofTipMismatch = errors.New("nipopow hierarchy prime proof tip mismatch")
	ErrHierarchyPrimeTerminusMissing  = errors.New("nipopow hierarchy prime terminus is not proven")
)

// HierarchyProof is a read-only, non-consensus wrapper that binds a Zone header
// to a Region manifest, a Region header to a Prime manifest, and that Prime
// manifest carrier to a verified Prime NiPoPoW proof.
//
// This object is intentionally a verifier/prototype primitive. It does not read
// or write chain state and it does not alter consensus or mining behavior.
type HierarchyProof struct {
	ZoneHeader   *types.WorkObject `json:"zoneHeader"`
	RegionHeader *types.WorkObject `json:"regionHeader"`
	PrimeHeader  *types.WorkObject `json:"primeHeader"`
	PrimeProof   *Proof            `json:"primeProof"`
}

// VerifyHierarchyProof validates the structural hierarchy wrapper:
//
//   - Zone and Region locations match.
//   - Region body manifest is committed by the Region header and contains the
//     Zone header hash.
//   - Prime body manifest is committed by the Prime header and contains the
//     Region header hash.
//   - The Prime header carrying that manifest is the tip of a valid Prime
//     NiPoPoW proof.
//   - Zone/Region prime terminus hashes are present somewhere in the Prime
//     proof, so the subordinate context is tied to proven Prime work.
func VerifyHierarchyProof(proof *HierarchyProof) error {
	if proof == nil {
		return ErrNilHierarchyProof
	}
	if proof.PrimeProof == nil {
		return ErrHierarchyMissingPrimeProof
	}
	if proof.ZoneHeader == nil {
		return ErrHierarchyMissingZoneHeader
	}
	if proof.RegionHeader == nil {
		return ErrHierarchyMissingRegionHeader
	}
	if proof.PrimeHeader == nil {
		return ErrHierarchyMissingPrimeHeader
	}

	if err := VerifyPrimeProof(proof.PrimeProof); err != nil {
		return fmt.Errorf("prime proof: %w", err)
	}
	if err := verifyHierarchyHeader("zone", proof.ZoneHeader, common.ZONE_CTX); err != nil {
		return err
	}
	if err := verifyHierarchyHeader("region", proof.RegionHeader, common.REGION_CTX); err != nil {
		return err
	}
	if err := verifyHierarchyHeader("prime", proof.PrimeHeader, common.PRIME_CTX); err != nil {
		return err
	}
	if proof.PrimeProof.Tip() != proof.PrimeHeader.Hash() {
		return fmt.Errorf("%w: proof tip %s prime header %s", ErrHierarchyPrimeProofTipMismatch, proof.PrimeProof.Tip().Hex(), proof.PrimeHeader.Hash().Hex())
	}

	zoneLocation := proof.ZoneHeader.Location()
	regionLocation := proof.RegionHeader.Location()
	if zoneLocation.Region() != regionLocation.Region() {
		return fmt.Errorf("%w: zone %v region %v", ErrHierarchyLocationMismatch, zoneLocation, regionLocation)
	}

	if err := verifyHierarchyPrimeTerminus("zone", proof.ZoneHeader, proof.PrimeProof); err != nil {
		return err
	}
	if err := verifyHierarchyPrimeTerminus("region", proof.RegionHeader, proof.PrimeProof); err != nil {
		return err
	}
	if err := verifyHierarchyManifest("region", proof.RegionHeader, common.REGION_CTX, common.ZONE_CTX, proof.ZoneHeader.Hash()); err != nil {
		return err
	}
	if err := verifyHierarchyManifest("prime", proof.PrimeHeader, common.PRIME_CTX, common.REGION_CTX, proof.RegionHeader.Hash()); err != nil {
		return err
	}

	return nil
}

func verifyHierarchyHeader(label string, header *types.WorkObject, wantCtx int) error {
	if err := verifyUsableHeader(header); err != nil {
		return fmt.Errorf("%s header: %w", label, err)
	}
	// WorkObject.Location() identifies the origin slice. In real chain storage,
	// Region/Prime coincident carriers can still be zone-located WorkObjects;
	// their order/source context is established by the chain source and the
	// manifest/proof path, not by Location().Context(). The Zone leaf must remain
	// a concrete Zone location because its region path is checked below.
	if wantCtx == common.ZONE_CTX && header.Location().Context() != common.ZONE_CTX {
		return fmt.Errorf("%w: %s header has location context %d want zone location", ErrHierarchyLocationMismatch, label, header.Location().Context())
	}
	return nil
}

func verifyHierarchyManifest(label string, carrier *types.WorkObject, carrierCtx int, manifestCtx int, required common.Hash) error {
	expected := types.DeriveSha(carrier.Manifest(), trie.NewStackTrie(nil))
	if carrier.ManifestHash(manifestCtx) != expected {
		return fmt.Errorf("%w: %s manifest ctx %d expected %s got %s", ErrHierarchyManifestMismatch, label, manifestCtx, expected.Hex(), carrier.ManifestHash(manifestCtx).Hex())
	}
	if !manifestContains(carrier.Manifest(), required) {
		return fmt.Errorf("%w: %s manifest from ctx %d missing %s", ErrHierarchyManifestMissingHash, label, carrierCtx, required.Hex())
	}
	return nil
}

func verifyHierarchyPrimeTerminus(label string, header *types.WorkObject, proof *Proof) error {
	terminus := header.PrimeTerminusHash()
	if terminus == (common.Hash{}) || !proofContainsHash(proof, terminus) {
		return fmt.Errorf("%w: %s terminus %s", ErrHierarchyPrimeTerminusMissing, label, terminus.Hex())
	}
	return nil
}

func proofContainsHash(proof *Proof, hash common.Hash) bool {
	if proof == nil {
		return false
	}
	for _, header := range proof.Headers {
		if header != nil && header.Hash() == hash {
			return true
		}
	}
	return false
}

func manifestContains(manifest types.BlockManifest, hash common.Hash) bool {
	for _, entry := range manifest {
		if entry == hash {
			return true
		}
	}
	return false
}
