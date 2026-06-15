package nipopow

import (
	"context"
	"errors"
	"fmt"

	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/core/types"
)

const (
	DefaultTemplateHierarchyProofM     uint64 = 16
	DefaultMaxTemplateFallbackIter     int    = 512
)

var (
	ErrTemplateHierarchyProofMissingPending = errors.New("nipopow template hierarchy proof missing pending header")
	ErrTemplateHierarchyProofRequiresZone   = errors.New("nipopow template hierarchy proof requires zone pending header")
	ErrTemplateHierarchyProofMissingContext = errors.New("nipopow template hierarchy proof missing hierarchy context")
	ErrTemplateHierarchyProofMissingAnchor  = errors.New("nipopow template hierarchy proof missing prime anchor")
	ErrTemplateHierarchyProofMissingBacking = errors.New("nipopow template hierarchy proof missing manifest-backed context")
)

// TemplateHierarchyProofOptions bounds the read-only shadow proof built for a
// mining template. PrimeAnchor is optional; when omitted, the builder derives
// the earliest non-zero Prime terminus from the template's Zone/Region context.
type TemplateHierarchyProofOptions struct {
	M           uint64
	Limits      BuildLimits
	PrimeAnchor common.Hash
}

// TemplateHierarchyProof is a shadow-mode proof artifact for a Zone mining
// template. The proof binds the already-persisted parent/context that the
// pending template extends; it does not claim the unmined template itself is
// already present in any Region or Prime manifest.
type TemplateHierarchyProof struct {
	TemplateHash       common.Hash           `json:"templateHash"`
	TemplateSealHash   common.Hash           `json:"templateSealHash"`
	TemplateParentHash common.Hash           `json:"templateParentHash"`
	Request            HierarchyProofRequest `json:"request"`
	Proof              *HierarchyProof       `json:"proof"`
}

// BuildTemplateHierarchyProofWithContext derives a hierarchy proof request from
// a Zone pending header and collects a verified read-only hierarchy proof for
// the canonical context that backs the template.
func BuildTemplateHierarchyProofWithContext(ctx context.Context, source HierarchyProofSource, pending *types.WorkObject, opts TemplateHierarchyProofOptions) (*TemplateHierarchyProof, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if source == nil {
		return nil, ErrNilHierarchySource
	}
	if pending == nil {
		return nil, ErrTemplateHierarchyProofMissingPending
	}
	if pending.Location().Context() != common.ZONE_CTX {
		return nil, fmt.Errorf("%w: location=%v", ErrTemplateHierarchyProofRequiresZone, pending.Location())
	}

	m := opts.M
	if m == 0 {
		m = DefaultTemplateHierarchyProofM
	}
	limits := opts.Limits.withDefaults()

	zoneHash := pending.ParentHash(common.ZONE_CTX)
	regionHash := pending.ParentHash(common.REGION_CTX)
	primeTip := pending.ParentHash(common.PRIME_CTX)
	if zoneHash == (common.Hash{}) || regionHash == (common.Hash{}) || primeTip == (common.Hash{}) {
		return nil, fmt.Errorf("%w: zone=%s region=%s prime=%s", ErrTemplateHierarchyProofMissingContext, zoneHash.Hex(), regionHash.Hex(), primeTip.Hex())
	}

	req, err := templateHierarchyProofRequest(ctx, source, zoneHash, regionHash, primeTip, opts.PrimeAnchor, m, limits)
	if err != nil {
		return nil, err
	}
	proof, err := CollectHierarchyProofWithContext(ctx, source, req)
	if err != nil {
		return nil, err
	}
	return &TemplateHierarchyProof{
		TemplateHash:       pending.Hash(),
		TemplateSealHash:   pending.SealHash(),
		TemplateParentHash: zoneHash,
		Request:            req,
		Proof:              proof,
	}, nil
}

func templateHierarchyProofRequest(ctx context.Context, source HierarchyProofSource, zoneHash common.Hash, regionHash common.Hash, primeTip common.Hash, primeAnchor common.Hash, m uint64, limits BuildLimits) (HierarchyProofRequest, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if templateDirectManifestsContain(ctx, source, zoneHash, regionHash, primeTip) {
		return buildTemplateHierarchyProofRequest(source, zoneHash, regionHash, primeTip, primeAnchor, m, limits)
	}
	return selectManifestBackedTemplateRequest(ctx, source, zoneHash, regionHash, primeTip, primeAnchor, m, limits)
}

func buildTemplateHierarchyProofRequest(source HierarchyProofSource, zoneHash common.Hash, regionHash common.Hash, primeTip common.Hash, primeAnchor common.Hash, m uint64, limits BuildLimits) (HierarchyProofRequest, error) {
	if primeAnchor == (common.Hash{}) {
		anchor, err := deriveTemplatePrimeAnchor(source, zoneHash, regionHash)
		if err != nil {
			return HierarchyProofRequest{}, err
		}
		primeAnchor = anchor
	}
	return HierarchyProofRequest{
		ZoneHash:    zoneHash,
		RegionHash:  regionHash,
		PrimeAnchor: primeAnchor,
		PrimeTip:    primeTip,
		M:           m,
		Limits:      limits,
	}, nil
}

func templateDirectManifestsContain(ctx context.Context, source HierarchyProofSource, zoneHash common.Hash, regionHash common.Hash, primeTip common.Hash) bool {
	if err := ctx.Err(); err != nil {
		return false
	}
	regionManifest, err := source.Manifest(regionHash, common.REGION_CTX)
	if err != nil || !manifestContainsHash(regionManifest, zoneHash) {
		return false
	}
	if err := ctx.Err(); err != nil {
		return false
	}
	primeManifest, err := source.Manifest(primeTip, common.PRIME_CTX)
	return err == nil && manifestContainsHash(primeManifest, regionHash)
}

func selectManifestBackedTemplateRequest(ctx context.Context, source HierarchyProofSource, zoneHash common.Hash, regionHash common.Hash, primeTip common.Hash, primeAnchor common.Hash, m uint64, limits BuildLimits) (HierarchyProofRequest, error) {
	if err := verifyTemplateContextPointers(source, zoneHash, regionHash, primeTip); err != nil {
		return HierarchyProofRequest{}, err
	}
	primeManifest, err := source.Manifest(primeTip, common.PRIME_CTX)
	if err != nil {
		return HierarchyProofRequest{}, fmt.Errorf("%w: prime context manifest: %v", ErrTemplateHierarchyProofMissingBacking, err)
	}
	candidateRegions := templateRegionCandidates(source, regionHash, primeManifest)
	// Bound fallback iterations to prevent excessive source calls.
	maxIterations := DefaultMaxTemplateFallbackIter
	iterations := 0
	for _, candidateRegion := range candidateRegions {
		if err := ctx.Err(); err != nil {
			return HierarchyProofRequest{}, err
		}
		if !manifestContainsHash(primeManifest, candidateRegion) {
			continue
		}
		manifest, err := source.Manifest(candidateRegion, common.REGION_CTX)
		if err != nil {
			continue
		}
		for _, candidateZone := range manifest {
			iterations++
			if iterations > maxIterations {
				return HierarchyProofRequest{}, fmt.Errorf("%w: exceeded %d fallback iterations (zone=%s region=%s prime=%s)", ErrTemplateHierarchyProofMissingBacking, maxIterations, zoneHash.Hex(), regionHash.Hex(), primeTip.Hex())
			}
			if err := ctx.Err(); err != nil {
				return HierarchyProofRequest{}, err
			}
			zoneHeader, err := source.Header(candidateZone, common.ZONE_CTX)
			if err != nil || zoneHeader == nil || zoneHeader.Location().Context() != common.ZONE_CTX {
				continue
			}
			regionHeader, err := source.Header(candidateRegion, common.REGION_CTX)
			if err != nil || regionHeader == nil || zoneHeader.Location().Region() != regionHeader.Location().Region() {
				continue
			}
			return buildTemplateHierarchyProofRequest(source, candidateZone, candidateRegion, primeTip, primeAnchor, m, limits)
		}
	}
	return HierarchyProofRequest{}, fmt.Errorf("%w: zone=%s region=%s prime=%s", ErrTemplateHierarchyProofMissingBacking, zoneHash.Hex(), regionHash.Hex(), primeTip.Hex())
}

func verifyTemplateContextPointers(source HierarchyProofSource, zoneHash common.Hash, regionHash common.Hash, primeTip common.Hash) error {
	zoneHeader, err := source.Header(zoneHash, common.ZONE_CTX)
	if err != nil {
		return fmt.Errorf("%w: zone parent: %v", ErrTemplateHierarchyProofMissingBacking, err)
	}
	if zoneHeader.ParentHash(common.REGION_CTX) != regionHash {
		return fmt.Errorf("%w: zone parent region context mismatch got=%s want=%s", ErrTemplateHierarchyProofMissingBacking, zoneHeader.ParentHash(common.REGION_CTX).Hex(), regionHash.Hex())
	}
	if zoneHeader.ParentHash(common.PRIME_CTX) != primeTip {
		return fmt.Errorf("%w: zone parent prime context mismatch got=%s want=%s", ErrTemplateHierarchyProofMissingBacking, zoneHeader.ParentHash(common.PRIME_CTX).Hex(), primeTip.Hex())
	}
	if _, err := source.Header(regionHash, common.REGION_CTX); err != nil {
		return fmt.Errorf("%w: region context: %v", ErrTemplateHierarchyProofMissingBacking, err)
	}
	if _, err := source.Header(primeTip, common.PRIME_CTX); err != nil {
		return fmt.Errorf("%w: prime context: %v", ErrTemplateHierarchyProofMissingBacking, err)
	}
	return nil
}

func templateRegionCandidates(source HierarchyProofSource, regionHash common.Hash, primeManifest types.BlockManifest) []common.Hash {
	seen := make(map[common.Hash]struct{})
	candidates := make([]common.Hash, 0, len(primeManifest)+1)
	if regionHeader, err := source.Header(regionHash, common.REGION_CTX); err == nil && regionHeader != nil {
		parentRegion := regionHeader.ParentHash(common.REGION_CTX)
		if parentRegion != (common.Hash{}) {
			seen[parentRegion] = struct{}{}
			candidates = append(candidates, parentRegion)
		}
	}
	for _, hash := range primeManifest {
		if hash == (common.Hash{}) {
			continue
		}
		if _, ok := seen[hash]; ok {
			continue
		}
		seen[hash] = struct{}{}
		candidates = append(candidates, hash)
	}
	return candidates
}

func manifestContainsHash(manifest types.BlockManifest, hash common.Hash) bool {
	for _, entry := range manifest {
		if entry == hash {
			return true
		}
	}
	return false
}

func deriveTemplatePrimeAnchor(source HierarchyProofSource, zoneHash common.Hash, regionHash common.Hash) (common.Hash, error) {
	zone, err := source.Header(zoneHash, common.ZONE_CTX)
	if err != nil {
		return common.Hash{}, fmt.Errorf("zone anchor context: %w", err)
	}
	region, err := source.Header(regionHash, common.REGION_CTX)
	if err != nil {
		return common.Hash{}, fmt.Errorf("region anchor context: %w", err)
	}

	zoneTerminus := zone.PrimeTerminusHash()
	regionTerminus := region.PrimeTerminusHash()
	if zoneTerminus == (common.Hash{}) || regionTerminus == (common.Hash{}) {
		return common.Hash{}, fmt.Errorf("%w: zone=%s region=%s", ErrTemplateHierarchyProofMissingAnchor, zoneTerminus.Hex(), regionTerminus.Hex())
	}
	if zoneTerminus == regionTerminus {
		return zoneTerminus, nil
	}
	if primeTerminusNumber(zone) <= primeTerminusNumber(region) {
		return zoneTerminus, nil
	}
	return regionTerminus, nil
}

func primeTerminusNumber(header *types.WorkObject) uint64 {
	if header == nil || header.PrimeTerminusNumber() == nil {
		return ^uint64(0)
	}
	return header.PrimeTerminusNumber().Uint64()
}
