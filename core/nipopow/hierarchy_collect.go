package nipopow

import (
	"context"
	"errors"
	"fmt"

	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/core/types"
)

var (
	ErrNilHierarchySource          = errors.New("nil nipopow hierarchy source")
	ErrHierarchyHeaderHashMismatch = errors.New("nipopow hierarchy source returned header hash mismatch")
	ErrHierarchyMissingManifest    = errors.New("nipopow hierarchy source missing manifest")
)

// HierarchyProofRequest identifies the already-persisted Zone/Region/Prime
// objects needed to collect a read-only hierarchy wrapper.
type HierarchyProofRequest struct {
	ZoneHash    common.Hash `json:"zoneHash"`
	RegionHash  common.Hash `json:"regionHash"`
	PrimeAnchor common.Hash `json:"primeAnchor"`
	PrimeTip    common.Hash `json:"primeTip"`
	M           uint64      `json:"m"`
	Limits      BuildLimits `json:"limits"`
}

// HierarchyProofSource is the read-only data seam for collecting hierarchy
// wrappers from chain storage, fixtures, or future block-template sources.
type HierarchyProofSource interface {
	PrimeProofSource
	Header(hash common.Hash, nodeCtx int) (*types.WorkObject, error)
	Manifest(hash common.Hash, nodeCtx int) (types.BlockManifest, error)
}

// CollectHierarchyProof collects a hierarchy proof using default context.
func CollectHierarchyProof(source HierarchyProofSource, req HierarchyProofRequest) (*HierarchyProof, error) {
	return CollectHierarchyProofWithContext(context.Background(), source, req)
}

// CollectHierarchyProofWithContext builds a read-only hierarchy wrapper from a
// caller-supplied source and then verifies it before returning.
func CollectHierarchyProofWithContext(ctx context.Context, source HierarchyProofSource, req HierarchyProofRequest) (*HierarchyProof, error) {
	if source == nil {
		return nil, ErrNilHierarchySource
	}
	if ctx == nil {
		ctx = context.Background()
	}

	zone, err := collectHierarchyHeaderWithManifest(source, req.ZoneHash, common.ZONE_CTX, false)
	if err != nil {
		return nil, fmt.Errorf("zone: %w", err)
	}
	region, err := collectHierarchyHeaderWithManifest(source, req.RegionHash, common.REGION_CTX, true)
	if err != nil {
		return nil, fmt.Errorf("region: %w", err)
	}
	prime, err := collectHierarchyHeaderWithManifest(source, req.PrimeTip, common.PRIME_CTX, true)
	if err != nil {
		return nil, fmt.Errorf("prime: %w", err)
	}

	proof, err := BuildPrimeProofWithContext(ctx, source, req.PrimeAnchor, req.PrimeTip, req.M, req.Limits)
	if err != nil {
		return nil, fmt.Errorf("prime proof: %w", err)
	}
	wrapper := &HierarchyProof{
		ZoneHeader:   zone,
		RegionHeader: region,
		PrimeHeader:  prime,
		PrimeProof:   proof,
	}
	if err := VerifyHierarchyProof(wrapper); err != nil {
		return nil, err
	}
	return wrapper, nil
}

func collectHierarchyHeaderWithManifest(source HierarchyProofSource, hash common.Hash, nodeCtx int, needManifest bool) (*types.WorkObject, error) {
	header, err := source.Header(hash, nodeCtx)
	if err != nil {
		return nil, err
	}
	if header == nil {
		return nil, ErrNilHeader
	}
	if header.Hash() != hash {
		return nil, fmt.Errorf("%w: ctx=%d requested=%s got=%s", ErrHierarchyHeaderHashMismatch, nodeCtx, hash.Hex(), header.Hash().Hex())
	}
	header = types.CopyWorkObject(header)
	if !needManifest {
		return header, nil
	}
	manifest, err := source.Manifest(hash, nodeCtx)
	if err != nil {
		return nil, fmt.Errorf("%w: ctx=%d hash=%s: %v", ErrHierarchyMissingManifest, nodeCtx, hash.Hex(), err)
	}
	if manifest == nil {
		return nil, fmt.Errorf("%w: ctx=%d hash=%s", ErrHierarchyMissingManifest, nodeCtx, hash.Hex())
	}
	header.Body().SetManifest(append(types.BlockManifest(nil), manifest...))
	return header, nil
}
