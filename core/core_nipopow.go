package core

import (
	"context"
	"fmt"

	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/core/nipopow"
	"github.com/dominant-strategies/go-quai/core/types"
)

// GetNiPoPoWProof builds a read-only Prime NiPoPoW proof for RPC callers.
func (c *Core) GetNiPoPoWProof(ctx context.Context, anchor common.Hash, tip common.Hash, m uint64) (*nipopow.Proof, error) {
	return c.sl.hc.BuildPrimeNiPoPoWProof(ctx, anchor, tip, m)
}

func (c *Core) GetNiPoPoWProofHeader(blockHash common.Hash) (*types.WorkObject, error) {
	return c.sl.GetNiPoPoWProofHeader(blockHash)
}

func (c *Core) GetHierarchyBlock(blockHash common.Hash, nodeCtx int) *types.WorkObject {
	return c.sl.GetHierarchyBlock(blockHash, nodeCtx)
}

func (c *Core) GetHierarchyManifest(blockHash common.Hash, nodeCtx int) (types.BlockManifest, error) {
	return c.sl.GetHierarchyManifest(blockHash, nodeCtx)
}

// GetBlockTemplateNiPoPoWProof builds a shadow-mode hierarchy proof for the
// canonical Zone/Region/Prime context backing a Zone mining template. It does
// not mutate state and does not change the public template payload.
func (c *Core) GetBlockTemplateNiPoPoWProof(ctx context.Context, pending *types.WorkObject, opts nipopow.TemplateHierarchyProofOptions) (*nipopow.TemplateHierarchyProof, error) {
	return nipopow.BuildTemplateHierarchyProofWithContext(ctx, coreTemplateHierarchySource{core: c}, pending, opts)
}

type coreTemplateHierarchySource struct {
	core *Core
}

func (s coreTemplateHierarchySource) Header(hash common.Hash, nodeCtx int) (*types.WorkObject, error) {
	if s.core == nil {
		return nil, nipopow.ErrNilHierarchySource
	}
	header := s.core.GetHierarchyBlock(hash, nodeCtx)
	if header == nil {
		return nil, fmt.Errorf("hierarchy header not found: ctx=%d hash=%s", nodeCtx, hash.Hex())
	}
	return types.CopyWorkObject(header), nil
}

func (s coreTemplateHierarchySource) Manifest(hash common.Hash, nodeCtx int) (types.BlockManifest, error) {
	if s.core == nil {
		return nil, nipopow.ErrNilHierarchySource
	}
	manifest, err := s.core.GetHierarchyManifest(hash, nodeCtx)
	if err != nil {
		return nil, err
	}
	return append(types.BlockManifest(nil), manifest...), nil
}

func (s coreTemplateHierarchySource) ProofHeader(hash common.Hash) (*types.WorkObject, error) {
	if s.core == nil {
		return nil, nipopow.ErrNilHierarchySource
	}
	return s.core.GetNiPoPoWProofHeader(hash)
}
