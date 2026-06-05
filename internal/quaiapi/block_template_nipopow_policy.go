package quaiapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/dominant-strategies/go-quai/core/nipopow"
	"github.com/dominant-strategies/go-quai/core/types"
	"github.com/dominant-strategies/go-quai/log"
)

const (
	DefaultBlockTemplateNiPoPoWProofTimeout        = 2 * time.Second
	DefaultBlockTemplateNiPoPoWProofMaxM           = 64
	DefaultBlockTemplateNiPoPoWProofMaxManifestLen = 512
	DefaultBlockTemplateNiPoPoWProofMaxBytes       = 1 * 1024 * 1024
)

var ErrBlockTemplateNiPoPoWProofBudgetExceeded = errors.New("nipopow block template proof exceeds request budget policy")

// BlockTemplateNiPoPoWRequestPolicy defines the deployment safety envelope for
// explicit opt-in block-template proof requests. Zero values are normalized to
// conservative defaults so the default block-template response remains unchanged
// while opted-in proof generation is bounded by timeout, proof-walk limits, and
// serialized response size.
type BlockTemplateNiPoPoWRequestPolicy struct {
	BuildTimeout       time.Duration
	MaxM               uint64
	MaxChainLength     uint64
	MaxProofHeaders    uint64
	MaxManifestHashes  uint64
	MaxSerializedBytes uint64
}

// BlockTemplateNiPoPoWProofBudgetStats records the proof-size fields that are
// useful for operator logs and shadow-mode evidence.
type BlockTemplateNiPoPoWProofBudgetStats struct {
	PrimeProofHeaders uint64 `json:"primeProofHeaders"`
	RegionManifestLen uint64 `json:"regionManifestLen"`
	PrimeManifestLen  uint64 `json:"primeManifestLen"`
	SerializedBytes   uint64 `json:"serializedBytes"`
}

func (p BlockTemplateNiPoPoWRequestPolicy) withDefaults() BlockTemplateNiPoPoWRequestPolicy {
	if p.BuildTimeout == 0 {
		p.BuildTimeout = DefaultBlockTemplateNiPoPoWProofTimeout
	}
	if p.MaxM == 0 {
		p.MaxM = DefaultBlockTemplateNiPoPoWProofMaxM
	}
	if p.MaxChainLength == 0 {
		p.MaxChainLength = nipopow.DefaultMaxProofChainLength
	}
	if p.MaxProofHeaders == 0 {
		p.MaxProofHeaders = nipopow.DefaultMaxProofHeaders
	}
	if p.MaxManifestHashes == 0 {
		p.MaxManifestHashes = DefaultBlockTemplateNiPoPoWProofMaxManifestLen
	}
	if p.MaxSerializedBytes == 0 {
		p.MaxSerializedBytes = DefaultBlockTemplateNiPoPoWProofMaxBytes
	}
	return p
}

func (p BlockTemplateNiPoPoWRequestPolicy) buildLimits() nipopow.BuildLimits {
	return nipopow.BuildLimits{
		MaxChainLength:  p.MaxChainLength,
		MaxProofHeaders: p.MaxProofHeaders,
		MaxM:            p.MaxM,
	}
}

func (p BlockTemplateNiPoPoWRequestPolicy) requestedM(request *BlockTemplateRequest) (uint64, error) {
	m := uint64(0)
	if request != nil {
		m = request.NiPoPoWProofM
	}
	if m == 0 {
		m = nipopow.DefaultTemplateHierarchyProofM
	}
	if m > p.MaxM {
		return 0, fmt.Errorf("%w: requested m %d exceeds max %d", ErrBlockTemplateNiPoPoWProofBudgetExceeded, m, p.MaxM)
	}
	return m, nil
}

func (s *PublicBlockChainQuaiAPI) blockTemplateNiPoPoWPolicy() BlockTemplateNiPoPoWRequestPolicy {
	if s == nil {
		return BlockTemplateNiPoPoWRequestPolicy{}.withDefaults()
	}
	return s.nipopowTemplateProofPolicy.withDefaults()
}

func (s *PublicBlockChainQuaiAPI) buildBlockTemplateNiPoPoWProof(ctx context.Context, pending *types.WorkObject, request *BlockTemplateRequest) (*nipopow.TemplateHierarchyProof, error) {
	policy := s.blockTemplateNiPoPoWPolicy()
	m, err := policy.requestedM(request)
	if err != nil {
		s.logBlockTemplateNiPoPoWProofRequest(BlockTemplateNiPoPoWProofBudgetStats{}, 0, err)
		return nil, err
	}

	if ctx == nil {
		ctx = context.Background()
	}
	proofCtx := ctx
	cancel := func() {}
	if policy.BuildTimeout > 0 {
		proofCtx, cancel = context.WithTimeout(ctx, policy.BuildTimeout)
	}
	defer cancel()

	opts := nipopow.TemplateHierarchyProofOptions{
		M:      m,
		Limits: policy.buildLimits(),
	}
	if request != nil {
		opts.PrimeAnchor = request.NiPoPoWPrimeAnchor
	}

	started := time.Now()
	proof, err := s.b.GetBlockTemplateNiPoPoWProof(proofCtx, pending, opts)
	elapsed := time.Since(started)
	if err != nil {
		s.logBlockTemplateNiPoPoWProofRequest(BlockTemplateNiPoPoWProofBudgetStats{}, elapsed, err)
		return nil, err
	}

	stats, err := policy.validateProofBudget(proof)
	if err != nil {
		s.logBlockTemplateNiPoPoWProofRequest(stats, elapsed, err)
		return nil, err
	}
	s.logBlockTemplateNiPoPoWProofRequest(stats, elapsed, nil)
	return proof, nil
}

// ValidateBlockTemplateNiPoPoWProofBudget applies the same post-build size
// policy used by quai_getBlockTemplate opt-in requests. It is useful for
// shadow-mode evidence and offline deployment checks.
func ValidateBlockTemplateNiPoPoWProofBudget(proof *nipopow.TemplateHierarchyProof, policy BlockTemplateNiPoPoWRequestPolicy) (BlockTemplateNiPoPoWProofBudgetStats, error) {
	return policy.withDefaults().validateProofBudget(proof)
}

func (p BlockTemplateNiPoPoWRequestPolicy) validateProofBudget(proof *nipopow.TemplateHierarchyProof) (BlockTemplateNiPoPoWProofBudgetStats, error) {
	stats := BlockTemplateNiPoPoWProofBudgetStats{}
	if proof == nil {
		return stats, fmt.Errorf("%w: nil proof", ErrBlockTemplateNiPoPoWProofBudgetExceeded)
	}
	if proof.Proof != nil {
		if proof.Proof.PrimeProof != nil {
			stats.PrimeProofHeaders = uint64(len(proof.Proof.PrimeProof.Headers))
		}
		if proof.Proof.RegionHeader != nil {
			stats.RegionManifestLen = uint64(len(proof.Proof.RegionHeader.Manifest()))
		}
		if proof.Proof.PrimeHeader != nil {
			stats.PrimeManifestLen = uint64(len(proof.Proof.PrimeHeader.Manifest()))
		}
	}
	if stats.PrimeProofHeaders > p.MaxProofHeaders {
		return stats, fmt.Errorf("%w: prime proof headers %d exceeds max %d", ErrBlockTemplateNiPoPoWProofBudgetExceeded, stats.PrimeProofHeaders, p.MaxProofHeaders)
	}
	if stats.RegionManifestLen > p.MaxManifestHashes {
		return stats, fmt.Errorf("%w: region manifest hashes %d exceeds max %d", ErrBlockTemplateNiPoPoWProofBudgetExceeded, stats.RegionManifestLen, p.MaxManifestHashes)
	}
	if stats.PrimeManifestLen > p.MaxManifestHashes {
		return stats, fmt.Errorf("%w: prime manifest hashes %d exceeds max %d", ErrBlockTemplateNiPoPoWProofBudgetExceeded, stats.PrimeManifestLen, p.MaxManifestHashes)
	}
	encoded, err := json.Marshal(proof)
	if err != nil {
		return stats, err
	}
	stats.SerializedBytes = uint64(len(encoded))
	if stats.SerializedBytes > p.MaxSerializedBytes {
		return stats, fmt.Errorf("%w: serialized proof %d bytes exceeds max %d", ErrBlockTemplateNiPoPoWProofBudgetExceeded, stats.SerializedBytes, p.MaxSerializedBytes)
	}
	return stats, nil
}

func (s *PublicBlockChainQuaiAPI) logBlockTemplateNiPoPoWProofRequest(stats BlockTemplateNiPoPoWProofBudgetStats, elapsed time.Duration, err error) {
	if s == nil || s.b == nil {
		return
	}
	logger := s.b.Logger()
	if logger == nil {
		return
	}
	fields := log.Fields{
		"elapsedMs":         float64(elapsed.Microseconds()) / 1000.0,
		"serializedBytes":   stats.SerializedBytes,
		"primeProofHeaders": stats.PrimeProofHeaders,
		"regionManifestLen": stats.RegionManifestLen,
		"primeManifestLen":  stats.PrimeManifestLen,
	}
	if err != nil {
		fields["err"] = err.Error()
		logger.WithFields(fields).Warn("NiPoPoW block template proof request failed")
		return
	}
	logger.WithFields(fields).Debug("NiPoPoW block template proof request completed")
}
