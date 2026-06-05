package quaiapi

import (
	"context"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/core/nipopow"
	"github.com/dominant-strategies/go-quai/core/types"
	"github.com/dominant-strategies/go-quai/log"
)

type blockTemplateNiPoPoWBackend struct {
	Backend

	pending *types.WorkObject
	proof   *nipopow.TemplateHierarchyProof
	err     error

	pendingCalls       int
	proofCalls         int
	proofPending       *types.WorkObject
	proofOpts          nipopow.TemplateHierarchyProofOptions
	waitForContextDone bool
}

func (b *blockTemplateNiPoPoWBackend) GetPendingHeader(powID types.PowID, coinbase common.Address) (*types.WorkObject, error) {
	b.pendingCalls++
	if powID != types.Kawpow {
		return nil, errors.New("unexpected pow id")
	}
	return b.pending, nil
}

func (b *blockTemplateNiPoPoWBackend) GetBlockTemplateNiPoPoWProof(ctx context.Context, pending *types.WorkObject, opts nipopow.TemplateHierarchyProofOptions) (*nipopow.TemplateHierarchyProof, error) {
	b.proofCalls++
	b.proofPending = pending
	b.proofOpts = opts
	if b.waitForContextDone {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return b.proof, b.err
}

func (b *blockTemplateNiPoPoWBackend) Logger() *log.Logger {
	return log.Global
}

func TestGetBlockTemplateDoesNotIncludeNiPoPoWProofByDefault(t *testing.T) {
	pending := newBlockTemplateNiPoPoWTestWorkObject(types.Kawpow)
	backend := &blockTemplateNiPoPoWBackend{pending: pending}
	api := NewPublicBlockChainQuaiAPI(backend)

	result, err := api.GetBlockTemplate(context.Background(), &BlockTemplateRequest{Rules: []string{"kawpow"}})
	if err != nil {
		t.Fatalf("GetBlockTemplate returned error: %v", err)
	}
	if _, ok := result["nipopowProof"]; ok {
		t.Fatalf("default block template unexpectedly included nipopowProof")
	}
	if backend.proofCalls != 0 {
		t.Fatalf("default block template called proof builder %d times", backend.proofCalls)
	}
}

func TestGetBlockTemplateIncludesNiPoPoWProofWhenOptedIn(t *testing.T) {
	pending := newBlockTemplateNiPoPoWTestWorkObject(types.Kawpow)
	proof := &nipopow.TemplateHierarchyProof{
		TemplateHash:       pending.Hash(),
		TemplateSealHash:   pending.SealHash(),
		TemplateParentHash: pending.ParentHash(common.ZONE_CTX),
		Request: nipopow.HierarchyProofRequest{
			ZoneHash: pending.ParentHash(common.ZONE_CTX),
			M:        7,
		},
		Proof: &nipopow.HierarchyProof{},
	}
	backend := &blockTemplateNiPoPoWBackend{pending: pending, proof: proof}
	api := NewPublicBlockChainQuaiAPI(backend)

	anchor := common.Hash{0x99}
	result, err := api.GetBlockTemplate(context.Background(), &BlockTemplateRequest{
		Rules:              []string{"kawpow"},
		NiPoPoWProof:       true,
		NiPoPoWProofM:      7,
		NiPoPoWPrimeAnchor: anchor,
	})
	if err != nil {
		t.Fatalf("GetBlockTemplate returned error: %v", err)
	}
	got, ok := result["nipopowProof"]
	if !ok {
		t.Fatalf("opt-in block template missing nipopowProof")
	}
	if got != proof {
		t.Fatalf("unexpected nipopowProof payload: got %#v want %#v", got, proof)
	}
	if backend.proofCalls != 1 {
		t.Fatalf("proof builder calls=%d want 1", backend.proofCalls)
	}
	if backend.proofPending != pending {
		t.Fatalf("proof builder received wrong pending header")
	}
	if backend.proofOpts.M != 7 {
		t.Fatalf("proof builder M=%d want 7", backend.proofOpts.M)
	}
	if backend.proofOpts.PrimeAnchor != anchor {
		t.Fatalf("proof builder anchor=%s want %s", backend.proofOpts.PrimeAnchor.Hex(), anchor.Hex())
	}
}

func TestGetBlockTemplateNiPoPoWProofOptInPropagatesBuilderError(t *testing.T) {
	pending := newBlockTemplateNiPoPoWTestWorkObject(types.Kawpow)
	wantErr := errors.New("proof unavailable")
	backend := &blockTemplateNiPoPoWBackend{pending: pending, err: wantErr}
	api := NewPublicBlockChainQuaiAPI(backend)

	_, err := api.GetBlockTemplate(context.Background(), &BlockTemplateRequest{
		Rules:        []string{"kawpow"},
		NiPoPoWProof: true,
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("GetBlockTemplate error=%v want %v", err, wantErr)
	}
	if backend.proofCalls != 1 {
		t.Fatalf("proof builder calls=%d want 1", backend.proofCalls)
	}
}

func TestGetBlockTemplateNiPoPoWProofAppliesRequestBudgetPolicy(t *testing.T) {
	pending := newBlockTemplateNiPoPoWTestWorkObject(types.Kawpow)
	proof := &nipopow.TemplateHierarchyProof{TemplateHash: pending.Hash(), TemplateSealHash: pending.SealHash(), TemplateParentHash: pending.ParentHash(common.ZONE_CTX), Proof: &nipopow.HierarchyProof{}}
	backend := &blockTemplateNiPoPoWBackend{pending: pending, proof: proof}
	api := NewPublicBlockChainQuaiAPI(backend)
	api.nipopowTemplateProofPolicy = BlockTemplateNiPoPoWRequestPolicy{
		BuildTimeout:       250 * time.Millisecond,
		MaxM:               32,
		MaxChainLength:     123,
		MaxProofHeaders:    45,
		MaxManifestHashes:  67,
		MaxSerializedBytes: 1024 * 1024,
	}

	_, err := api.GetBlockTemplate(context.Background(), &BlockTemplateRequest{
		Rules:        []string{"kawpow"},
		NiPoPoWProof: true,
	})
	if err != nil {
		t.Fatalf("GetBlockTemplate returned error: %v", err)
	}
	if backend.proofCalls != 1 {
		t.Fatalf("proof builder calls=%d want 1", backend.proofCalls)
	}
	if backend.proofOpts.M != nipopow.DefaultTemplateHierarchyProofM {
		t.Fatalf("proof builder default M=%d want %d", backend.proofOpts.M, nipopow.DefaultTemplateHierarchyProofM)
	}
	if backend.proofOpts.Limits.MaxChainLength != 123 || backend.proofOpts.Limits.MaxProofHeaders != 45 || backend.proofOpts.Limits.MaxM != 32 {
		t.Fatalf("unexpected proof limits: %+v", backend.proofOpts.Limits)
	}
}

func TestGetBlockTemplateNiPoPoWProofRejectsMAbovePolicyBeforeBuilder(t *testing.T) {
	pending := newBlockTemplateNiPoPoWTestWorkObject(types.Kawpow)
	backend := &blockTemplateNiPoPoWBackend{pending: pending}
	api := NewPublicBlockChainQuaiAPI(backend)
	api.nipopowTemplateProofPolicy = BlockTemplateNiPoPoWRequestPolicy{MaxM: 4}

	_, err := api.GetBlockTemplate(context.Background(), &BlockTemplateRequest{
		Rules:         []string{"kawpow"},
		NiPoPoWProof:  true,
		NiPoPoWProofM: 5,
	})
	if !errors.Is(err, ErrBlockTemplateNiPoPoWProofBudgetExceeded) {
		t.Fatalf("GetBlockTemplate error=%v want %v", err, ErrBlockTemplateNiPoPoWProofBudgetExceeded)
	}
	if backend.proofCalls != 0 {
		t.Fatalf("proof builder calls=%d want 0", backend.proofCalls)
	}
}

func TestGetBlockTemplateNiPoPoWProofHonorsTimeout(t *testing.T) {
	pending := newBlockTemplateNiPoPoWTestWorkObject(types.Kawpow)
	backend := &blockTemplateNiPoPoWBackend{pending: pending, waitForContextDone: true}
	api := NewPublicBlockChainQuaiAPI(backend)
	api.nipopowTemplateProofPolicy = BlockTemplateNiPoPoWRequestPolicy{BuildTimeout: time.Nanosecond}

	_, err := api.GetBlockTemplate(context.Background(), &BlockTemplateRequest{
		Rules:        []string{"kawpow"},
		NiPoPoWProof: true,
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("GetBlockTemplate error=%v want deadline exceeded", err)
	}
	if backend.proofCalls != 1 {
		t.Fatalf("proof builder calls=%d want 1", backend.proofCalls)
	}
}

func TestGetBlockTemplateNiPoPoWProofRejectsOversizedSerializedProof(t *testing.T) {
	pending := newBlockTemplateNiPoPoWTestWorkObject(types.Kawpow)
	proof := &nipopow.TemplateHierarchyProof{TemplateHash: pending.Hash(), TemplateSealHash: pending.SealHash(), TemplateParentHash: pending.ParentHash(common.ZONE_CTX), Proof: &nipopow.HierarchyProof{}}
	backend := &blockTemplateNiPoPoWBackend{pending: pending, proof: proof}
	api := NewPublicBlockChainQuaiAPI(backend)
	api.nipopowTemplateProofPolicy = BlockTemplateNiPoPoWRequestPolicy{MaxSerializedBytes: 1}

	_, err := api.GetBlockTemplate(context.Background(), &BlockTemplateRequest{
		Rules:        []string{"kawpow"},
		NiPoPoWProof: true,
	})
	if !errors.Is(err, ErrBlockTemplateNiPoPoWProofBudgetExceeded) {
		t.Fatalf("GetBlockTemplate error=%v want %v", err, ErrBlockTemplateNiPoPoWProofBudgetExceeded)
	}
	if backend.proofCalls != 1 {
		t.Fatalf("proof builder calls=%d want 1", backend.proofCalls)
	}
}

func newBlockTemplateNiPoPoWTestWorkObject(powID types.PowID) *types.WorkObject {
	auxMerkleRoot := common.Hash{0xaa}
	coinbaseOut := []byte{0x00, 0x00, 0x00, 0x00, 0x00} // zero outputs + locktime
	auxTx := types.NewAuxPowCoinbaseTx(powID, 1234, coinbaseOut, auxMerkleRoot, 1700000000)
	auxHeader := types.NewBlockHeader(powID, 1, [32]byte{0x11}, [32]byte{0x22}, 1700000000, 0x1b0127c1, 0, 1234)
	auxPow := types.NewAuxPow(powID, auxHeader, nil, nil, nil, auxTx)

	woHeader := types.NewWorkObjectHeader(
		common.Hash{0x01},
		common.Hash{0x02},
		big.NewInt(1234),
		big.NewInt(1000),
		big.NewInt(3000001),
		common.Hash{0x03},
		types.BlockNonce{},
		0,
		1700000000,
		common.Location{0, 0},
		common.Address{},
		nil,
		auxPow,
		types.NewPowShareDiffAndCount(big.NewInt(1), big.NewInt(1), big.NewInt(0)),
		types.NewPowShareDiffAndCount(big.NewInt(1), big.NewInt(1), big.NewInt(0)),
		big.NewInt(10),
		big.NewInt(20),
		big.NewInt(1000000000),
	)
	return types.NewWorkObject(woHeader, types.EmptyWorkObjectBody(), nil)
}
