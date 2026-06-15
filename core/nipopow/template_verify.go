package nipopow

import (
	"errors"
	"fmt"

	"github.com/dominant-strategies/go-quai/common"
)

var (
	ErrTemplateProofMissing                 = errors.New("nipopow template proof missing")
	ErrTemplateProofMissingTemplateHash     = errors.New("nipopow template proof missing template hash")
	ErrTemplateProofMissingTemplateSealHash = errors.New("nipopow template proof missing template seal hash")
	ErrTemplateProofMissingTemplateParent   = errors.New("nipopow template proof missing template parent hash")
	ErrTemplateProofMissingHierarchyProof   = errors.New("nipopow template proof missing hierarchy proof")
	ErrTemplateProofTemplateHashMismatch    = errors.New("nipopow template proof template hash mismatch")
	ErrTemplateProofTemplateSealMismatch    = errors.New("nipopow template proof template seal hash mismatch")
	ErrTemplateProofTemplateParentMismatch  = errors.New("nipopow template proof template parent hash mismatch")
	ErrTemplateProofRequestMismatch         = errors.New("nipopow template proof request mismatch")
)

// TemplateHierarchyProofVerificationOptions lets an independent client bind an
// opt-in template proof artifact to template metadata learned outside the proof
// payload. Zero hashes are ignored so callers can verify standalone proof
// artifacts when only the opted-in block template response is available.
type TemplateHierarchyProofVerificationOptions struct {
	ExpectedTemplateHash       common.Hash
	ExpectedTemplateSealHash   common.Hash
	ExpectedTemplateParentHash common.Hash
}

// VerifyTemplateHierarchyProofArtifact validates an opt-in block-template
// NiPoPoW artifact without RPC or DB access. It checks the self-contained
// hierarchy proof, then binds the request fields to the embedded proof headers
// so a pool/client can reject copied, stale, or tampered proof payloads.
func VerifyTemplateHierarchyProofArtifact(artifact *TemplateHierarchyProof, opts TemplateHierarchyProofVerificationOptions) error {
	if artifact == nil {
		return ErrTemplateProofMissing
	}
	if artifact.TemplateHash == (common.Hash{}) {
		return ErrTemplateProofMissingTemplateHash
	}
	if artifact.TemplateSealHash == (common.Hash{}) {
		return ErrTemplateProofMissingTemplateSealHash
	}
	if artifact.TemplateParentHash == (common.Hash{}) {
		return ErrTemplateProofMissingTemplateParent
	}
	if opts.ExpectedTemplateHash != (common.Hash{}) && opts.ExpectedTemplateHash != artifact.TemplateHash {
		return fmt.Errorf("%w: expected %s got %s", ErrTemplateProofTemplateHashMismatch, opts.ExpectedTemplateHash.Hex(), artifact.TemplateHash.Hex())
	}
	if opts.ExpectedTemplateSealHash != (common.Hash{}) && opts.ExpectedTemplateSealHash != artifact.TemplateSealHash {
		return fmt.Errorf("%w: expected %s got %s", ErrTemplateProofTemplateSealMismatch, opts.ExpectedTemplateSealHash.Hex(), artifact.TemplateSealHash.Hex())
	}
	if opts.ExpectedTemplateParentHash != (common.Hash{}) && opts.ExpectedTemplateParentHash != artifact.TemplateParentHash {
		return fmt.Errorf("%w: expected %s got %s", ErrTemplateProofTemplateParentMismatch, opts.ExpectedTemplateParentHash.Hex(), artifact.TemplateParentHash.Hex())
	}
	if artifact.Proof == nil {
		return ErrTemplateProofMissingHierarchyProof
	}
	if err := VerifyHierarchyProof(artifact.Proof); err != nil {
		return err
	}
	if artifact.Request.ZoneHash != artifact.Proof.ZoneHeader.Hash() {
		return fmt.Errorf("%w: zone request %s proof %s", ErrTemplateProofRequestMismatch, artifact.Request.ZoneHash.Hex(), artifact.Proof.ZoneHeader.Hash().Hex())
	}
	if artifact.Request.RegionHash != artifact.Proof.RegionHeader.Hash() {
		return fmt.Errorf("%w: region request %s proof %s", ErrTemplateProofRequestMismatch, artifact.Request.RegionHash.Hex(), artifact.Proof.RegionHeader.Hash().Hex())
	}
	if artifact.Request.PrimeTip != artifact.Proof.PrimeHeader.Hash() {
		return fmt.Errorf("%w: prime tip request %s proof %s", ErrTemplateProofRequestMismatch, artifact.Request.PrimeTip.Hex(), artifact.Proof.PrimeHeader.Hash().Hex())
	}
	if artifact.Proof.PrimeProof == nil {
		return ErrTemplateProofMissingHierarchyProof
	}
	if artifact.Request.PrimeAnchor != (common.Hash{}) && artifact.Request.PrimeAnchor != artifact.Proof.PrimeProof.Anchor {
		return fmt.Errorf("%w: prime anchor request %s proof %s", ErrTemplateProofRequestMismatch, artifact.Request.PrimeAnchor.Hex(), artifact.Proof.PrimeProof.Anchor.Hex())
	}
	if artifact.Request.M != 0 && artifact.Request.M != artifact.Proof.PrimeProof.M {
		return fmt.Errorf("%w: m request %d proof %d", ErrTemplateProofRequestMismatch, artifact.Request.M, artifact.Proof.PrimeProof.M)
	}
	return nil
}
