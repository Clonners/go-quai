package nipopow

import (
	"errors"
	"testing"

	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/core/types"
)

func TestVerifyTemplateHierarchyProofArtifactAcceptsBoundTemplateProof(t *testing.T) {
	fixture := testHierarchyProof(t)
	artifact := testTemplateHierarchyProofArtifact(t, fixture)

	err := VerifyTemplateHierarchyProofArtifact(artifact, TemplateHierarchyProofVerificationOptions{
		ExpectedTemplateHash:       artifact.TemplateHash,
		ExpectedTemplateSealHash:   artifact.TemplateSealHash,
		ExpectedTemplateParentHash: artifact.TemplateParentHash,
	})
	if err != nil {
		t.Fatalf("expected template proof artifact to verify: %v", err)
	}
}

func TestVerifyTemplateHierarchyProofArtifactRejectsRequestBindingMismatch(t *testing.T) {
	artifact := testTemplateHierarchyProofArtifact(t, testHierarchyProof(t))
	artifact.Request.RegionHash = common.HexToHash("0x1234")

	err := VerifyTemplateHierarchyProofArtifact(artifact, TemplateHierarchyProofVerificationOptions{})
	if !errors.Is(err, ErrTemplateProofRequestMismatch) {
		t.Fatalf("expected request mismatch, got %v", err)
	}
}

func TestVerifyTemplateHierarchyProofArtifactRejectsExpectedTemplateHashMismatch(t *testing.T) {
	artifact := testTemplateHierarchyProofArtifact(t, testHierarchyProof(t))

	err := VerifyTemplateHierarchyProofArtifact(artifact, TemplateHierarchyProofVerificationOptions{
		ExpectedTemplateHash: common.HexToHash("0xbeef"),
	})
	if !errors.Is(err, ErrTemplateProofTemplateHashMismatch) {
		t.Fatalf("expected template hash mismatch, got %v", err)
	}
}

func TestVerifyTemplateHierarchyProofArtifactRejectsMissingHierarchyProof(t *testing.T) {
	artifact := testTemplateHierarchyProofArtifact(t, testHierarchyProof(t))
	artifact.Proof = nil

	err := VerifyTemplateHierarchyProofArtifact(artifact, TemplateHierarchyProofVerificationOptions{})
	if !errors.Is(err, ErrTemplateProofMissingHierarchyProof) {
		t.Fatalf("expected missing hierarchy proof, got %v", err)
	}
}

func TestVerifyTemplateHierarchyProofArtifactRejectsTamperedManifest(t *testing.T) {
	artifact := testTemplateHierarchyProofArtifact(t, testHierarchyProof(t))
	artifact.Proof.RegionHeader.Body().SetManifest(types.BlockManifest{common.HexToHash("0xabc")})
	setHierarchyManifestCommitment(t, artifact.Proof.RegionHeader, common.REGION_CTX)

	err := VerifyTemplateHierarchyProofArtifact(artifact, TemplateHierarchyProofVerificationOptions{})
	if !errors.Is(err, ErrHierarchyManifestMissingHash) {
		t.Fatalf("expected hierarchy manifest failure, got %v", err)
	}
}

func testTemplateHierarchyProofArtifact(t *testing.T, fixture *HierarchyProof) *TemplateHierarchyProof {
	t.Helper()

	pending := testZoneTemplatePendingHeader(t, fixture)
	return &TemplateHierarchyProof{
		TemplateHash:       pending.Hash(),
		TemplateSealHash:   pending.SealHash(),
		TemplateParentHash: pending.ParentHash(common.ZONE_CTX),
		Request: HierarchyProofRequest{
			ZoneHash:    fixture.ZoneHeader.Hash(),
			RegionHash:  fixture.RegionHeader.Hash(),
			PrimeAnchor: fixture.PrimeProof.Anchor,
			PrimeTip:    fixture.PrimeHeader.Hash(),
			M:           fixture.PrimeProof.M,
			Limits:      DefaultBuildLimits,
		},
		Proof: fixture,
	}
}
