package main

import (
	"errors"
	"testing"
)

func TestExtractTemplateProofRejectsMissingOptInProof(t *testing.T) {
	_, _, _, err := extractTemplateProof([]byte(`{"blockTemplateResponse":{"height":1}}`))
	if !errors.Is(err, errMissingNiPoPoWProof) {
		t.Fatalf("expected missing nipopowProof error, got %v", err)
	}
}
