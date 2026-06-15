package types

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/dominant-strategies/go-quai/common"
)

func TestHeaderMarshalJSONIncludesManifestHashArray(t *testing.T) {
	raw, err := json.Marshal(EmptyHeader())
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("unmarshal header json object: %v", err)
	}
	manifestRaw := fields["manifestHash"]
	if string(manifestRaw) == "null" || len(manifestRaw) == 0 {
		t.Fatalf("manifestHash should be a %d-entry array, got %s", common.HierarchyDepth, string(manifestRaw))
	}
	var manifestHashes []common.Hash
	if err := json.Unmarshal(manifestRaw, &manifestHashes); err != nil {
		t.Fatalf("decode manifestHash: %v", err)
	}
	if len(manifestHashes) != common.HierarchyDepth {
		t.Fatalf("manifestHash length mismatch: want %d got %d", common.HierarchyDepth, len(manifestHashes))
	}
}

func TestPowShareDiffAndCountMarshalJSONIncludesFields(t *testing.T) {
	raw, err := json.Marshal(NewPowShareDiffAndCount(big.NewInt(1), big.NewInt(2), big.NewInt(3)))
	if err != nil {
		t.Fatalf("marshal pow share diff/count: %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("decode pow share diff/count JSON: %v", err)
	}
	for _, name := range []string{"difficulty", "count", "uncled"} {
		if len(fields[name]) == 0 || string(fields[name]) == "null" {
			t.Fatalf("expected %s field in pow share diff/count JSON, got %s", name, string(raw))
		}
	}
}

func TestAuxPowMarshalJSONIncludesRequiredFields(t *testing.T) {
	raw, err := json.Marshal(auxPowTestData(Kawpow))
	if err != nil {
		t.Fatalf("marshal auxpow: %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("decode auxpow JSON: %v", err)
	}
	for _, name := range []string{"powId", "header", "auxpow2", "signature", "merkleBranch", "transaction"} {
		if len(fields[name]) == 0 || string(fields[name]) == "null" {
			t.Fatalf("expected %s field in auxpow JSON, got %s", name, string(raw))
		}
	}
}
