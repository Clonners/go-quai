package main

import (
	"bytes"
	"testing"

	"github.com/dominant-strategies/go-quai/common"
)

func TestParseCLIRequiresReadOnlyDBsAndHashes(t *testing.T) {
	_, err := parseCLI(nil, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected missing flags to return an error")
	}
}

func TestParseCLIAcceptsExplicitHierarchyInputs(t *testing.T) {
	cfg, err := parseCLI([]string{
		"--prime.db", "/tmp/prime",
		"--region.db", "/tmp/region",
		"--zone.db", "/tmp/zone",
		"--zone-hash", common.HexToHash("0x01").Hex(),
		"--region-hash", common.HexToHash("0x02").Hex(),
		"--prime-anchor", common.HexToHash("0x03").Hex(),
		"--prime-tip", common.HexToHash("0x04").Hex(),
		"--m", "16",
	}, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("expected parse success: %v", err)
	}
	if cfg.PrimeDBPath != "/tmp/prime" || cfg.RegionDBPath != "/tmp/region" || cfg.ZoneDBPath != "/tmp/zone" {
		t.Fatalf("db paths not parsed: %+v", cfg)
	}
	if cfg.Request.ZoneHash != common.HexToHash("0x01") || cfg.Request.RegionHash != common.HexToHash("0x02") {
		t.Fatalf("hierarchy hashes not parsed: %+v", cfg.Request)
	}
	if cfg.Request.M != 16 {
		t.Fatalf("m not parsed: %+v", cfg.Request.M)
	}
}

func TestParseLocation(t *testing.T) {
	region, err := parseLocation("0", common.REGION_CTX)
	if err != nil {
		t.Fatalf("region parse: %v", err)
	}
	if region.Context() != common.REGION_CTX || region.Region() != 0 {
		t.Fatalf("bad region location: %v", region)
	}
	zone, err := parseLocation("0,0", common.ZONE_CTX)
	if err != nil {
		t.Fatalf("zone parse: %v", err)
	}
	if zone.Context() != common.ZONE_CTX || zone.Region() != 0 || zone.Zone() != 0 {
		t.Fatalf("bad zone location: %v", zone)
	}
}
