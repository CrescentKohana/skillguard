package rules_test

import (
	"testing"

	"github.com/CrescentKohana/skillguard/internal/rules"
)

func TestAllAndLookupReturnIndependentCopies(t *testing.T) {
	all := rules.All()
	original := all[0].OWASP[0]
	all[0].OWASP[0] = "mutated"
	all[0].ATLAS[0] = "mutated"
	fresh := rules.All()[0]
	if fresh.OWASP[0] != original || fresh.ATLAS[0] == "mutated" {
		t.Fatalf("mutating All()'s result changed the catalogue: OWASP=%v ATLAS=%v", fresh.OWASP, fresh.ATLAS)
	}

	r, ok := rules.Lookup(all[0].ID)
	if !ok {
		t.Fatal("Lookup failed")
	}
	r.OWASP[0] = "mutated"
	r.ATLAS[0] = "mutated"
	if got, _ := rules.Lookup(all[0].ID); got.OWASP[0] != original || got.ATLAS[0] == "mutated" {
		t.Fatalf("mutating Lookup's result changed the catalogue: OWASP=%v ATLAS=%v", got.OWASP, got.ATLAS)
	}
}
