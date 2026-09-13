package tproxy

import (
	"strings"
	"testing"
)

func TestRenderFirewallRulesetDedupesAndSorts(t *testing.T) {
	got := renderFirewallRuleset([]int{2398, 8888, 2398, 43210})
	if !strings.Contains(got, "{ 2398, 8888, 43210 }") {
		t.Errorf("ruleset = %q, want a sorted, deduplicated port set", got)
	}
	if !strings.Contains(got, "table inet "+firewallTable) {
		t.Errorf("ruleset = %q, want it to declare table %q", got, firewallTable)
	}
	if !strings.Contains(got, `iifname != "lo"`) {
		t.Errorf("ruleset = %q, must restrict to non-loopback interfaces only", got)
	}
	if !strings.Contains(got, "drop") {
		t.Errorf("ruleset = %q, must drop matching traffic", got)
	}
}

func TestRenderFirewallRulesetSingleValue(t *testing.T) {
	got := renderFirewallRuleset([]int{2398})
	if !strings.Contains(got, "{ 2398 }") {
		t.Errorf("ruleset = %q, want a single-element set", got)
	}
}
