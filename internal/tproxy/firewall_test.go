package tproxy

import (
	"strings"
	"testing"
)

func TestRenderFirewallRulesetDedupesAndSorts(t *testing.T) {
	got := renderFirewallRuleset([]int{2398, 8888, 2398, 43210}, false)
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
	if !strings.Contains(got, "ct state established,related accept") {
		t.Errorf("ruleset = %q, must accept established/related traffic so a recycled ephemeral port cannot black-hole this host's own outbound connections", got)
	}
}

func TestRenderFirewallRulesetSingleValue(t *testing.T) {
	got := renderFirewallRuleset([]int{2398}, false)
	if !strings.Contains(got, "{ 2398 }") {
		t.Errorf("ruleset = %q, want a single-element set", got)
	}
}

func TestRenderFirewallRulesetFlushPrefix(t *testing.T) {
	withoutFlush := renderFirewallRuleset([]int{2398}, false)
	if strings.Contains(withoutFlush, "flush") {
		t.Errorf("ruleset = %q, must not flush a table that may not exist yet (nft -f is atomic: flushing a missing table fails the whole script)", withoutFlush)
	}
	withFlush := renderFirewallRuleset([]int{2398}, true)
	if !strings.HasPrefix(withFlush, "flush table inet "+firewallTable+"\n") {
		t.Errorf("ruleset = %q, want it to flush the existing table before redefining it", withFlush)
	}
}
