package tproxy

import (
	"context"
	"fmt"
	"os/exec"
	"sort"
	"strconv"
	"strings"
)

// firewallTable is a dedicated nftables table this package owns exclusively --
// applying it never touches any rule an admin or another part of the panel
// manages, and removing it (StopAll, or the port list going empty) never
// leaves a stray table behind for a future nft ruleset dump to explain.
const firewallTable = "tproxy_backend"

// ensureFirewall blocks every non-loopback source from reaching the given
// MTProxy client ports, mirroring upstream tproxy-server's own reference
// deploy/firewall.nft. MTProxy's -H listener binds every interface by design
// (confirmed in that same reference: their own nftables table exists for
// exactly this reason) -- without this, anyone who portscans the host finds a
// second, uncloaked way to reach the proxy that never goes through
// frontproxy's capability check at all, defeating the single-domain design
// this feature exists for. Called with the full current port set on every
// change, never incrementally, so a crashed-and-recovered process can never
// leave a stale hole open.
func ensureFirewall(ctx context.Context, ports []int) error {
	return applyFirewall(ctx, ports)
}

// removeFirewall deletes the table this package owns. Best-effort and
// idempotent for the same reason as the delete step inside applyFirewallViaNft.
func removeFirewall(ctx context.Context) {
	_ = applyFirewall(ctx, nil)
}

// applyFirewall is indirected so tests can replace the real nft invocation --
// exercising the Manager's own logic for *when* and *with which ports* this
// gets called does not need a real nft binary or root, and CI/dev machines
// cannot be assumed to have either.
var applyFirewall = applyFirewallViaNft

func applyFirewallViaNft(ctx context.Context, ports []int) error {
	nft, err := exec.LookPath("nft")
	if err != nil {
		return fmt.Errorf("nft (nftables) is required to safely expose an MTProxy backend port and was not found in PATH: %w", err)
	}

	// Best-effort, matching the reference unit's own `ExecStart=-nft delete
	// table ...`: an absent table is the common case, not an error, and nft's
	// own message for it is not a stable string worth parsing.
	_ = exec.CommandContext(ctx, nft, "delete", "table", "inet", firewallTable).Run()

	if len(ports) == 0 {
		return nil
	}

	cmd := exec.CommandContext(ctx, nft, "-f", "-")
	cmd.Stdin = strings.NewReader(renderFirewallRuleset(ports))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft -f: %w: %s", err, string(out))
	}
	return nil
}

// renderFirewallRuleset builds the nft(8) script text for the given ports,
// deduplicated and sorted so the output is stable across calls with the same
// set. Pure and side-effect-free so it is unit-testable without root or nft.
func renderFirewallRuleset(ports []int) string {
	unique := make(map[int]struct{}, len(ports))
	for _, p := range ports {
		unique[p] = struct{}{}
	}
	sorted := make([]int, 0, len(unique))
	for p := range unique {
		sorted = append(sorted, p)
	}
	sort.Ints(sorted)

	strs := make([]string, len(sorted))
	for i, p := range sorted {
		strs[i] = strconv.Itoa(p)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s {\n", firewallTable)
	b.WriteString("\tchain local_backend {\n")
	b.WriteString("\t\ttype filter hook input priority -10; policy accept;\n")
	fmt.Fprintf(&b, "\t\tiifname != \"lo\" tcp dport { %s } drop\n", strings.Join(strs, ", "))
	b.WriteString("\t}\n")
	b.WriteString("}\n")
	return b.String()
}
