package tproxy

import (
	"context"
	"fmt"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

// firewallTable is a dedicated nftables table this package owns exclusively,
// so applying or removing it never touches an admin's own rules.
const firewallTable = "tproxy_backend"

// firewallTimeout bounds every nft invocation -- Manager holds its own lock
// for the duration of each call.
const firewallTimeout = 5 * time.Second

// ensureFirewall blocks non-loopback access to the given MTProxy client
// ports (MTProxy's -H binds every interface); apply before the process starts.
func ensureFirewall(ctx context.Context, ports []int) error {
	return applyFirewall(ctx, ports)
}

// removeFirewall deletes the table this package owns. Best-effort and
// idempotent -- an absent table is the common case, not an error.
func removeFirewall(ctx context.Context) {
	nft, err := exec.LookPath("nft")
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, firewallTimeout)
	defer cancel()
	_ = exec.CommandContext(ctx, nft, "delete", "table", "inet", firewallTable).Run()
}

// applyFirewall is indirected so tests can replace the real nft invocation --
// exercising the Manager's own logic needs neither a real nft binary nor root.
var applyFirewall = applyFirewallViaNft

// applyFirewallViaNft replaces the whole table in one atomic nft -f
// transaction; whether to flush first depends on whether it already exists.
func applyFirewallViaNft(ctx context.Context, ports []int) error {
	nft, err := exec.LookPath("nft")
	if err != nil {
		return fmt.Errorf("nft (nftables) is required to safely expose an MTProxy backend port and was not found in PATH: %w", err)
	}
	if len(ports) == 0 {
		removeFirewall(ctx)
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, firewallTimeout)
	defer cancel()

	exists := exec.CommandContext(ctx, nft, "list", "table", "inet", firewallTable).Run() == nil
	cmd := exec.CommandContext(ctx, nft, "-f", "-")
	cmd.Stdin = strings.NewReader(renderFirewallRuleset(ports, exists))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft -f: %w: %s", err, string(out))
	}
	return nil
}

// renderFirewallRuleset builds the nft(8) script text, deduplicated and
// sorted. flushExisting must be true only when the table already exists.
func renderFirewallRuleset(ports []int, flushExisting bool) string {
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
	if flushExisting {
		fmt.Fprintf(&b, "flush table inet %s\n", firewallTable)
	}
	fmt.Fprintf(&b, "table inet %s {\n", firewallTable)
	b.WriteString("\tchain local_backend {\n")
	b.WriteString("\t\ttype filter hook input priority -10; policy accept;\n")
	// A recycled ephemeral port must not drop this host's own outbound replies.
	b.WriteString("\t\tct state established,related accept\n")
	fmt.Fprintf(&b, "\t\tiifname != \"lo\" tcp dport { %s } drop\n", strings.Join(strs, ", "))
	b.WriteString("\t}\n")
	b.WriteString("}\n")
	return b.String()
}
