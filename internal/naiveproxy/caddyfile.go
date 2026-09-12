package naiveproxy

import (
	"fmt"
	"net"
	"sort"
	"strings"
)

// renderCaddyfile builds the Caddyfile text for inst, and doubles as its
// change fingerprint -- Manager compares this string, not a separate hash.
func renderCaddyfile(inst Instance) (string, error) {
	_, port, err := net.SplitHostPort(inst.ListenAddr)
	if err != nil {
		return "", fmt.Errorf("naiveproxy: inbound %d has an invalid ListenAddr %q: %w", inst.Id, inst.ListenAddr, err)
	}

	fields := []string{inst.Domain, inst.CertFile, inst.KeyFile}
	for _, c := range inst.Clients {
		fields = append(fields, c.Username, c.Password)
	}
	for _, v := range fields {
		// Unescaped in the output: a newline would inject an extra Caddyfile
		// directive (e.g. a rogue upstream) rather than stay inside its own line.
		if strings.ContainsAny(v, "\r\n") {
			return "", fmt.Errorf("naiveproxy: a field for inbound %d contains a newline", inst.Id)
		}
	}

	clients := append([]Client(nil), inst.Clients...)
	sort.Slice(clients, func(i, j int) bool { return clients[i].Username < clients[j].Username })

	var b strings.Builder
	b.WriteString("{\n\tadmin off\n}\n\n")
	fmt.Fprintf(&b, "https://%s {\n", net.JoinHostPort(inst.Domain, port))
	b.WriteString("\tbind 127.0.0.1\n")
	fmt.Fprintf(&b, "\ttls %s %s\n", inst.CertFile, inst.KeyFile)
	b.WriteString("\tforward_proxy {\n")
	for _, c := range clients {
		fmt.Fprintf(&b, "\t\tbasic_auth %s %s\n", c.Username, c.Password)
	}
	b.WriteString("\t\thide_ip\n\t\thide_via\n")
	if inst.RouteThroughXray {
		fmt.Fprintf(&b, "\t\tupstream socks5://127.0.0.1:%d\n", inst.XrayRoutePort)
	}
	b.WriteString("\t}\n}\n")
	return b.String(), nil
}
