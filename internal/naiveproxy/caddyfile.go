package naiveproxy

import (
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
)

// renderCaddyfile builds the Caddyfile text for inst, and doubles as its
// change fingerprint -- Manager compares this string, not a separate hash.
func renderCaddyfile(inst Instance) (string, error) {
	host, port, err := net.SplitHostPort(inst.ListenAddr)
	if err != nil {
		return "", fmt.Errorf("naiveproxy: inbound %d has an invalid ListenAddr %q: %w", inst.Id, inst.ListenAddr, err)
	}
	// "bind 127.0.0.1" below is hardcoded regardless of ListenAddr's host --
	// reject anything else so the field and the listener can't disagree.
	if host != "127.0.0.1" {
		return "", fmt.Errorf("naiveproxy: inbound %d's ListenAddr %q must be on 127.0.0.1", inst.Id, inst.ListenAddr)
	}
	if inst.RouteThroughXray && (inst.XrayRoutePort <= 0 || inst.XrayRoutePort > 65535) {
		return "", fmt.Errorf("naiveproxy: inbound %d has RouteThroughXray set with an invalid XrayRoutePort %d", inst.Id, inst.XrayRoutePort)
	}

	for _, v := range []string{inst.CertFile, inst.KeyFile} {
		// Unescaped file paths: a newline would inject an extra Caddyfile
		// directive (e.g. a rogue upstream) rather than stay inside the tls line.
		if strings.ContainsAny(v, "\r\n") {
			return "", fmt.Errorf("naiveproxy: inbound %d has a newline in a cert/key path", inst.Id)
		}
	}
	for _, c := range inst.Clients {
		if strings.ContainsAny(c.Username+c.Password, "\r\n") {
			return "", fmt.Errorf("naiveproxy: inbound %d has a newline in a client credential", inst.Id)
		}
	}

	clients := slices.Clone(inst.Clients)
	slices.SortFunc(clients, func(a, b Client) int { return strings.Compare(a.Username, b.Username) })

	var b strings.Builder
	b.WriteString("{\n\tadmin off\n\tauto_https disable_redirects\n}\n\n")
	// A bare ":port" address, no host: CONNECT's Host/authority is the
	// client's *target*, not this server's name, so a host match would never see it.
	fmt.Fprintf(&b, "https://:%s {\n", port)
	b.WriteString("\tbind 127.0.0.1\n")
	fmt.Fprintf(&b, "\ttls %s %s\n", caddyfileQuote(inst.CertFile), caddyfileQuote(inst.KeyFile))
	b.WriteString("\tforward_proxy {\n")
	for _, c := range clients {
		fmt.Fprintf(&b, "\t\tbasic_auth %s %s\n", caddyfileQuote(c.Username), caddyfileQuote(c.Password))
	}
	b.WriteString("\t\thide_ip\n\t\thide_via\n")
	if inst.RouteThroughXray {
		fmt.Fprintf(&b, "\t\tupstream socks5://127.0.0.1:%s\n", strconv.Itoa(inst.XrayRoutePort))
	}
	b.WriteString("\t}\n}\n")
	return b.String(), nil
}

// caddyfileQuote wraps s in a Caddyfile double-quoted token, escaping the
// two characters that would otherwise end it early or start an expansion.
func caddyfileQuote(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}
