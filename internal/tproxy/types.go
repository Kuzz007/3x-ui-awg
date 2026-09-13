// Package tproxy manages the Telegram web-proxy (tproxy) sidecar: a shared
// tproxy-server relay (github.com/telegramdesktop/tproxy-server) that bridges
// a Telegram app's WebView-carried MTProto traffic to one MTProxy engine
// (github.com/TelegramMessenger/MTProxy) per tproxy inbound. Both binaries are
// compiled amd64-only in this fork's own release CI (see .github/workflows/release.yml)
// since neither upstream publishes prebuilt releases.
//
// Unlike internal/naiveproxy (one Caddy process per inbound) or
// internal/mtproto (one mtg process per inbound, many secrets each), tproxy
// has two distinct process kinds with different scopes:
//
//   - Exactly one tproxy-server process for the whole panel. It owns the
//     panel's single public hostname (the same domain internal/frontproxy
//     already terminates TLS for) and dispatches each authenticated request to
//     the MTProxy backend named by whichever client profile matched. Every
//     tproxy inbound's clients live in this one process's profiles.json, so
//     any client add/remove/re-key across any tproxy inbound restarts it --
//     the upstream protocol has no hot-reload anywhere in its stack.
//   - One MTProxy engine process per tproxy inbound, holding every active
//     client secret of that inbound via repeated -S flags (mirrors how
//     internal/mtproto runs one mtg process per inbound for the same reason:
//     MTProxy's own /stats is process-wide, not per-secret, so per-client
//     traffic accounting -- not yet designed, see the open backlog -- reads
//     from tproxy-server's own per-profile session state instead of this).
//
// A tproxy-server MTProxy engine's client (HTTP) port binds every interface
// by design (confirmed in tproxy-server's own reference deploy/firewall.nft:
// upstream ships an nftables table for exactly this), so nothing but
// tproxy-server's own loopback relay may ever reach it -- see firewall.go.
package tproxy

// ClientSecret is one client's raw MTProto secret, shared by both layers: it
// derives that client's tproxy-server bridge capability (profiles.json) and is
// also the -S value MTProxy itself uses to decrypt that client's traffic --
// the same design a t.me/webproxy?server=&secret= link already implies one
// secret authenticates both hops.
type ClientSecret struct {
	// Name must be unique across every tproxy inbound on the panel, not just
	// within one: all inbounds' clients share the one tproxy-server process's
	// profiles.json, which rejects a duplicate profile name outright.
	Name   string
	Secret string
}

// Instance is the desired runtime state of one tproxy inbound: an MTProxy
// engine serving every listed client's secret, plus that inbound's slice of
// the panel-wide tproxy-server profile set. Package-local, mirrors
// internal/mtproto's Instance and internal/naiveproxy's Instance.
type Instance struct {
	Id      int
	Clients []ClientSecret
}
