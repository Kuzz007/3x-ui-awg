package tproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// freeLocalPort asks the OS for an unused loopback TCP port, matching
// internal/mtproto's FreeLocalPort -- kept as its own tiny copy rather than a
// cross-sidecar-package dependency for two lines of net.Listen.
func freeLocalPort() (int, error) {
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// freeLocalAddr is freeLocalPort formatted as a "127.0.0.1:PORT" listen
// address, the form tproxy-server's own config.json fields expect.
func freeLocalAddr() (string, error) {
	port, err := freeLocalPort()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("127.0.0.1:%d", port), nil
}

// serverConfig is the subset of tproxy-server's own internal/config.Config
// this package ever sets explicitly. Every other field -- all of Limits and
// Timeouts included -- is intentionally absent: Load() decodes this JSON on
// top of its own built-in Defaults(), so an absent key keeps tproxy-server's
// own default rather than this package having to restate it.
type serverConfig struct {
	PublicHostname string `json:"public_hostname"`
	BasePath       string `json:"base_path"`
	Listen         string `json:"listen"`
	AdminListen    string `json:"admin_listen"`
	PublicDir      string `json:"public_dir"`
	StaticRoutes   string `json:"static_routes"`
	TokenKeyFile   string `json:"token_key_file"`
	ProfilesFile   string `json:"profiles_file"`
}

// renderServerConfig builds tproxy-server's config.json for the one
// panel-wide relay process. hostname is frontproxy's own public domain --
// tproxy shares REALITY's single domain rather than getting its own, so the
// bridge capability is bound to the same hostname clients already reach the
// panel and subscription server through.
func renderServerConfig(hostname, listenAddr, adminAddr string) ([]byte, error) {
	cfg := serverConfig{
		PublicHostname: hostname,
		BasePath:       "",
		Listen:         listenAddr,
		AdminListen:    adminAddr,
		PublicDir:      publicDirPath(),
		StaticRoutes:   "exact",
		TokenKeyFile:   tokenKeyPath(),
		ProfilesFile:   profilesPath(),
	}
	return json.MarshalIndent(cfg, "", "  ")
}

// placeholderIndexHTML is the file tproxy-server's public_dir must contain.
// It is only ever served to a request that reached tproxy-server without a
// valid bridge capability -- in normal operation frontproxy's own capability
// check (see internal/frontproxy) never forwards such a request here at all,
// so this is defense in depth, not the panel's decoy: a bland, static,
// content-free page rather than a second decoy implementation to keep in
// sync with frontproxy's own.
const placeholderIndexHTML = "<!doctype html><title></title>\n"

type profileSpec struct {
	// Name must be unique across every profile this panel ever renders (every
	// tproxy inbound shares the one profiles.json) -- see types.go's
	// ClientSecret.Name.
	Name    string
	Secret  string
	Backend string // loopback "ip:port" of this client's inbound's MTProxy engine
}

type profileEntry struct {
	Name        string `json:"name"`
	Secret      string `json:"secret"`
	Backend     string `json:"backend"`
	CarrierMode string `json:"carrier_mode"`
}

type profilesFile struct {
	Profiles []profileEntry `json:"profiles"`
}

// renderProfiles builds the panel-wide profiles.json from every tproxy
// inbound's active clients. carrier_mode is fixed to "https": tproxy-server's
// other three modes (https-lanes, websocket, websocket-lanes) trade off
// against carriers this fork has no configured use for yet.
func renderProfiles(specs []profileSpec) ([]byte, error) {
	entries := make([]profileEntry, 0, len(specs))
	for _, s := range specs {
		entries = append(entries, profileEntry{
			Name:        s.Name,
			Secret:      s.Secret,
			Backend:     s.Backend,
			CarrierMode: "https",
		})
	}
	return json.MarshalIndent(profilesFile{Profiles: entries}, "", "  ")
}

var hexDigitsRE = regexp.MustCompile(`^[0-9a-fA-F]+$`)

// mtproxySecretArg normalizes a client secret into the exact form MTProxy's
// own -S flag accepts: exactly 32 hex digits, no "dd" random-padding prefix.
// -S rejects anything else outright (mtproto-proxy.c's own parser: "requires
// exactly 32 hex digits"), including the profiles.json random-padding form,
// so a dd-prefixed secret is stripped down to its plain 32 first -- the
// prefix only ever changes the client-side wire behavior and the bridge
// capability tproxy-server derives, never what MTProxy itself is told.
//
// Disambiguated by length, not by content: a plain 32-hex secret that simply
// happens to start with "dd" is not the padding form and must not be
// truncated -- tproxy-server's own DecodeSecret uses the identical rule (a
// dd-prefixed secret is exactly 34 hex digits, one byte longer than plain).
func mtproxySecretArg(secret string) (string, error) {
	trimmed := strings.ToLower(strings.TrimSpace(secret))
	switch {
	case len(trimmed) == 32 && hexDigitsRE.MatchString(trimmed):
		return trimmed, nil
	case len(trimmed) == 34 && strings.HasPrefix(trimmed, "dd") && hexDigitsRE.MatchString(trimmed):
		return trimmed[2:], nil
	default:
		return "", fmt.Errorf("client secret must be 32 hex digits, optionally dd-prefixed (got %q)", secret)
	}
}

// mtproxyWorkers is passed to -M. MTProxy's own README recommends raising it
// only on a powerful server; one worker per inbound-scoped engine is the
// right default when several such engines can run side by side.
const mtproxyWorkers = 1

// mtproxyArgs builds the full mtproto-proxy command line for one inbound's
// engine: clientPort is -H (what tproxy-server's matching profiles dial as
// their backend), statsPort is -p (loopback-only /stats, not yet scraped by
// anything -- traffic accounting is a separate, later step). One -S per
// active client secret, matching the README's own "-S <secret1> -S <secret2>"
// multi-secret form. No -u: like every other sidecar this fork already runs
// (mtg-multi, Caddy, Tor), the engine runs as whatever user the panel process
// itself does, rather than a one-off privilege-dropped exception just here.
func mtproxyArgs(clientPort, statsPort int, secrets []string) ([]string, error) {
	args := []string{
		"-p", strconv.Itoa(statsPort),
		"-H", strconv.Itoa(clientPort),
	}
	for _, secret := range secrets {
		normalized, err := mtproxySecretArg(secret)
		if err != nil {
			return nil, err
		}
		args = append(args, "-S", normalized)
	}
	args = append(args,
		"--aes-pwd", proxySecretPath(), proxyMultiConfPath(),
		"-M", strconv.Itoa(mtproxyWorkers),
	)
	return args, nil
}
