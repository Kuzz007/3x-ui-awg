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

// freeLocalPort asks the OS for an unused loopback TCP port, a package-local
// copy of internal/mtproto's identical helper.
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

// serverConfig is the subset of tproxy-server's own Config this package ever
// sets; every omitted field keeps tproxy-server's own Defaults() instead.
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
// panel-wide relay process. hostname is frontproxy's own public domain.
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

// placeholderIndexHTML is public_dir's required content -- defense in depth
// only; frontproxy's own capability check never forwards a request here.
const placeholderIndexHTML = "<!doctype html><title></title>\n"

type profileSpec struct {
	// Name must be unique across every profile this panel renders -- see
	// types.go's ClientSecret.Name.
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

// renderProfiles builds profiles.json from every tproxy inbound's clients.
// carrier_mode is fixed to "https" -- the other three modes are unused so far.
func renderProfiles(specs []profileSpec) ([]byte, error) {
	seen := make(map[string]struct{}, len(specs))
	entries := make([]profileEntry, 0, len(specs))
	for _, s := range specs {
		if _, dup := seen[s.Name]; dup {
			// tproxy-server's own loadProfiles rejects this outright, taking
			// down the shared relay for every client on every inbound.
			return nil, fmt.Errorf("duplicate tproxy client name %q across inbounds", s.Name)
		}
		seen[s.Name] = struct{}{}
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

// normalizeSecret validates and case-normalizes a client secret, keeping
// whichever length it was given: 32 plain hex digits, or 34 dd-prefixed.
func normalizeSecret(secret string) (string, error) {
	trimmed := strings.ToLower(strings.TrimSpace(secret))
	switch {
	case len(trimmed) == 32 && hexDigitsRE.MatchString(trimmed):
		return trimmed, nil
	case len(trimmed) == 34 && strings.HasPrefix(trimmed, "dd") && hexDigitsRE.MatchString(trimmed):
		return trimmed, nil
	default:
		// Length only, never the secret itself -- this reaches the panel log.
		return "", fmt.Errorf("client secret must be 32 hex digits, optionally dd-prefixed (got %d characters)", len(trimmed))
	}
}

// mtproxySecretArg strips normalizeSecret's dd-prefix, if any: MTProxy's own
// -S flag accepts only exactly 32 hex digits.
func mtproxySecretArg(secret string) (string, error) {
	normalized, err := normalizeSecret(secret)
	if err != nil {
		return "", err
	}
	if len(normalized) == 34 {
		return normalized[2:], nil
	}
	return normalized, nil
}

// mtproxyWorkers is passed to -M. 0 disables forking a slave worker process
// entirely -- MTProxy's own source forks one per worker even at -M 1.
const mtproxyWorkers = 0

// mtproxyArgs builds the full mtproto-proxy command line for one inbound's
// engine. clientPort is -H, statsPort is -p; one -S per active client secret.
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
