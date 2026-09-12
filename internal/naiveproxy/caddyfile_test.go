package naiveproxy

import (
	"strings"
	"testing"
)

func testInstance() Instance {
	return Instance{
		Id:         1,
		ListenAddr: "127.0.0.1:40100",
		Domain:     "decoy.example.test",
		CertFile:   "/bin/naiveproxy/decoy.example.test.crt",
		KeyFile:    "/bin/naiveproxy/decoy.example.test.key",
		Clients: []Client{
			{Email: "b@x", Username: "bravo", Password: "pw-b"},
			{Email: "a@x", Username: "alpha", Password: "pw-a"},
		},
	}
}

// A CONNECT tunnel's Host is the client's *target*, never this server's own
// name, so the site address must be a bare ":port" catch-all, not "domain:port".
func TestRenderCaddyfileSiteAddressHasNoHostMatcher(t *testing.T) {
	got, err := renderCaddyfile(testInstance())
	if err != nil {
		t.Fatalf("renderCaddyfile: %v", err)
	}
	if !strings.Contains(got, "https://:40100 {") {
		t.Errorf("Caddyfile does not carry a bare :port site address, got:\n%s", got)
	}
	if strings.Contains(got, "decoy.example.test:40100") {
		t.Error("Caddyfile's site address is host-matched -- CONNECT traffic would never reach forward_proxy")
	}
}

// Automatic HTTPS opens an HTTP->HTTPS redirect on :80 by default even with
// a manual tls directive -- with N instances on 127.0.0.1, only the first would bind it.
func TestRenderCaddyfileDisablesAutoHTTPSRedirects(t *testing.T) {
	got, err := renderCaddyfile(testInstance())
	if err != nil {
		t.Fatalf("renderCaddyfile: %v", err)
	}
	if !strings.Contains(got, "auto_https disable_redirects") {
		t.Errorf("expected auto_https redirects disabled, got:\n%s", got)
	}
}

func TestRenderCaddyfileSortsClientsDeterministically(t *testing.T) {
	inst := testInstance()
	first, err := renderCaddyfile(inst)
	if err != nil {
		t.Fatalf("renderCaddyfile: %v", err)
	}

	inst.Clients[0], inst.Clients[1] = inst.Clients[1], inst.Clients[0]
	second, err := renderCaddyfile(inst)
	if err != nil {
		t.Fatalf("renderCaddyfile: %v", err)
	}

	if first != second {
		t.Errorf("client order changed the rendered output:\nfirst:\n%s\nsecond:\n%s", first, second)
	}
	if strings.Index(first, "alpha") > strings.Index(first, "bravo") {
		t.Errorf("clients not sorted by username, got:\n%s", first)
	}
}

func TestRenderCaddyfileOmitsUpstreamWhenNotRoutingThroughXray(t *testing.T) {
	got, err := renderCaddyfile(testInstance())
	if err != nil {
		t.Fatalf("renderCaddyfile: %v", err)
	}
	if strings.Contains(got, "upstream") {
		t.Errorf("upstream directive present without RouteThroughXray, got:\n%s", got)
	}
}

func TestRenderCaddyfileAddsUpstreamWhenRoutingThroughXray(t *testing.T) {
	inst := testInstance()
	inst.RouteThroughXray = true
	inst.XrayRoutePort = 41200
	got, err := renderCaddyfile(inst)
	if err != nil {
		t.Fatalf("renderCaddyfile: %v", err)
	}
	if !strings.Contains(got, "upstream socks5://127.0.0.1:41200") {
		t.Errorf("expected the socks5 upstream directive, got:\n%s", got)
	}
}

func TestRenderCaddyfileRejectsInvalidRouteThroughXrayPort(t *testing.T) {
	for _, port := range []int{0, -1, 65536} {
		inst := testInstance()
		inst.RouteThroughXray = true
		inst.XrayRoutePort = port
		_, err := renderCaddyfile(inst)
		if err == nil {
			t.Fatalf("XrayRoutePort=%d: renderCaddyfile returned nil error, want a rejection", port)
		}
		if !strings.Contains(err.Error(), "XrayRoutePort") {
			t.Errorf("XrayRoutePort=%d: error = %q, want it to name the field", port, err.Error())
		}
	}
}

func TestRenderCaddyfileRejectsInvalidListenAddr(t *testing.T) {
	inst := testInstance()
	inst.ListenAddr = "not-a-valid-addr"
	_, err := renderCaddyfile(inst)
	if err == nil {
		t.Fatal("renderCaddyfile with a malformed ListenAddr returned nil error")
	}
	if !strings.Contains(err.Error(), "invalid ListenAddr") {
		t.Errorf("error = %q, want it to name the invalid ListenAddr", err.Error())
	}
}

// bind 127.0.0.1 is hardcoded below; a ListenAddr on a different host would
// silently disagree with what Caddy actually binds (see Instance's doc comment).
func TestRenderCaddyfileRejectsNonLoopbackListenAddr(t *testing.T) {
	inst := testInstance()
	inst.ListenAddr = "0.0.0.0:40100"
	_, err := renderCaddyfile(inst)
	if err == nil {
		t.Fatal("renderCaddyfile with a non-loopback ListenAddr returned nil error")
	}
	if !strings.Contains(err.Error(), "127.0.0.1") {
		t.Errorf("error = %q, want it to mention the 127.0.0.1 requirement", err.Error())
	}
}

// A newline in any unescaped field would inject an extra directive, the same
// risk internal/sub/service.go's amneziaWGConfigText already guards against.
func TestRenderCaddyfileRejectsNewlineInjection(t *testing.T) {
	base := testInstance()
	cases := []struct {
		name        string
		mutate      func(*Instance)
		errContains string
	}{
		{"cert file", func(i *Instance) { i.CertFile = "/tmp/x\nupstream evil" }, "cert/key path"},
		{"key file", func(i *Instance) { i.KeyFile = "/tmp/x\nupstream evil" }, "cert/key path"},
		{"username", func(i *Instance) { i.Clients[0].Username = "a\nupstream evil" }, "client credential"},
		{"password", func(i *Instance) { i.Clients[0].Password = "a\nupstream evil" }, "client credential"},
		{"CRLF pair", func(i *Instance) { i.CertFile = "/tmp/x\r\nadmin on" }, "cert/key path"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inst := base
			inst.Clients = append([]Client(nil), base.Clients...)
			tc.mutate(&inst)
			_, err := renderCaddyfile(inst)
			if err == nil {
				t.Fatalf("renderCaddyfile with a newline in %s returned nil error, want a rejection", tc.name)
			}
			if !strings.Contains(err.Error(), tc.errContains) {
				t.Errorf("error = %q, want it to mention %q -- wrong validation branch may have fired", err.Error(), tc.errContains)
			}
		})
	}
}

// The Caddyfile tokenizer splits on whitespace and treats '"'/'#' specially
// -- a credential with any of these must stay one literal quoted value.
func TestRenderCaddyfileQuotesClientCredentials(t *testing.T) {
	inst := testInstance()
	inst.Clients = []Client{{Email: "x", Username: "weird user", Password: `p"#\w`}}
	got, err := renderCaddyfile(inst)
	if err != nil {
		t.Fatalf("renderCaddyfile: %v", err)
	}
	want := `basic_auth "weird user" "p\"#\\w"`
	if !strings.Contains(got, want) {
		t.Errorf("expected a quoted, escaped basic_auth line %q, got:\n%s", want, got)
	}
}

func TestRenderCaddyfileDisablesAdminAPI(t *testing.T) {
	got, err := renderCaddyfile(testInstance())
	if err != nil {
		t.Fatalf("renderCaddyfile: %v", err)
	}
	if !strings.Contains(got, "admin off") {
		t.Errorf("expected admin API disabled (no live-reload support yet, and no reason to open it), got:\n%s", got)
	}
}
