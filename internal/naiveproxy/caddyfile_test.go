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

func TestRenderCaddyfileUsesListenPortNotADefault(t *testing.T) {
	got, err := renderCaddyfile(testInstance())
	if err != nil {
		t.Fatalf("renderCaddyfile: %v", err)
	}
	if !strings.Contains(got, "https://decoy.example.test:40100 {") {
		t.Errorf("Caddyfile does not carry the ListenAddr port, got:\n%s", got)
	}
	if strings.Contains(got, "https://decoy.example.test {") {
		t.Error("Caddyfile site address has no port -- Caddy would default it to :443")
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

func TestRenderCaddyfileRejectsInvalidListenAddr(t *testing.T) {
	inst := testInstance()
	inst.ListenAddr = "not-a-valid-addr"
	if _, err := renderCaddyfile(inst); err == nil {
		t.Fatal("renderCaddyfile with a malformed ListenAddr returned nil error")
	}
}

// A newline in any unescaped field would inject an extra directive, the same
// risk internal/sub/service.go's amneziaWGConfigText already guards against.
func TestRenderCaddyfileRejectsNewlineInjection(t *testing.T) {
	base := testInstance()
	cases := map[string]func(*Instance){
		"domain":    func(i *Instance) { i.Domain = "evil.test\nupstream socks5://attacker:1" },
		"cert file": func(i *Instance) { i.CertFile = "/tmp/x\nupstream evil" },
		"key file":  func(i *Instance) { i.KeyFile = "/tmp/x\nupstream evil" },
		"username":  func(i *Instance) { i.Clients[0].Username = "a\nupstream evil" },
		"password":  func(i *Instance) { i.Clients[0].Password = "a\nupstream evil" },
		"CRLF pair": func(i *Instance) { i.Domain = "evil.test\r\nadmin on" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			inst := base
			inst.Clients = append([]Client(nil), base.Clients...)
			mutate(&inst)
			if _, err := renderCaddyfile(inst); err == nil {
				t.Fatalf("renderCaddyfile with a newline in %s returned nil error, want a rejection", name)
			}
		})
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
