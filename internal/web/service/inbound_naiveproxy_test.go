package service

import (
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
)

func TestFillProtocolDefaultsNaiveProxy(t *testing.T) {
	cs := &ClientService{}
	ib := &model.Inbound{Protocol: model.NaiveProxy}

	c := &model.Client{Email: "u"}
	if err := cs.fillProtocolDefaults(c, ib); err != nil {
		t.Fatal(err)
	}
	// A UUID with the dashes stripped, matching Trojan's own password shape --
	// pinning the format catches a future generator swap to something Caddy's
	// basic_auth (or the Caddyfile tokenizer) might not accept.
	if len(c.NaiveProxyPassword) != 32 || strings.Contains(c.NaiveProxyPassword, "-") {
		t.Fatalf("naiveproxy password = %q, want a 32-char dash-free hex string", c.NaiveProxyPassword)
	}

	// An existing password is not overwritten.
	pre := &model.Client{Email: "v", NaiveProxyPassword: "preset"}
	if err := cs.fillProtocolDefaults(pre, ib); err != nil {
		t.Fatal(err)
	}
	if pre.NaiveProxyPassword != "preset" {
		t.Fatalf("an existing password must be preserved, got %q", pre.NaiveProxyPassword)
	}
}
