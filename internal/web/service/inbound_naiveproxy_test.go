package service

import (
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
	if c.NaiveProxyPassword == "" {
		t.Fatal("naiveproxy client should get a generated password")
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
