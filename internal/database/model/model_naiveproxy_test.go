package model

import "testing"

func TestClientToRecordRoundTripNaiveProxy(t *testing.T) {
	c := &Client{
		Email:              "alice@example.test",
		Enable:             true,
		NaiveProxyPassword: "a1b2c3d4e5f6",
	}

	rec := c.ToRecord()
	if rec.NaiveProxyPassword != c.NaiveProxyPassword {
		t.Fatalf("ToRecord: NaiveProxyPassword = %q, want %q", rec.NaiveProxyPassword, c.NaiveProxyPassword)
	}

	got := rec.ToClient()
	if got.NaiveProxyPassword != c.NaiveProxyPassword {
		t.Errorf("round-trip: NaiveProxyPassword = %q, want %q", got.NaiveProxyPassword, c.NaiveProxyPassword)
	}
}
