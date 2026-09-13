package tproxy

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRenderServerConfigOmitsLimitsAndTimeouts(t *testing.T) {
	data, err := renderServerConfig("proxy.example.com", "127.0.0.1:8080", "127.0.0.1:8081")
	if err != nil {
		t.Fatalf("renderServerConfig: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, absent := range []string{"limits", "timeouts", "enable_pprof", "public_upstream"} {
		if _, ok := raw[absent]; ok {
			t.Errorf("config.json must omit %q so tproxy-server's own Defaults() apply, got it explicitly set", absent)
		}
	}
	want := map[string]string{
		"public_hostname": "proxy.example.com",
		"base_path":       "",
		"listen":          "127.0.0.1:8080",
		"admin_listen":    "127.0.0.1:8081",
		"static_routes":   "exact",
	}
	for key, expected := range want {
		got, ok := raw[key].(string)
		if !ok {
			t.Errorf("%s is missing or not a string (raw value %#v)", key, raw[key])
			continue
		}
		if got != expected {
			t.Errorf("%s = %q, want %q", key, got, expected)
		}
	}
	for _, key := range []string{"public_dir", "token_key_file", "profiles_file"} {
		if s, ok := raw[key].(string); !ok || s == "" {
			t.Errorf("%s must be a non-empty string, got %#v", key, raw[key])
		}
	}
}

func TestRenderProfilesShape(t *testing.T) {
	data, err := renderProfiles([]profileSpec{
		{Name: "alice", Secret: "00112233445566778899aabbccddeeff", Backend: "127.0.0.1:2398"},
	})
	if err != nil {
		t.Fatalf("renderProfiles: %v", err)
	}
	var parsed profilesFile
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(parsed.Profiles) != 1 {
		t.Fatalf("got %d profiles, want 1", len(parsed.Profiles))
	}
	p := parsed.Profiles[0]
	if p.Name != "alice" || p.Backend != "127.0.0.1:2398" || p.CarrierMode != "https" {
		t.Errorf("unexpected profile: %+v", p)
	}
}

func TestRenderProfilesRejectsDuplicateName(t *testing.T) {
	_, err := renderProfiles([]profileSpec{
		{Name: "alice", Secret: "00112233445566778899aabbccddeeff", Backend: "127.0.0.1:2398"},
		{Name: "alice", Secret: "ffeeddccbbaa99887766554433221100", Backend: "127.0.0.1:2399"},
	})
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("renderProfiles error = %v, want a duplicate-name error", err)
	}
}

func TestRenderProfilesEmpty(t *testing.T) {
	data, err := renderProfiles(nil)
	if err != nil {
		t.Fatalf("renderProfiles: %v", err)
	}
	var parsed profilesFile
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(parsed.Profiles) != 0 {
		t.Errorf("got %d profiles, want 0", len(parsed.Profiles))
	}
}

func TestMtproxySecretArg(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"plain lowercase", "00112233445566778899aabbccddeeff", "00112233445566778899aabbccddeeff", false},
		{"plain uppercase normalized", "00112233445566778899AABBCCDDEEFF", "00112233445566778899aabbccddeeff", false},
		{"dd-prefixed stripped", "dd00112233445566778899aabbccddeeff", "00112233445566778899aabbccddeeff", false},
		{"DD-prefixed case-insensitive", "DD00112233445566778899AABBCCDDEEFF", "00112233445566778899aabbccddeeff", false},
		{"plain 32-char secret that happens to start with dd is not truncated", "dd0123456789abcdef0123456789abcd", "dd0123456789abcdef0123456789abcd", false},
		{"too short", "00112233", "", true},
		{"not hex", "gg112233445566778899aabbccddeeff", "", true},
		{"base64 form rejected -- MTProxy's own -S only accepts hex", "AAECAwQFBgcICQoLDA0ODw==", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := mtproxySecretArg(c.in)
			if c.wantErr {
				if err == nil {
					t.Fatalf("mtproxySecretArg(%q) = %q, want error", c.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("mtproxySecretArg(%q): %v", c.in, err)
			}
			if got != c.want {
				t.Errorf("mtproxySecretArg(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestMtproxyArgsShape(t *testing.T) {
	args, err := mtproxyArgs(2398, 8888, []string{
		"00112233445566778899aabbccddeeff",
		"dd00112233445566778899aabbccddee00",
	})
	if err != nil {
		t.Fatalf("mtproxyArgs: %v", err)
	}
	joined := strings.Join(args, " ")
	for _, want := range []string{
		"-p 8888", "-H 2398",
		"-S 00112233445566778899aabbccddeeff",
		"-S 00112233445566778899aabbccddee00",
		"--aes-pwd",
		"-M 0",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("mtproxyArgs = %q, want it to contain %q", joined, want)
		}
	}
	if strings.Contains(joined, "-u ") {
		t.Errorf("mtproxyArgs = %q, must not pass -u -- this fork runs sidecars unprivileged the same way every other one does, not via MTProxy's own setuid flag", joined)
	}
}

func TestMtproxyArgsRejectsBadSecret(t *testing.T) {
	if _, err := mtproxyArgs(1, 2, []string{"not-a-secret"}); err == nil {
		t.Fatal("mtproxyArgs accepted a malformed secret")
	}
}
