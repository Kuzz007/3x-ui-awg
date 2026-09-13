package tproxy

import "testing"

func TestCheckPlatform(t *testing.T) {
	if err := checkPlatform("linux", "amd64"); err != nil {
		t.Errorf("checkPlatform(linux, amd64) = %v, want nil", err)
	}
	for _, c := range [][2]string{{"linux", "arm64"}, {"windows", "amd64"}, {"darwin", "amd64"}} {
		if err := checkPlatform(c[0], c[1]); err == nil {
			t.Errorf("checkPlatform(%s, %s) = nil, want an error", c[0], c[1])
		}
	}
}
