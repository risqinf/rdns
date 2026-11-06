package cdnbypass

import "testing"

func TestIsMediaCDN(t *testing.T) {
	cases := []struct {
		host string
		want bool
	}{
		{"nflxvideo.net", true},
		{"ipv4-c001-ix.1.oca.nflxvideo.net", true},
		{"googlevideo.com", true},
		{"rr1---sn-npoe7nes.googlevideo.com", true},
		{"v16m.tiktokcdn.com", true},
		{"s-media.aiv-cdn.net", true},
		{"cdn.steamcontent.com", true},
		{"netflix.com", false},
		{"api.netflix.com", false},
		{"www.youtube.com", false},
		{"maybank2u.com.my", false},
		{"", false},
	}

	for _, tc := range cases {
		if got := IsMediaCDN(tc.host); got != tc.want {
			t.Errorf("IsMediaCDN(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
}
