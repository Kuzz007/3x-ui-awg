package naiveproxy

// Client is one Naive user's HTTP Basic-Auth credential, rendered into the
// Caddyfile as its own basic_auth line.
type Client struct {
	Email    string
	Username string
	Password string
}

// Instance is everything one Naive-backed inbound needs to run its own Caddy
// process. Package-local, mirrors internal/mtproto's Instance.
type Instance struct {
	Id         int
	ListenAddr string // loopback "127.0.0.1:PORT" this Caddy binds to
	Domain     string // the SNI frontproxy's SNI-relay matches to reach ListenAddr

	// A manually supplied cert for Domain: Caddy never sees a direct,
	// publicly reachable connection to complete its own ACME challenge on.
	CertFile string
	KeyFile  string

	Clients []Client

	// Mirror MTProto's identically named fields: when set, Caddy dials
	// outbound traffic through this loopback SOCKS5 port (an Xray inbound).
	RouteThroughXray bool
	XrayRoutePort    int
}
