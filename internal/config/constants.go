package config

// Network-wide constants shared by both roles.
const (
	// TunnelMarkDefault is the SO_MARK value stamped on rdns-client
	// tunnel sockets. nftsetup programs a tproxy rule that skips
	// sockets with this mark, so the tunnel to the exit node never
	// gets redirected back into the local SNI interceptor.
	TunnelMarkDefault uint32 = 0xd1920d7 // "rdns"
)
