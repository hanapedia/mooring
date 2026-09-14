package bgp

import (
	"fmt"
	"os"
	"strconv"
)

// BGPConfig holds the peering parameters for the embedded GoBGP speaker.
// All fields are shared across daemon pods when using the sidecar pattern
// (peer is always 127.0.0.1), except RouterID and NextHop which must be
// set to the local node IP via the BGP_ROUTER_ID env var.
type BGPConfig struct {
	LocalASN  uint32
	RemoteASN uint32
	RouterID  string // local node IP; used as the BGP router ID
	PeerAddr  string // address of the sidecar BGP daemon; default 127.0.0.1
	NextHop   string // next-hop attribute for advertised routes; default RouterID
}

// FromEnv reads BGP config from environment variables.
// BGP_LOCAL_ASN, BGP_REMOTE_ASN, and BGP_ROUTER_ID are required.
func FromEnv() (BGPConfig, error) {
	localASN, err := requireUint32Env("BGP_LOCAL_ASN")
	if err != nil {
		return BGPConfig{}, err
	}
	remoteASN, err := requireUint32Env("BGP_REMOTE_ASN")
	if err != nil {
		return BGPConfig{}, err
	}
	routerID := os.Getenv("BGP_ROUTER_ID")
	if routerID == "" {
		return BGPConfig{}, fmt.Errorf("BGP_ROUTER_ID env var must be set")
	}

	peerAddr := os.Getenv("BGP_PEER_ADDR")
	if peerAddr == "" {
		peerAddr = "127.0.0.1"
	}
	nextHop := os.Getenv("BGP_NEXT_HOP")
	if nextHop == "" {
		nextHop = routerID
	}

	return BGPConfig{
		LocalASN:  localASN,
		RemoteASN: remoteASN,
		RouterID:  routerID,
		PeerAddr:  peerAddr,
		NextHop:   nextHop,
	}, nil
}

func requireUint32Env(key string) (uint32, error) {
	val := os.Getenv(key)
	if val == "" {
		return 0, fmt.Errorf("%s env var must be set", key)
	}
	n, err := strconv.ParseUint(val, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("%s must be a valid uint32: %w", key, err)
	}
	return uint32(n), nil
}
