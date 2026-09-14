package bgp

import (
	"context"
	"fmt"
	"net"

	gobgpapi "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/server"
	"google.golang.org/protobuf/types/known/anypb"
)

// BGPSpeaker embeds a GoBGP server that runs as an active BGP client.
// It never binds to a listening port; it connects outward to the sidecar
// BGP daemon configured via BGPConfig. The sidecar must be set up with
// mooring as a passive peer.
//
// BGPSpeaker implements both routing.RouteAdvertiser and ctrl.Runnable.
// Register it with mgr.Add() so its lifecycle is managed alongside the
// controller-runtime manager.
type BGPSpeaker struct {
	cfg BGPConfig
	srv *server.BgpServer
}

func New(cfg BGPConfig) *BGPSpeaker {
	return &BGPSpeaker{cfg: cfg}
}

// Start implements ctrl.Runnable. It starts the embedded GoBGP server,
// configures global BGP settings and the sidecar peer, then blocks until
// ctx is cancelled, at which point it performs a clean shutdown.
func (s *BGPSpeaker) Start(ctx context.Context) error {
	s.srv = server.NewBgpServer()
	go s.srv.Serve()

	if err := s.srv.StartBgp(ctx, &gobgpapi.StartBgpRequest{
		Global: &gobgpapi.Global{
			Asn:        s.cfg.LocalASN,
			RouterId:   s.cfg.RouterID,
			ListenPort: -1, // active client only — never bind
		},
	}); err != nil {
		return fmt.Errorf("start bgp: %w", err)
	}

	if err := s.srv.AddPeer(ctx, &gobgpapi.AddPeerRequest{
		Peer: &gobgpapi.Peer{
			Conf: &gobgpapi.PeerConf{
				NeighborAddress: s.cfg.PeerAddr,
				PeerAsn:         s.cfg.RemoteASN,
			},
		},
	}); err != nil {
		return fmt.Errorf("add bgp peer %s: %w", s.cfg.PeerAddr, err)
	}

	<-ctx.Done()

	if err := s.srv.StopBgp(context.Background(), &gobgpapi.StopBgpRequest{}); err != nil {
		return fmt.Errorf("stop bgp: %w", err)
	}
	return nil
}

// AdvertisePrefix announces prefix to the BGP peer.
func (s *BGPSpeaker) AdvertisePrefix(ctx context.Context, prefix *net.IPNet) error {
	nlri, attrs, err := s.buildPath(prefix)
	if err != nil {
		return err
	}
	_, err = s.srv.AddPath(ctx, &gobgpapi.AddPathRequest{
		Path: &gobgpapi.Path{
			Family: ipv4Unicast(),
			Nlri:   nlri,
			Pattrs: attrs,
		},
	})
	return err
}

// WithdrawPrefix withdraws a previously advertised prefix from the BGP peer.
func (s *BGPSpeaker) WithdrawPrefix(ctx context.Context, prefix *net.IPNet) error {
	nlri, attrs, err := s.buildPath(prefix)
	if err != nil {
		return err
	}
	return s.srv.DeletePath(ctx, &gobgpapi.DeletePathRequest{
		Path: &gobgpapi.Path{
			Family: ipv4Unicast(),
			Nlri:   nlri,
			Pattrs: attrs,
		},
	})
}

func (s *BGPSpeaker) buildPath(prefix *net.IPNet) (nlri *anypb.Any, attrs []*anypb.Any, err error) {
	ones, _ := prefix.Mask.Size()
	ip := prefix.IP.To4()
	if ip == nil {
		return nil, nil, fmt.Errorf("only IPv4 prefixes are supported, got %s", prefix)
	}

	nlri, err = anypb.New(&gobgpapi.IPAddressPrefix{
		PrefixLen: uint32(ones),
		Prefix:    prefix.IP.String(),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("marshal NLRI: %w", err)
	}

	origin, err := anypb.New(&gobgpapi.OriginAttribute{Origin: 0}) // IGP
	if err != nil {
		return nil, nil, fmt.Errorf("marshal origin attribute: %w", err)
	}
	nextHop, err := anypb.New(&gobgpapi.NextHopAttribute{NextHop: s.cfg.NextHop})
	if err != nil {
		return nil, nil, fmt.Errorf("marshal next-hop attribute: %w", err)
	}

	return nlri, []*anypb.Any{origin, nextHop}, nil
}

func ipv4Unicast() *gobgpapi.Family {
	return &gobgpapi.Family{
		Afi:  gobgpapi.Family_AFI_IP,
		Safi: gobgpapi.Family_SAFI_UNICAST,
	}
}
