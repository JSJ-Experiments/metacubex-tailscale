// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/tailscale/net/packet"
	"github.com/metacubex/tailscale/tailcfg"
	"github.com/metacubex/tailscale/tstime/mono"
	"github.com/metacubex/tailscale/types/logger"
)

func TestConnectionPathCandidates(t *testing.T) {
	c := newConn(logger.Discard)
	c.derpMapAtomic.Store(&tailcfg.DERPMap{Regions: map[int]*tailcfg.DERPRegion{
		1: {RegionID: 1, RegionCode: "TYO"},
	}})
	direct := netip.MustParseAddrPort("192.0.2.1:41641")
	relayIP := netip.MustParseAddr("100.91.245.79")
	relayAddr := netip.MustParseAddrPort("198.51.100.1:40000")
	vni := packet.VirtualNetworkID{}
	vni.Set(7)
	ep := &endpoint{
		c:             c,
		endpointState: map[netip.AddrPort]*endpointState{direct: {}},
		preferredRelayPaths: map[netip.Addr]addrQuality{
			relayIP: {epAddr: epAddr{ap: relayAddr, vni: vni}},
		},
	}

	got := ep.connectionPathCandidatesLocked([]string{"DIRECT", relayIP.String(), "tyo", "XXX"})
	if len(got) != 4 {
		t.Fatalf("candidate count = %d, want 4", len(got))
	}
	if got[0].path != "DIRECT" || got[0].addr.ap != direct {
		t.Fatalf("direct candidate = %#v", got[0])
	}
	if got[1].path != relayIP.String() || got[1].addr.ap != relayAddr || !got[1].addr.vni.IsSet() {
		t.Fatalf("peer relay candidate = %#v", got[1])
	}
	if got[2].path != "TYO" || got[2].addr.ap.Port() != 1 || got[2].addr.ap.Addr() != tailcfg.DerpMagicIPAddr {
		t.Fatalf("DERP candidate = %#v", got[2])
	}
	if got[3].err == nil {
		t.Fatal("unknown DERP region was accepted")
	}
}

func TestConnectionPathOptions(t *testing.T) {
	c := newConn(logger.Discard)
	c.derpMapAtomic.Store(&tailcfg.DERPMap{Regions: map[int]*tailcfg.DERPRegion{
		2: {RegionID: 2, RegionCode: "TYO", RegionName: "Tokyo"},
		1: {RegionID: 1, RegionCode: "FRA", RegionName: "Frankfurt"},
	}})

	got := c.ConnectionPathOptions()
	if len(got.DERPRegions) != 2 {
		t.Fatalf("DERP region count = %d, want 2", len(got.DERPRegions))
	}
	if got.DERPRegions[0].Code != "FRA" || got.DERPRegions[1].Code != "TYO" {
		t.Fatalf("DERP regions = %#v, want FRA then TYO", got.DERPRegions)
	}
}

func TestConnectionOrderForNode(t *testing.T) {
	target := netip.MustParseAddr("100.120.147.123")
	firstRelay := netip.MustParseAddr("100.91.245.79")
	lastRelay := netip.MustParseAddr("100.67.42.33")
	c := newConn(logger.Discard)
	c.derpMapAtomic.Store(&tailcfg.DERPMap{Regions: map[int]*tailcfg.DERPRegion{
		1: {RegionID: 1, RegionCode: "TYO"},
		2: {RegionID: 2, RegionCode: "SIN"},
		3: {RegionID: 3, RegionCode: "FRA"},
	}})
	c.SetConnectionOrder([]ConnectionOrder{{
		Target: target,
		Paths:  []string{firstRelay.String(), "TYO", "SIN", "FRA", lastRelay.String()},
	}})

	node := (&tailcfg.Node{Addresses: []netip.Prefix{netip.PrefixFrom(target, target.BitLen())}}).View()
	got := c.relayPreferenceForNode(node)
	if !got.enabled {
		t.Fatal("preference was not enabled")
	}
	if got.peerRelayRanks[firstRelay] != 0 || got.peerRelayRanks[lastRelay] != 4 {
		t.Fatalf("peer relay ordering = %#v, want first=0 and last=4", got.peerRelayRanks)
	}
	wantDERP := []netip.AddrPort{
		netip.AddrPortFrom(tailcfg.DerpMagicIPAddr, 1),
		netip.AddrPortFrom(tailcfg.DerpMagicIPAddr, 2),
		netip.AddrPortFrom(tailcfg.DerpMagicIPAddr, 3),
	}
	if len(got.derpFallbacks) != len(wantDERP) {
		t.Fatalf("DERP fallback count = %d, want %d", len(got.derpFallbacks), len(wantDERP))
	}
	for i, want := range wantDERP {
		if got.derpFallbacks[i].addr != want {
			t.Errorf("DERP fallback[%d] = %v, want %v", i, got.derpFallbacks[i].addr, want)
		}
	}

	now := mono.Now()
	ep := &endpoint{relayPreference: got}
	_, derpAddr, _ := ep.addrForSendLocked(now)
	if derpAddr != wantDERP[0] {
		t.Fatalf("initial relay path = %v, want %v", derpAddr, wantDERP[0])
	}
	ep.failedPreferredDERP = map[int]mono.Time{1: now}
	_, derpAddr, _ = ep.addrForSendLocked(now)
	if derpAddr != wantDERP[1] {
		t.Fatalf("relay path after TYO failure = %v, want %v", derpAddr, wantDERP[1])
	}
	ep.failedPreferredDERP[1] = now.Add(-preferredDERPFailureBackoff)
	_, derpAddr, _ = ep.addrForSendLocked(now)
	if derpAddr != wantDERP[0] {
		t.Fatalf("relay path after failure backoff = %v, want %v", derpAddr, wantDERP[0])
	}
}

func TestConnectionOrderDirect(t *testing.T) {
	target := netip.MustParseAddr("100.120.147.123")
	relay := netip.MustParseAddr("100.91.245.79")
	c := newConn(logger.Discard)
	c.derpMapAtomic.Store(&tailcfg.DERPMap{Regions: map[int]*tailcfg.DERPRegion{
		1: {RegionID: 1, RegionCode: "TYO"},
	}})
	c.SetConnectionOrder([]ConnectionOrder{{
		Target: target,
		Paths:  []string{"TYO", relay.String(), "DIRECT"},
	}})

	node := (&tailcfg.Node{Addresses: []netip.Prefix{netip.PrefixFrom(target, target.BitLen())}}).View()
	order := c.relayPreferenceForNode(node)
	if order.directRank != 2 {
		t.Fatalf("direct rank = %d, want 2", order.directRank)
	}

	now := mono.Now()
	directAddr := epAddr{ap: netip.MustParseAddrPort("192.0.2.1:1234")}
	ep := &endpoint{
		relayPreference:    order,
		bestAddr:           addrQuality{epAddr: directAddr},
		trustBestAddrUntil: now.Add(time.Minute),
	}
	udpAddr, derpAddr, _ := ep.addrForSendLocked(now)
	if udpAddr.ap.IsValid() || derpAddr.Port() != 1 {
		t.Fatalf("path with TYO before direct = (%v, %v), want DERP-1", udpAddr, derpAddr)
	}

	ep.failedPreferredDERP = map[int]mono.Time{0: now}
	udpAddr, derpAddr, _ = ep.addrForSendLocked(now)
	if udpAddr != directAddr || derpAddr.IsValid() {
		t.Fatalf("path after TYO failure = (%v, %v), want direct %v", udpAddr, derpAddr, directAddr)
	}
}
