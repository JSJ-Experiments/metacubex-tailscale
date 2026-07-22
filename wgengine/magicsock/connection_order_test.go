// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/tailscale/tailcfg"
	"github.com/metacubex/tailscale/tstime/mono"
	"github.com/metacubex/tailscale/types/logger"
)

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
