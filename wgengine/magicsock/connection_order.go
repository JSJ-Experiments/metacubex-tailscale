// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"net/netip"
	"strings"

	"github.com/metacubex/tailscale/tailcfg"
)

// ConnectionOrder configures the ordered paths to use for one peer.
//
// Target is a Tailscale IP address of the peer being contacted. Paths is an
// ordered list whose entries are "DIRECT", a Tailscale IP address of an
// eligible peer relay server, or a DERP region code (for example, "TYO").
// Entries that are not present in the current network map are ignored. When
// Paths is empty, normal Tailscale path selection is used.
//
// Only explicitly listed data paths are used. Peer relay allocation begins
// for the listed relay servers, and the first ready path in the list wins.
// DERP failures are retried after a short backoff.
type ConnectionOrder struct {
	Target netip.Addr
	Paths  []string
}

// RelayPreference is the former name of ConnectionOrder.
//
// Deprecated: use ConnectionOrder.
type RelayPreference = ConnectionOrder

type relayPreferenceSet struct {
	byTarget map[netip.Addr][]string
}

type relayPreferenceForEndpoint struct {
	enabled        bool
	directRank     int
	peerRelayRanks map[netip.Addr]int
	derpFallbacks  []preferredDERP
}

type preferredDERP struct {
	addr netip.AddrPort
	rank int
}

// connectionDERPCodeMatches accepts both the DERP map's canonical region code
// and compatibility aliases used by existing connection-order files.
//
// Tailscale's public DERP map calls Tokyo "tok", while older metacubex
// connection-order examples and deployments use the IATA metropolitan code
// "TYO". Keep accepting TYO so those files continue to select Tokyo.
func connectionDERPCodeMatches(requested, canonical string) bool {
	if strings.EqualFold(requested, canonical) {
		return true
	}
	return strings.EqualFold(requested, "TYO") && strings.EqualFold(canonical, "TOK")
}

func nodePrimaryTailscaleIP(n tailcfg.NodeView) netip.Addr {
	var result netip.Addr
	n.Addresses().All()(func(_ int, prefix netip.Prefix) bool {
		if prefix.IsSingleIP() && prefix.Addr().IsValid() {
			result = prefix.Addr()
			return false
		}
		return true
	})
	return result
}

// SetConnectionOrder sets per-peer connection orders. It is safe to call
// before or after the connection is started; existing endpoints are updated
// immediately and subsequent netmap updates retain the latest orders.
func (c *Conn) SetConnectionOrder(orders []ConnectionOrder) {
	set := &relayPreferenceSet{byTarget: make(map[netip.Addr][]string, len(orders))}
	for _, order := range orders {
		if !order.Target.IsValid() || len(order.Paths) == 0 {
			continue
		}
		paths := make([]string, 0, len(order.Paths))
		for _, path := range order.Paths {
			if path = strings.TrimSpace(path); path != "" {
				paths = append(paths, path)
			}
		}
		if len(paths) != 0 {
			set.byTarget[order.Target] = paths
		}
	}
	c.relayPreferenceSet.Store(set)

	// Apply the new order to existing endpoints immediately. A netmap update
	// may not arrive for a long time, especially while an on-device UI is
	// being used to compare paths.
	c.mu.Lock()
	defer c.mu.Unlock()
	c.peerMap.forEachEndpoint(func(ep *endpoint) {
		ep.applyConnectionOrder(c.relayPreferenceForTarget(ep.nodeAddr))
	})
}

// SetRelayPreferences is the former name of SetConnectionOrder.
//
// Deprecated: use SetConnectionOrder.
func (c *Conn) SetRelayPreferences(preferences []RelayPreference) {
	c.SetConnectionOrder(preferences)
}

func (c *Conn) relayPreferenceForNode(n tailcfg.NodeView) relayPreferenceForEndpoint {
	var target netip.Addr
	n.Addresses().All()(func(_ int, prefix netip.Prefix) bool {
		if prefix.IsSingleIP() && prefix.Addr().IsValid() {
			target = prefix.Addr()
			return false
		}
		return true
	})
	return c.relayPreferenceForTarget(target)
}

func (c *Conn) relayPreferenceForTarget(target netip.Addr) relayPreferenceForEndpoint {
	set := c.relayPreferenceSet.Load()
	if set == nil || len(set.byTarget) == 0 {
		return relayPreferenceForEndpoint{}
	}

	paths := set.byTarget[target]
	if len(paths) == 0 {
		return relayPreferenceForEndpoint{}
	}

	preference := relayPreferenceForEndpoint{
		directRank:     -1,
		peerRelayRanks: make(map[netip.Addr]int),
	}
	dm := c.derpMapAtomic.Load()
	for rank, path := range paths {
		if strings.EqualFold(path, "DIRECT") {
			if preference.directRank == -1 {
				preference.directRank = rank
				preference.enabled = true
			}
			continue
		}
		if ip, err := netip.ParseAddr(path); err == nil {
			if _, exists := preference.peerRelayRanks[ip]; !exists {
				preference.peerRelayRanks[ip] = rank
				preference.enabled = true
			}
			continue
		}
		if dm == nil {
			continue
		}
		for regionID, region := range dm.Regions {
			if connectionDERPCodeMatches(path, region.RegionCode) {
				preference.derpFallbacks = append(preference.derpFallbacks, preferredDERP{
					addr: netip.AddrPortFrom(tailcfg.DerpMagicIPAddr, uint16(regionID)),
					rank: rank,
				})
				preference.enabled = true
				break
			}
		}
	}
	return preference
}
