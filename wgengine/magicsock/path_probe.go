// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/metacubex/tailscale/ipn/ipnstate"
	"github.com/metacubex/tailscale/tailcfg"
	"github.com/metacubex/tailscale/tstime/mono"
)

// ConnectionPathProbe is the result of probing one concrete data path to a
// peer. Multiple direct endpoints can produce multiple results with Path set
// to "DIRECT".
type ConnectionPathProbe struct {
	Path          string `json:"path"`
	Endpoint      string `json:"endpoint,omitempty"`
	Reachable     bool   `json:"reachable"`
	LatencyMillis int64  `json:"latencyMillis,omitempty"`
	Error         string `json:"error,omitempty"`
}

// ConnectionDERPRegion describes a DERP path that can be selected by region
// code.
type ConnectionDERPRegion struct {
	ID   int    `json:"id"`
	Code string `json:"code"`
	Name string `json:"name"`
}

// ConnectionPathOptions is the set of paths that may be placed in a
// ConnectionOrder.
type ConnectionPathOptions struct {
	DERPRegions []ConnectionDERPRegion `json:"derpRegions"`
	PeerRelays  []string               `json:"peerRelays"`
}

type connectionPathCandidate struct {
	path string
	addr epAddr
	err  error
}

// ConnectionPathOptions returns the currently known DERP regions and eligible
// peer relay servers. DIRECT is always available and is therefore not repeated
// in the result.
func (c *Conn) ConnectionPathOptions() ConnectionPathOptions {
	var result ConnectionPathOptions
	if dm := c.derpMapAtomic.Load(); dm != nil {
		result.DERPRegions = make([]ConnectionDERPRegion, 0, len(dm.Regions))
		for id, region := range dm.Regions {
			if region == nil {
				continue
			}
			result.DERPRegions = append(result.DERPRegions, ConnectionDERPRegion{
				ID:   id,
				Code: region.RegionCode,
				Name: region.RegionName,
			})
		}
		sort.Slice(result.DERPRegions, func(i, j int) bool {
			return result.DERPRegions[i].Code < result.DERPRegions[j].Code
		})
	}

	for relay := range c.PeerRelays() {
		result.PeerRelays = append(result.PeerRelays, relay.String())
	}
	sort.Strings(result.PeerRelays)
	return result
}

// ProbeConnectionPaths probes all requested data paths concurrently without
// changing which path carries WireGuard traffic. target is the Tailscale IP of
// the remote peer. A path is "DIRECT", a DERP region code, or the Tailscale IP
// of a configured peer relay.
func (c *Conn) ProbeConnectionPaths(ctx context.Context, target netip.Addr, paths []string) ([]ConnectionPathProbe, error) {
	c.mu.Lock()
	var ep *endpoint
	c.peerMap.forEachEndpoint(func(candidate *endpoint) {
		if candidate.nodeAddr == target {
			ep = candidate
		}
	})
	c.mu.Unlock()
	if ep == nil {
		return nil, fmt.Errorf("unknown peer %v", target)
	}

	ep.mu.Lock()
	candidates := ep.connectionPathCandidatesLocked(paths)
	results := make([]ConnectionPathProbe, len(candidates))
	type response struct {
		index int
		value *ipnstate.PingResult
	}
	responses := make(chan response, len(candidates))
	pending := 0
	now := mono.Now()
	for i, candidate := range candidates {
		results[i] = ConnectionPathProbe{
			Path:     candidate.path,
			Endpoint: candidate.addr.String(),
		}
		if candidate.err != nil {
			results[i].Error = candidate.err.Error()
			continue
		}
		pending++
		index := i
		res := new(ipnstate.PingResult)
		ep.startDiscoPingLocked(candidate.addr, now, pingPathProbe, 0, &pingResultAndCallback{
			res: res,
			cb: func(value *ipnstate.PingResult) {
				responses <- response{index: index, value: value}
			},
		})
	}
	ep.mu.Unlock()

	for pending != 0 {
		select {
		case response := <-responses:
			result := &results[response.index]
			if result.Reachable {
				continue
			}
			result.Reachable = true
			result.LatencyMillis = int64(response.value.LatencySeconds*1000 + 0.5)
			pending--
		case <-ctx.Done():
			for i := range results {
				if results[i].Error == "" && !results[i].Reachable {
					results[i].Error = "timeout"
				}
			}
			return results, nil
		}
	}
	return results, nil
}

func (de *endpoint) connectionPathCandidatesLocked(paths []string) []connectionPathCandidate {
	var candidates []connectionPathCandidate
	dm := de.c.derpMapAtomic.Load()
	for _, rawPath := range paths {
		path := strings.TrimSpace(rawPath)
		switch {
		case strings.EqualFold(path, "DIRECT"):
			var endpoints []netip.AddrPort
			for endpoint := range de.endpointState {
				endpoints = append(endpoints, endpoint)
			}
			sort.Slice(endpoints, func(i, j int) bool {
				return endpoints[i].Compare(endpoints[j]) < 0
			})
			if len(endpoints) == 0 {
				candidates = append(candidates, connectionPathCandidate{path: "DIRECT", err: fmt.Errorf("no direct endpoints")})
			}
			for _, endpoint := range endpoints {
				candidates = append(candidates, connectionPathCandidate{
					path: "DIRECT",
					addr: epAddr{ap: endpoint},
				})
			}
		case isConnectionPathPeerRelay(path):
			relayIP, _ := netip.ParseAddr(path)
			relay, ok := de.preferredRelayPaths[relayIP]
			if !ok {
				candidates = append(candidates, connectionPathCandidate{
					path: relayIP.String(),
					err:  fmt.Errorf("peer relay path is not ready"),
				})
				continue
			}
			candidates = append(candidates, connectionPathCandidate{
				path: relayIP.String(),
				addr: relay.epAddr,
			})
		default:
			regionID := 0
			regionCode := strings.ToUpper(path)
			if dm != nil {
				for id, region := range dm.Regions {
					if strings.EqualFold(region.RegionCode, path) {
						regionID = id
						regionCode = region.RegionCode
						break
					}
				}
			}
			if regionID == 0 {
				candidates = append(candidates, connectionPathCandidate{
					path: regionCode,
					err:  fmt.Errorf("unknown DERP region"),
				})
				continue
			}
			candidates = append(candidates, connectionPathCandidate{
				path: regionCode,
				addr: epAddr{ap: netip.AddrPortFrom(tailcfg.DerpMagicIPAddr, uint16(regionID))},
			})
		}
	}
	return candidates
}

func isConnectionPathPeerRelay(path string) bool {
	ip, err := netip.ParseAddr(path)
	return err == nil && ip.IsValid()
}
