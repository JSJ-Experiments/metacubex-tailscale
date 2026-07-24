// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tsnet

import (
	"net/netip"
	"reflect"
	"testing"

	"github.com/metacubex/tailscale/wgengine/magicsock"
)

func TestSetConnectionOrderBeforeStart(t *testing.T) {
	server := new(Server)
	input := []magicsock.ConnectionOrder{{
		Target: netip.MustParseAddr("100.64.0.1"),
		Paths:  []string{"DIRECT", "TYO"},
	}}

	server.SetConnectionOrder(input)
	input[0].Paths[0] = "MUTATED"

	want := []magicsock.ConnectionOrder{{
		Target: netip.MustParseAddr("100.64.0.1"),
		Paths:  []string{"DIRECT", "TYO"},
	}}
	if !reflect.DeepEqual(server.ConnectionOrder, want) {
		t.Fatalf("ConnectionOrder = %#v, want %#v", server.ConnectionOrder, want)
	}
}
