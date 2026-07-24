// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tsnet

import "github.com/metacubex/tailscale/wgengine/magicsock"

func cloneConnectionOrder(orders []magicsock.ConnectionOrder) []magicsock.ConnectionOrder {
	cloned := make([]magicsock.ConnectionOrder, len(orders))
	for i, order := range orders {
		cloned[i] = order
		cloned[i].Paths = append([]string(nil), order.Paths...)
	}
	return cloned
}

// SetConnectionOrder updates the ordered paths used for individual Tailscale
// peers. It can be called before or after Start. Updates made after Start are
// applied to the running magicsock connection immediately.
func (s *Server) SetConnectionOrder(orders []magicsock.ConnectionOrder) {
	orders = cloneConnectionOrder(orders)

	s.connectionOrderMu.Lock()
	defer s.connectionOrderMu.Unlock()

	s.ConnectionOrder = orders
	if s.connectionOrderMagicSock != nil {
		s.connectionOrderMagicSock.SetConnectionOrder(orders)
	}
}
