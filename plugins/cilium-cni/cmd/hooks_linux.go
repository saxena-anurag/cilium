// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package cmd

import (
	datapath "github.com/cilium/cilium/pkg/datapath/types"
)

// OnLinkConfigReady is invoked before the datapath connectors are called to create the pod's
// network links (i.e. veth or netkit pairs). It may be used to further modify the link
// configuration.
type OnLinkConfigReady interface {
	OnLinkConfigReady(linkConfig *datapath.LinkConfig) error
}

// WithOnLinkConfigReady adds a new callback to be invoked before the datapath connectors are called
// to create the pod's network links.
func WithOnLinkConfigReady(f OnLinkConfigReady) Option {
	return func(cmd *Cmd) {
		cmd.onLinkConfigReady = append(cmd.onLinkConfigReady, f)
	}
}
