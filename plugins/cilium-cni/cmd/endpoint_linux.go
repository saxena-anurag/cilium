// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package cmd

import (
	"fmt"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
)

func ifindexFromMac(mac string) (int64, error) {
	var link netlink.Link

	links, err := safenetlink.LinkList()
	if err != nil {
		return -1, fmt.Errorf("unable to list interfaces: %w", err)
	}

	for _, l := range links {
		// Linux slave devices have the same MAC address as their master
		// device, but we want the master device.
		if l.Attrs().RawFlags&unix.IFF_SLAVE != 0 {
			continue
		}
		if l.Attrs().HardwareAddr.String() == mac {
			if link != nil {
				return -1, fmt.Errorf("several interfaces found with MAC %s: %s and %s", mac, link.Attrs().Name, l.Attrs().Name)
			}
			link = l
		}
	}

	if link == nil {
		return -1, fmt.Errorf("no interface found with MAC %s", mac)
	}

	return int64(link.Attrs().Index), nil
}
