// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package cmd

import "fmt"

func ifindexFromMac(mac string) (int64, error) {
	return -1, fmt.Errorf("ifindexFromMac not implemented on Windows")
}
