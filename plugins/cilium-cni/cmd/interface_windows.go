// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package cmd

import (
	"fmt"
	"log/slog"

	current "github.com/containernetworking/cni/pkg/types/100"

	"github.com/cilium/cilium/api/v1/models"
)

func interfaceAdd(_ *slog.Logger, _ *current.IPConfig, _ *models.IPAMAddressResponse, _ *models.DaemonConfigurationStatus) error {
	return fmt.Errorf("interfaceAdd not implemented on Windows")
}
