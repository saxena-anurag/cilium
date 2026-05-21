// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package cmd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"

	cniInvoke "github.com/containernetworking/cni/pkg/invoke"
	"github.com/containernetworking/cni/pkg/skel"
	cniTypes "github.com/containernetworking/cni/pkg/types"
	cniTypesV1 "github.com/containernetworking/cni/pkg/types/100"
	cniVersion "github.com/containernetworking/cni/pkg/version"
	gops "github.com/google/gops/agent"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/client"
	"github.com/cilium/cilium/pkg/defaults"
	endpointid "github.com/cilium/cilium/pkg/endpoint/id"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/logging/logfields"
	chainingapi "github.com/cilium/cilium/plugins/cilium-cni/chaining/api"
	"github.com/cilium/cilium/plugins/cilium-cni/lib"
	"github.com/cilium/cilium/plugins/cilium-cni/types"
)

var (
	getNetnsCookie = false
)

// Cmd provides methods for the CNI ADD, DEL and CHECK commands.
type Cmd struct {
	logger  *slog.Logger
	version string
	cfg     EndpointConfigurator

	onConfigReady          []OnConfigReady
	onIPAMReady            []OnIPAMReady
	onInterfaceConfigReady []OnInterfaceConfigReady
}

// CmdState holds the IP configuration state for an endpoint.
type CmdState struct {
	IP6      netip.Addr
	IP4      netip.Addr
	HostAddr *models.NodeAddressing
}

func allocateIPsWithDelegatedPlugin(
	ctx context.Context,
	conf *models.DaemonConfigurationStatus,
	netConf *types.NetConf,
	stdinData []byte,
) (*models.IPAMResponse, func(context.Context), error) {
	ipamRawResult, err := cniInvoke.DelegateAdd(ctx, netConf.IPAM.Type, stdinData, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to invoke delegated plugin ADD for IPAM: %w", err)
	}

	releaseFunc := func(ctx context.Context) {
		cniInvoke.DelegateDel(ctx, netConf.IPAM.Type, stdinData, nil)
	}

	ipamResult, err := cniTypesV1.NewResultFromResult(ipamRawResult)
	if err != nil {
		return nil, releaseFunc, fmt.Errorf("could not interpret delegated IPAM result for CNI version %s: %w", cniTypesV1.ImplementedSpecVersion, err)
	}

	ipam := &models.IPAMResponse{
		HostAddressing: conf.Addressing,
		Address:        &models.AddressPair{},
	}

	masterMac := ""
	for _, iface := range ipamResult.Interfaces {
		if iface.Sandbox != "" {
			continue
		}
		if iface.Mac != "" {
			if ifMac, err := net.ParseMAC(iface.Mac); err != nil {
				return nil, releaseFunc, fmt.Errorf("failed to parse interface MAC %q: %w", iface.Mac, err)
			} else {
				masterMac = ifMac.String()
			}
		}
		break
	}

	for _, ipConfig := range ipamResult.IPs {
		ipNet := ipConfig.Address
		if ipNet.IP.To4() != nil {
			if conf.Addressing.IPV4 != nil {
				ipam.Address.IPV4 = ipNet.String()
				ipam.IPV4 = &models.IPAMAddressResponse{
					IP:              ipNet.IP.String(),
					Gateway:         ipConfig.Gateway.String(),
					MasterMac:       masterMac,
					InterfaceNumber: "0",
				}
			}
		} else {
			if conf.Addressing.IPV6 != nil {
				ipam.Address.IPV6 = ipNet.String()
				ipam.IPV6 = &models.IPAMAddressResponse{
					IP:              ipNet.IP.String(),
					Gateway:         ipConfig.Gateway.String(),
					MasterMac:       masterMac,
					InterfaceNumber: "0",
				}
			}
		}
	}

	return ipam, releaseFunc, nil
}

func (cmd *Cmd) Add(args *skel.CmdArgs) (err error) {
	n, err := types.LoadNetConf(args.StdinData)
	if err != nil {
		return fmt.Errorf("unable to parse CNI configuration %q: %w", string(args.StdinData), err)
	}

	if err = cmd.setupLogging(n); err != nil {
		return fmt.Errorf("unable to setup logging: %w", err)
	}

	scopedLogger := buildLogAttrsWithEventID(cmd.logger, args)

	if n.EnableDebug {
		if err := gops.Listen(gops.Options{}); err != nil {
			scopedLogger.Warn("Unable to start gops", logfields.Error, err)
		} else {
			defer gops.Close()
		}
	}

	scopedLogger.Debug("Processing CNI ADD request", logfields.NetConf, n)

	if n.PrevResult != nil {
		scopedLogger.Debug("CNI Previous result", logfields.Previous, n.PrevResult)
	}

	cniArgs := &types.ArgsSpec{}
	if err = cniTypes.LoadArgs(args.Args, cniArgs); err != nil {
		return fmt.Errorf("unable to extract CNI arguments: %w", err)
	}
	scopedLogger = buildLogAttrsWithCNIArgs(scopedLogger, cniArgs)

	c, err := client.NewDefaultClientWithTimeout(defaults.ClientConnectTimeout)
	if err != nil {
		return fmt.Errorf("unable to connect to Cilium agent: %w", client.Hint(err))
	}

	conf, err := getConfigFromCiliumAgent(c)
	if err != nil {
		return err
	}

	for _, hook := range cmd.onConfigReady {
		if err := hook.OnConfigReady(args, cniArgs, conf); err != nil {
			return err
		}
	}

	// If CNI ADD gives us a PrevResult, we're a chained plugin and *must* detect a
	// valid chained mode.
	if len(n.NetConf.RawPrevResult) != 0 {
		if chainAction, err := getChainedAction(n, scopedLogger); chainAction != nil {
			var (
				res *cniTypesV1.Result
				ctx = chainingapi.PluginContext{
					Logger:     scopedLogger,
					Args:       args,
					CniArgs:    cniArgs,
					NetConf:    n,
					CiliumConf: conf,
				}
			)

			res, err = chainAction.Add(context.TODO(), ctx, c)
			if err != nil {
				scopedLogger.Warn("Chained ADD failed", logfields.Error, err)
				return err
			}
			scopedLogger.Debug("Returning result", logfields.Result, res)
			return cniTypes.PrintResult(res, n.CNIVersion)
		} else if err != nil {
			scopedLogger.Error("Invalid chaining mode", logfields.Error, err)
			return err
		} else {
			const errMsg = "CNI PrevResult supplied, but not in chaining mode -- this is invalid, please set chaining-mode in CNI configuration"
			scopedLogger.Error(errMsg)
			return errors.New(errMsg)
		}
	}

	res := &cniTypesV1.Result{}
	configs, err := cmd.cfg.GetConfigurations(ConfigurationParams{scopedLogger, conf, args, cniArgs})
	if err != nil {
		return fmt.Errorf("failed to determine endpoint configuration: %w", err)
	}

	for _, epConf := range configs {
		var ipam *models.IPAMResponse
		var releaseIPsFunc func(context.Context)
		if conf.IpamMode == ipamOption.IPAMDelegatedPlugin {
			ipam, releaseIPsFunc, err = allocateIPsWithDelegatedPlugin(context.TODO(), conf, n, args.StdinData)
		} else {
			ipam, releaseIPsFunc, err = allocateIPsWithCiliumAgent(scopedLogger, c, cniArgs, epConf.IPAMPool())
		}

		// release addresses on failure
		defer func() {
			if err != nil && releaseIPsFunc != nil {
				releaseIPsFunc(context.TODO())
			}
		}()

		if err != nil {
			return err
		}

		if !ipv6IsEnabled(ipam) && !ipv4IsEnabled(ipam) {
			return errors.New("IPAM did provide neither IPv4 nor IPv6 address")
		}

		for _, hook := range cmd.onIPAMReady {
			if err := hook.OnIPAMReady(ipam); err != nil {
				return err
			}
		}

		state, ep, err := epConf.PrepareEndpoint(ipam)
		if err != nil {
			return fmt.Errorf("unable to prepare endpoint configuration: %w", err)
		}

		// Populate IP addressing on the endpoint from the IPAM response.
		if ipv6IsEnabled(ipam) && conf.Addressing.IPV6 != nil {
			ep.Addressing.IPV6 = ipam.Address.IPV6
			ep.Addressing.IPV6PoolName = ipam.Address.IPV6PoolName
			ep.Addressing.IPV6ExpirationUUID = ipam.IPV6.ExpirationUUID

			ip, err := netip.ParseAddr(ipam.Address.IPV6)
			if err == nil {
				state.IP6 = ip
			}

			ipConfig := &cniTypesV1.IPConfig{
				Address: net.IPNet{
					IP:   state.IP6.AsSlice(),
					Mask: net.CIDRMask(128, 128),
				},
			}
			if ipam.IPV6.Gateway != "" {
				ipConfig.Gateway = net.ParseIP(ipam.IPV6.Gateway)
			}
			ipConfig.Interface = cniTypesV1.Int(len(res.Interfaces))
			res.IPs = append(res.IPs, ipConfig)
		}

		if ipv4IsEnabled(ipam) && conf.Addressing.IPV4 != nil {
			ep.Addressing.IPV4 = ipam.Address.IPV4
			ep.Addressing.IPV4PoolName = ipam.Address.IPV4PoolName
			ep.Addressing.IPV4ExpirationUUID = ipam.IPV4.ExpirationUUID

			ip, err := netip.ParseAddr(ipam.Address.IPV4)
			if err == nil {
				state.IP4 = ip
			}

			ipConfig := &cniTypesV1.IPConfig{
				Address: net.IPNet{
					IP:   state.IP4.AsSlice(),
					Mask: net.CIDRMask(32, 32),
				},
			}
			if ipam.IPV4.Gateway != "" {
				ipConfig.Gateway = net.ParseIP(ipam.IPV4.Gateway)
			}
			ipConfig.Interface = cniTypesV1.Int(len(res.Interfaces))
			res.IPs = append(res.IPs, ipConfig)
		}

		for _, hook := range cmd.onInterfaceConfigReady {
			if err := hook.OnInterfaceConfigReady(state, ep, res); err != nil {
				return err
			}
		}

		// Tell the Cilium agent to create the endpoint. The agent is responsible
		// for all datapath setup on Windows (e.g. configuring network adapters).
		ep.SyncBuildEndpoint = true
		if _, err = c.EndpointCreate(ep); err != nil {
			scopedLogger.Warn("Unable to create endpoint",
				logfields.Error, err,
				logfields.ContainerID, ep.ContainerID,
			)
			return fmt.Errorf("unable to create endpoint: %w", err)
		}

		scopedLogger.Debug("Endpoint successfully created",
			logfields.ContainerID, ep.ContainerID,
		)
	}

	return cniTypes.PrintResult(res, n.CNIVersion)
}

// Del is invoked on CNI DEL
func (cmd *Cmd) Del(args *skel.CmdArgs) error {
	n, err := types.LoadNetConf(args.StdinData)
	if err != nil {
		return fmt.Errorf("unable to parse CNI configuration %q: %w", string(args.StdinData), err)
	}

	if err := cmd.setupLogging(n); err != nil {
		return fmt.Errorf("unable to setup logging: %w", err)
	}

	scopedLogger := buildLogAttrsWithEventID(cmd.logger, args)

	if n.EnableDebug {
		if err := gops.Listen(gops.Options{}); err != nil {
			scopedLogger.Warn("Unable to start gops", logfields.Error, err)
		} else {
			defer gops.Close()
		}
	}
	scopedLogger.Debug("Processing CNI DEL request", logfields.NetConf, n)

	cniArgs := &types.ArgsSpec{}
	if err = cniTypes.LoadArgs(args.Args, cniArgs); err != nil {
		return fmt.Errorf("unable to extract CNI arguments: %w", err)
	}
	scopedLogger = buildLogAttrsWithCNIArgs(scopedLogger, cniArgs)

	c := lib.NewDeletionFallbackClient(scopedLogger)

	// If this is a chained plugin, delegate to the chaining mode.
	if chainAction, err := getChainedAction(n, scopedLogger); chainAction != nil {
		var (
			ctx = chainingapi.PluginContext{
				Logger:  scopedLogger,
				Args:    args,
				CniArgs: cniArgs,
				NetConf: n,
			}
		)

		return chainAction.Delete(context.TODO(), ctx, c)
	} else if err != nil {
		scopedLogger.Error("Invalid chaining mode", logfields.Error, err)
		return err
	}

	req := &models.EndpointBatchDeleteRequest{ContainerID: args.ContainerID}
	if err := c.EndpointDeleteMany(req); err != nil {
		if errors.Is(err, lib.ErrClientFailure) {
			scopedLogger.Error("Failed to delete endpoint", logfields.Error, err)
			return err
		}
		scopedLogger.Warn("Errors encountered while deleting endpoint", logfields.Error, err)
	}

	if n.IPAM.Type != "" {
		err = cniInvoke.DelegateDel(context.TODO(), n.IPAM.Type, args.StdinData, nil)
		if err != nil {
			return err
		}
	}

	// On Windows, the Cilium agent is responsible for all datapath cleanup
	// (network adapter removal, etc.) when the endpoint is deleted via the API above.
	// No additional CNI-side cleanup is required.
	scopedLogger.Debug("CNI DEL processing complete")
	return nil
}

// Check implements the cni CHECK verb.
func (cmd *Cmd) Check(args *skel.CmdArgs) error {
	n, err := types.LoadNetConf(args.StdinData)
	if err != nil {
		return cniTypes.NewError(cniTypes.ErrInvalidNetworkConfig, "InvalidNetworkConfig",
			fmt.Sprintf("unable to parse CNI configuration \"%s\": %v", string(args.StdinData), err))
	}

	if err := cmd.setupLogging(n); err != nil {
		return cniTypes.NewError(cniTypes.ErrInvalidNetworkConfig, "InvalidLoggingConfig",
			fmt.Sprintf("unable to setup logging: %s", err))
	}

	scopedLogger := buildLogAttrsWithEventID(cmd.logger, args)

	if n.EnableDebug {
		if err := gops.Listen(gops.Options{}); err != nil {
			scopedLogger.Warn("Unable to start gops", logfields.Error, err)
		} else {
			defer gops.Close()
		}
	}
	scopedLogger.Debug("Processing CNI CHECK request", logfields.NetConf, n)

	cniArgs := &types.ArgsSpec{}
	if err = cniTypes.LoadArgs(args.Args, cniArgs); err != nil {
		return cniTypes.NewError(cniTypes.ErrInvalidNetworkConfig, "InvalidArgs",
			fmt.Sprintf("unable to extract CNI arguments: %s", err))
	}
	scopedLogger = buildLogAttrsWithCNIArgs(scopedLogger, cniArgs)

	c, err := client.NewDefaultClientWithTimeout(defaults.ClientConnectTimeout)
	if err != nil {
		return cniTypes.NewError(cniTypes.ErrTryAgainLater, "DaemonDown",
			fmt.Sprintf("unable to connect to Cilium agent: %s", client.Hint(err)))
	}

	// If this is a chained plugin, delegate to the chaining mode.
	if chainAction, err := getChainedAction(n, scopedLogger); chainAction != nil {
		var (
			ctx = chainingapi.PluginContext{
				Logger:  scopedLogger,
				Args:    args,
				CniArgs: cniArgs,
				NetConf: n,
			}
		)

		err := chainAction.Check(context.TODO(), ctx, c)
		scopedLogger.Debug("Chained CHECK returned", logfields.Error, err, logfields.Name, n.Name)
		return err
	} else if err != nil {
		scopedLogger.Error("Invalid chaining mode", logfields.Error, err)
		return err
	}

	// Ask the agent for the endpoint's health
	eID := endpointid.NewCNIAttachmentID(args.ContainerID, args.IfName)
	scopedLogger.Debug("Asking agent for healthz", logfields.EndpointID, eID)

	epHealth, err := c.EndpointHealthGet(eID)
	if err != nil {
		return cniTypes.NewError(types.CniErrHealthzGet, "HealthzFailed",
			fmt.Sprintf("failed to retrieve container health: %s", err))
	}

	if epHealth.OverallHealth == models.EndpointHealthStatusFailure {
		return cniTypes.NewError(types.CniErrUnhealthy, "Unhealthy",
			"container is unhealthy in agent")
	}
	scopedLogger.Debug("Container has a healthy agent endpoint",
		logfields.ContainerID, args.ContainerID,
		logfields.ContainerInterface, args.IfName,
	)

	// mechanical: parse PrevResult
	if err := cniVersion.ParsePrevResult(&n.NetConf); err != nil {
		return err
	}
	prevResult, err := cniTypesV1.NewResultFromResult(n.NetConf.PrevResult)
	if err != nil {
		return err
	}

	// Verify the container interface exists and has expected IPs.
	if err := verifyInterface(args.IfName, prevResult); err != nil {
		return err
	}

	return nil
}

// verifyInterface checks that the named interface exists and has the expected
// IP addresses from the CNI result. On Windows, we use the standard net package
// rather than netlink since the Cilium agent manages the datapath.
func verifyInterface(ifName string, expected *cniTypesV1.Result) error {
	iface, err := net.InterfaceByName(ifName)
	if err != nil {
		return fmt.Errorf("interface %q not found: %w", ifName, err)
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return fmt.Errorf("failed to list addresses on interface %q: %w", ifName, err)
	}

	// Collect expected IPs from the CNI result that belong to this interface.
	var wantAddresses []*cniTypesV1.IPConfig
	for idx, resultIface := range expected.Interfaces {
		if resultIface.Sandbox == "" {
			continue
		}
		if resultIface.Name != ifName {
			continue
		}
		for _, ip := range expected.IPs {
			if ip.Interface != nil && *ip.Interface == idx {
				wantAddresses = append(wantAddresses, ip)
			}
		}
	}

	for _, want := range wantAddresses {
		found := false
		wantIP := want.Address.IP.String()
		for _, addr := range addrs {
			// addr.String() returns CIDR notation "ip/mask"; parse just the IP.
			addrIP, _, err := net.ParseCIDR(addr.String())
			if err != nil {
				continue
			}
			if addrIP.Equal(want.Address.IP) {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("expected IP %s on interface %s but not found", wantIP, ifName)
		}
	}

	return nil
}

// needsEndpointRoutingOnHost returns false on Windows.
// Linux uses cloud ENI IPAM modes that require host-side routing;
// this is not yet applicable on Windows.
func needsEndpointRoutingOnHost(conf *models.DaemonConfigurationStatus) bool {
	return false
}
