// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	cniInvoke "github.com/containernetworking/cni/pkg/invoke"
	"github.com/containernetworking/cni/pkg/skel"
	cniTypes "github.com/containernetworking/cni/pkg/types"
	cniVersion "github.com/containernetworking/cni/pkg/version"
	gops "github.com/google/gops/agent"
	"github.com/google/uuid"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/client"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/hooks"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/version"
	chainingapi "github.com/cilium/cilium/plugins/cilium-cni/chaining/api"
	"github.com/cilium/cilium/plugins/cilium-cni/types"
)

const (
	// defaultLogMaxBackups is to make sure that we have an upper bound on disk space used by
	// CNI file logging (e.g. < 7 * 100 MB).
	defaultLogMaxBackups = 7
)

// Option allows the customization of the Cmd implementation
type Option func(cmd *Cmd)

// WithVersion overrides the version reported by the CNI plugin binary in its about string.
func WithVersion(version string) Option {
	return func(cmd *Cmd) {
		cmd.version = version
	}
}

// WithEPConfigurator is used to create a Cmd instance with a custom
// endpoint configurator. The endpoint configurator can be used to customize
// the creation of endpoints during the CNI ADD invocation.
// This function is exported to be accessed outside the tree.
func WithEPConfigurator(cfg EndpointConfigurator) Option {
	return func(cmd *Cmd) {
		cmd.cfg = cfg
	}
}

// PluginMain is the main entry point for the Cilium CNI plugin.
func PluginMain(opts ...Option) {
	// slogloggercheck: the logger has been initialized with default settings
	logger := logging.DefaultSlogLogger.With(logfields.LogSubsys, "cilium-cni")
	cmd := &Cmd{
		logger:  logger,
		version: "Cilium CNI plugin " + version.Version,
		cfg:     &DefaultConfigurator{},
	}
	for _, opt := range opts {
		opt(cmd)
	}

	skel.PluginMainFuncs(
		skel.CNIFuncs{
			Add:    cmd.Add,
			Del:    cmd.Del,
			Check:  cmd.Check,
			Status: cmd.Status,
		},
		cniVersion.PluginSupports("0.1.0", "0.2.0", "0.3.0", "0.3.1", "0.4.0", "1.0.0", "1.1.0"),
		cmd.version,
	)
}

func ipv6IsEnabled(ipam *models.IPAMResponse) bool {
	if ipam == nil || ipam.Address.IPV6 == "" {
		return false
	}

	if ipam.HostAddressing == nil || ipam.HostAddressing.IPV6 == nil {
		return false
	}

	return ipam.HostAddressing.IPV6.Enabled
}

func ipv4IsEnabled(ipam *models.IPAMResponse) bool {
	if ipam == nil || ipam.Address.IPV4 == "" {
		return false
	}

	if ipam.HostAddressing == nil || ipam.HostAddressing.IPV4 == nil {
		return false
	}

	return ipam.HostAddressing.IPV4.Enabled
}

func getConfigFromCiliumAgent(client *client.Client) (*models.DaemonConfigurationStatus, error) {
	configResult, err := client.ConfigGet()
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve configuration from Cilium agent: %w", err)
	}

	if configResult == nil || configResult.Status == nil {
		return nil, errors.New("received empty configuration object from Cilium agent")
	}

	return configResult.Status, nil
}

func allocateIPsWithCiliumAgent(logger *slog.Logger, client *client.Client, cniArgs *types.ArgsSpec, ipamPoolName string) (*models.IPAMResponse, func(context.Context), error) {
	podName := string(cniArgs.K8S_POD_NAMESPACE) + "/" + string(cniArgs.K8S_POD_NAME)

	ipam, err := client.IPAMAllocate("", podName, ipamPoolName, true)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to allocate IP via local cilium agent: %w", err)
	}

	if ipam.Address == nil {
		return nil, nil, errors.New("invalid IPAM response, missing addressing")
	}

	releaseFunc := func(context.Context) {
		if ipam.Address != nil {
			releaseIP(logger, client, ipam.Address.IPV4, ipam.Address.IPV4PoolName)
			releaseIP(logger, client, ipam.Address.IPV6, ipam.Address.IPV6PoolName)
		}
	}

	return ipam, releaseFunc, nil
}

func releaseIP(logger *slog.Logger, client *client.Client, ip, pool string) {
	if ip != "" {
		if err := client.IPAMReleaseIP(ip, pool); err != nil {
			logger.Warn(
				"Unable to release IP",
				logfields.Error, err,
				logfields.IPAddr, ip,
				logfields.PoolName, pool,
			)
		}
	}
}

func (cmd *Cmd) setupLogging(n *types.NetConf) error {
	f := n.LogFormat
	if f == "" {
		f = string(logging.DefaultLogFormatTimestamp)
	}
	logOptions := logging.LogOptions{
		logging.FormatOpt: f,
		logging.WriterOpt: logging.StdErrOpt,
	}
	err := logging.SetupLogging([]string{}, logOptions, "cilium-cni", n.EnableDebug)
	if err != nil {
		return err
	}

	if len(n.LogFile) != 0 {
		logging.AddHandlers(hooks.NewFileRotationLogHook(
			// slogloggercheck: the logger has been initialized with default settings
			logging.GetSlogLevel(logging.DefaultSlogLogger),
			n.LogFile,
			hooks.EnableCompression(),
			hooks.WithMaxBackups(defaultLogMaxBackups),
		))
	}

	// slogloggercheck: The logger has been initialized with options from cilium CNI config.
	cmd.logger = logging.DefaultSlogLogger.With(logfields.LogSubsys, "cilium-cni")
	return nil
}

// Status implements the cni STATUS verb.
// Currently, it
//   - checks cilium-cni connectivity with cilium-agent using healthz endpoint
//   - If cilium-cni depends on delegated plugins (host-local, azure etc) for IPAM,
//     cilium-cni invokes the STATUS API of the delegated plugins and passes the result back.
func (cmd *Cmd) Status(args *skel.CmdArgs) error {
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
	scopedLogger.Debug("Processing CNI STATUS request", logfields.NetConf, n)

	if n.PrevResult != nil {
		scopedLogger.Debug("CNI Previous result", logfields.Previous, n.PrevResult)
	}

	cniArgs := &types.ArgsSpec{}
	if err = cniTypes.LoadArgs(args.Args, cniArgs); err != nil {
		return cniTypes.NewError(cniTypes.ErrInvalidNetworkConfig, "InvalidArgs",
			fmt.Sprintf("unable to extract CNI arguments: %s", err))
	}
	scopedLogger = buildLogAttrsWithCNIArgs(scopedLogger, cniArgs)

	c, err := client.NewDefaultClientWithTimeout(defaults.ClientConnectTimeout)
	if err != nil {
		// use ErrTryAgainLater to tell the runtime that this is not a check failure
		return cniTypes.NewError(types.CniErrPluginNotAvailable, "DaemonDown",
			fmt.Sprintf("unable to connect to Cilium agent: %s", client.Hint(err)))
	}

	// If this is a chained plugin, then "delegate" to the special chaining mode and be done
	if chainAction, err := getChainedAction(n, scopedLogger); chainAction != nil {
		var (
			ctx = chainingapi.PluginContext{
				Logger:  scopedLogger,
				Args:    args,
				CniArgs: cniArgs,
				NetConf: n,
			}
		)

		// err is nil on success
		err := chainAction.Status(context.TODO(), ctx, c)
		scopedLogger.Debug("Chained STATUS returned",
			logfields.Error, err,
			logfields.Name, n.Name,
		)

		return err
	} else if err != nil {
		scopedLogger.Error("Invalid chaining mode", logfields.Error, err)
		return err
	}

	if _, err := c.Daemon.GetHealthz(nil); err != nil {
		return cniTypes.NewError(types.CniErrPluginNotAvailable, "DaemonHealthzFailed",
			fmt.Sprintf("Cilium agent healthz check failed: %s", client.Hint(err)))
	}
	scopedLogger.Debug("Cilium agent is healthy")

	if n.IPAM.Type != "" {
		// If using a delegated plugin for IPAM, invoke the STATUS API of the delegated
		// plugins and pass the result back.
		err = cniInvoke.DelegateStatus(context.TODO(), n.IPAM.Type, args.StdinData, nil)
		if err != nil {
			return err
		}
	}

	return nil
}

// getChainedAction retrieves the desired chained action. It returns nil if there
// is no chained action, and error if there is a configured chained action but it is
// invalid.
func getChainedAction(n *types.NetConf, logger *slog.Logger) (chainingapi.ChainingPlugin, error) {
	if n.ChainingMode != "" {
		chainAction := chainingapi.Lookup(n.ChainingMode)
		if chainAction == nil {
			return nil, fmt.Errorf("invalid chaining-mode %s", n.ChainingMode)
		}

		logger.Info("Using chained plugin", logfields.Mode, n.ChainingMode)
		return chainAction, nil
	}

	// Chained action can either be explicitly enabled, or implicitly based on
	// network name.
	// Portmap is a special case; we used it to signify that the portmap plugin
	// is included later in the chain, but we should treat it as a standard plugin.
	if n.Name != chainingapi.DefaultConfigName && n.Name != "portmap" {
		chainAction := chainingapi.Lookup(n.Name)
		if chainAction == nil {
			// In this case, we are just being called with a different network name;
			// there isn't any chaining happening.
			return nil, nil
		}

		logger.Info("Using chained plugin", logfields.Name, n.Name)
		return chainAction, nil
	}

	// OK to return nil, nil if chaining isn't enabled.
	return nil, nil
}

func buildLogAttrsWithEventID(logger *slog.Logger, args *skel.CmdArgs) *slog.Logger {
	return logger.With(
		logfields.EventUUID, uuid.New(),
		logfields.ContainerID, args.ContainerID,
		logfields.NetNSName, args.Netns,
		logfields.Interface, args.IfName,
		logfields.Args, args.Args,
		logfields.Path, args.Path,
	)
}

func buildLogAttrsWithCNIArgs(logger *slog.Logger, cniArgs *types.ArgsSpec) *slog.Logger {
	return logger.With(
		logfields.K8sNamespace, cniArgs.K8S_POD_NAMESPACE,
		logfields.K8sPodName, cniArgs.K8S_POD_NAME,
	)
}
