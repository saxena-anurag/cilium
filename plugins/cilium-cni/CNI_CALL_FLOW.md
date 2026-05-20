# Cilium CNI Plugin — Call Flow Graph

This document describes the call flow for the Cilium CNI plugin's **ADD** and **DEL** operations, starting from the binary entry point. Both **Linux** and **Windows** platform-specific paths are covered, along with the **chaining mode** alternative flow.

---

## Table of Contents

- [Entry Point](#entry-point)
- [CNI ADD Operation](#cni-add-operation)
  - [ADD — Common Initialization](#add--common-initialization)
  - [ADD — Chaining Mode Path](#add--chaining-mode-path)
  - [ADD — Standard Mode Path (Linux)](#add--standard-mode-path-linux)
  - [ADD — Standard Mode Path (Windows)](#add--standard-mode-path-windows)
- [CNI DEL Operation](#cni-del-operation)
  - [DEL — Common Initialization](#del--common-initialization)
  - [DEL — Chaining Mode Path](#del--chaining-mode-path)
  - [DEL — Standard Mode Path (Linux)](#del--standard-mode-path-linux)
  - [DEL — Standard Mode Path (Windows)](#del--standard-mode-path-windows)
- [Key Data Structures](#key-data-structures)
- [Chaining Plugin Registry](#chaining-plugin-registry)
- [Deletion Fallback Queue](#deletion-fallback-queue)
- [ASCII Call Flow Diagrams](#ascii-call-flow-diagrams)

---

## Entry Point

```
main() [main.go]
  └── runtime.LockOSThread()             // Pin goroutine to OS thread (required for netns operations)
  └── cmd.PluginMain()                    // [cmd/cmd.go]
        ├── Initialize Cmd struct
        │     ├── logger = DefaultSlogLogger
        │     ├── version = "Cilium CNI plugin " + version.Version
        │     └── cfg = DefaultConfigurator{}
        ├── Apply Option functions (WithVersion, WithEPConfigurator, etc.)
        └── skel.PluginMainFuncs(...)     // CNI framework dispatcher
              ├── ADD   → cmd.Add()
              ├── DEL   → cmd.Del()
              ├── CHECK → cmd.Check()
              └── STATUS → cmd.Status()
```

---

## CNI ADD Operation

### ADD — Common Initialization

Both Linux and Windows share the same initial steps:

```
Cmd.Add(args *skel.CmdArgs) [cmd/cmd_linux.go or cmd/cmd_windows.go]
  │
  ├── 1. types.LoadNetConf(args.StdinData)
  │       └── Parse JSON CNI config → NetConf struct
  │       └── parsePrevResult() if RawPrevResult exists
  │
  ├── 2. cmd.setupLogging(n)              [cmd/cmd.go]
  │       ├── logging.SetupLogging()
  │       └── Add file rotation hook if LogFile configured
  │
  ├── 3. buildLogAttrsWithEventID()       // Add UUID, ContainerID, Netns, IfName to logger
  │
  ├── 4. gops.Listen() (if EnableDebug)   // Start diagnostics agent
  │
  ├── 5. cniTypes.LoadArgs(args.Args, cniArgs)
  │       └── Extract K8S_POD_NAME, K8S_POD_NAMESPACE, K8S_POD_UID
  │
  ├── 6. buildLogAttrsWithCNIArgs()       // Add pod namespace/name to logger
  │
  ├── 7. client.NewDefaultClientWithTimeout()
  │       └── Connect to Cilium agent API socket
  │
  ├── 8. getConfigFromCiliumAgent(c)      [cmd/cmd.go]
  │       └── c.ConfigGet() → DaemonConfigurationStatus
  │
  ├── 9. Invoke onConfigReady hooks
  │       └── foreach hook: hook.OnConfigReady(args, cniArgs, conf)
  │
  └── 10. Branch: Chaining vs Standard mode
           ├── If RawPrevResult exists → Chaining Mode Path
           └── Else → Standard Mode Path
```

### ADD — Chaining Mode Path

When `RawPrevResult` is present in the CNI config (indicating cilium-cni is chained after another CNI plugin):

```
Chaining Mode ADD
  │
  ├── getChainedAction(n, logger)         [cmd/cmd.go]
  │     ├── Check n.ChainingMode (explicit config)
  │     │     └── chainingapi.Lookup(n.ChainingMode)
  │     └── Or check n.Name (implicit, network name match)
  │           └── chainingapi.Lookup(n.Name)
  │
  ├── Build PluginContext{Logger, Args, CniArgs, NetConf, CiliumConf}
  │
  └── chainAction.Add(ctx, pluginContext, ciliumClient)
        │
        └── [Example: GenericVethChainer.Add()]  [chaining/generic-veth/generic-veth.go]
              │  (Used by: generic-veth, aws-cni, azure, flannel)
              │
              ├── cniVersion.ParsePrevResult()
              ├── cniTypesV1.NewResultFromResult()
              │
              ├── ns.Do(func() {                   // Enter container netns
              │     ├── List all links, find the veth interface
              │     ├── Extract: vethLXCMac, vethLXCName, peerIndex
              │     ├── Get IPv4 address (AddrList FAMILY_V4)
              │     ├── Get IPv6 address (AddrList FAMILY_V6)
              │     └── Optionally adjust route MTU if EnableRouteMTU
              │   })
              │
              ├── netlink.LinkByIndex(peerIndex)   // Get host-side veth peer
              │     └── Extract: hostMac, vethHostName, vethHostIdx
              │
              ├── Build EndpointChangeRequest{
              │     Addressing, ContainerID, State, HostMac, InterfaceIndex,
              │     Mac, InterfaceName, ContainerInterfaceName, K8s metadata,
              │     SyncBuildEndpoint: true,
              │     DatapathConfiguration: {
              │       RequireArpPassthrough: true,
              │       RequireEgressProg: true,
              │       ExternalIpam: true,
              │       RequireRouting: false
              │     }
              │   }
              │
              ├── cli.EndpointCreate(ep)           // Create endpoint in Cilium agent
              │
              ├── If agent returns new MAC → ns.Do(mac.ReplaceMacAddressWithLinkName())
              │
              └── Return prevResult (pass-through CNI result)
```

### ADD — Standard Mode Path (Linux)

When cilium-cni operates as the primary (non-chained) CNI plugin on Linux:

```
Standard Mode ADD (Linux) [cmd/cmd_linux.go]
  │
  ├── cfg.GetConfigurations(params)                // [cmd/endpoint.go]
  │     └── DefaultConfigurator.GetConfigurations()
  │           └── Returns []EndpointConfiguration with IfName=args.IfName
  │
  ├── netns.OpenPinned(args.Netns)                 // Open container network namespace
  │
  ├── sysctl.NewDirectSysctl()                     // Create sysctl interface
  │
  └── FOR EACH epConf in configs:
        │
        ├── ns.Do: link.DeleteByName(epConf.IfName())    // Clean up any stale interface
        │
        ├── IP Allocation (branch by IPAM mode):
        │   ├── IPAMDelegatedPlugin:
        │   │     └── allocateIPsWithDelegatedPlugin()    [cmd/cmd_linux.go]
        │   │           ├── cniInvoke.DelegateAdd()       // Invoke delegated IPAM plugin
        │   │           ├── Parse delegated result → IPAMResponse
        │   │           └── Extract masterMac from result interfaces
        │   └── Other IPAM modes:
        │         └── allocateIPsWithCiliumAgent()        [cmd/cmd.go]
        │               ├── client.IPAMAllocate(podName, pool)
        │               └── Return releaseFunc for cleanup on failure
        │
        ├── connector.SufficientAddressing(ipam.HostAddressing)
        │
        ├── Validate: ipv6IsEnabled || ipv4IsEnabled
        │
        ├── Invoke onIPAMReady hooks
        │     └── foreach hook: hook.OnIPAMReady(ipam)
        │
        ├── epConf.PrepareEndpoint(ipam)                  [cmd/endpoint.go]
        │     └── Build CmdState{HostAddr} and EndpointChangeRequest{
        │           ContainerID, Labels, State, Addressing, K8s metadata,
        │           ContainerInterfaceName, DatapathConfiguration, Properties
        │         }
        │
        ├── Build LinkConfig{EndpointID, PeerIfName, PeerNamespace, MTU, etc.}
        │
        ├── Invoke onLinkConfigReady hooks (Linux only)
        │     └── foreach hook: hook.OnLinkConfigReady(&linkConfig)
        │
        ├── connector.NewLinkPair(logger, linkMode, linkConfig, sysctl)
        │     └── Create veth/netkit pair based on DatapathMode
        │
        ├── Record host-side interface info in CNI result
        │
        ├── Prepare IPv6 addressing (if enabled):
        │     ├── prepareIP(ipv6Addr, state, routeMTU)    [cmd/cmd_linux.go]
        │     │     ├── connector.IPv6Routes() → routes
        │     │     └── connector.IPv6Gateway() → gateway
        │     └── Populate ep.Addressing.IPV6, IPV6PoolName, ExpirationUUID
        │
        ├── Prepare IPv4 addressing (if enabled):
        │     ├── prepareIP(ipv4Addr, state, routeMTU)
        │     │     ├── connector.IPv4Routes() → routes
        │     │     └── connector.IPv4Gateway() → gateway
        │     └── Populate ep.Addressing.IPV4, IPV4PoolName, ExpirationUUID
        │
        ├── Host-side routing (if needsEndpointRoutingOnHost()):
        │     └── interfaceAdd(logger, ipConfig, ipam, conf)     [cmd/interface_linux.go]
        │           ├── linuxrouting.NewRoutingInfo()
        │           └── routingInfo.Configure()  // Install ip rules & routes
        │           (Applies to: ENI, Azure, AlibabaCloud, DelegatedPlugin modes)
        │
        ├── Invoke onInterfaceConfigReady hooks
        │     └── foreach hook: hook.OnInterfaceConfigReady(state, ep, res)
        │
        ├── ns.Do(func() {                          // Enter container netns
        │     ├── reserveLocalIPPorts(conf, sysctl)
        │     ├── Enable IPv6 if needed (sysctl disable_ipv6=0)
        │     └── configureIface(logger, ipam, ifName, state)
        │           ├── LinkByName(ifName)
        │           ├── LinkSetUp(link)
        │           ├── addIPConfigToLink() for IPv4
        │           │     ├── AddrAdd()
        │           │     ├── RouteAdd() for each route (sorted by mask)
        │           │     └── ReplaceRule() for each ip rule
        │           └── addIPConfigToLink() for IPv6
        │   })
        │
        ├── Get netns cookie (if supported)
        │     └── ns.Do: netns.GetNetNSCookie()
        │
        ├── c.EndpointCreate(ep)                    // Create endpoint in Cilium agent
        │     └── ep.SyncBuildEndpoint = true       // Synchronous regeneration
        │
        ├── If agent returns new MAC:
        │     └── ns.Do: mac.ReplaceMacAddressWithLinkName()
        │
        ├── ns.Do(func() {                          // Final netns configuration
        │     ├── configurePacketizationLayerPMTUD()
        │     └── configureCongestionControl()
        │   })
        │
        └── Append container-side interface to CNI result
  │
  └── cniTypes.PrintResult(res, n.CNIVersion)       // Return CNI result to runtime
```

### ADD — Standard Mode Path (Windows)

When cilium-cni operates as the primary CNI plugin on Windows:

```
Standard Mode ADD (Windows) [cmd/cmd_windows.go]
  │
  ├── cfg.GetConfigurations(params)                // Same as Linux
  │
  └── FOR EACH epConf in configs:
        │
        ├── IP Allocation (same branch logic as Linux):
        │   ├── IPAMDelegatedPlugin → allocateIPsWithDelegatedPlugin()
        │   └── Other → allocateIPsWithCiliumAgent()
        │
        ├── Validate: ipv6IsEnabled || ipv4IsEnabled
        │
        ├── Invoke onIPAMReady hooks
        │
        ├── epConf.PrepareEndpoint(ipam)
        │
        ├── Populate IPv6/IPv4 addressing directly from IPAM response
        │   (No route/rule calculation — agent handles datapath on Windows)
        │
        ├── Invoke onInterfaceConfigReady hooks
        │
        ├── c.EndpointCreate(ep)                   // Agent handles ALL datapath setup
        │     └── ep.SyncBuildEndpoint = true
        │
        └── Log success
  │
  └── cniTypes.PrintResult(res, n.CNIVersion)
```

**Key Difference (Windows):** No veth/netkit pair creation, no netns operations, no sysctl configuration, no host-side routing. The Cilium agent is responsible for all datapath setup (network adapter configuration, etc.).

---

## CNI DEL Operation

### DEL — Common Initialization

```
Cmd.Del(args *skel.CmdArgs) [cmd/cmd_linux.go or cmd/cmd_windows.go]
  │
  ├── 1. types.LoadNetConf(args.StdinData)
  │
  ├── 2. cmd.setupLogging(n)
  │
  ├── 3. buildLogAttrsWithEventID()
  │
  ├── 4. gops.Listen() (if EnableDebug)
  │
  ├── 5. cniTypes.LoadArgs(args.Args, cniArgs)
  │
  ├── 6. buildLogAttrsWithCNIArgs()
  │
  ├── 7. lib.NewDeletionFallbackClient(logger)     // NOT a direct Cilium client!
  │       └── Creates DeletionFallbackClient with:
  │             ├── Lazy connection to Cilium agent
  │             ├── Deletion queue directory (for offline fallback)
  │             └── Lockfile path for queue synchronization
  │
  └── 8. Branch: Chaining vs Standard mode
```

### DEL — Chaining Mode Path

```
Chaining Mode DEL
  │
  ├── getChainedAction(n, logger)
  │
  ├── Build PluginContext{Logger, Args, CniArgs, NetConf}
  │     (Note: No CiliumConf — agent config is not fetched during DEL)
  │
  └── chainAction.Delete(ctx, pluginContext, delClient)
        │
        └── [Example: GenericVethChainer.Delete()]
              └── delClient.EndpointDeleteMany(req)
                    └── (See Deletion Fallback Queue section below)
```

### DEL — Standard Mode Path (Linux)

```
Standard Mode DEL (Linux) [cmd/cmd_linux.go]
  │
  ├── c.EndpointDeleteMany(req)                    // Delete via DeletionFallbackClient
  │     └── req = {ContainerID: args.ContainerID}
  │     └── (See Deletion Fallback Queue section for retry/fallback logic)
  │
  ├── If n.IPAM.Type != "" (delegated IPAM):
  │     └── cniInvoke.DelegateDel()                // Release IP via delegated plugin
  │         (Done BEFORE entering netns — ns may already be deleted)
  │
  ├── netns.OpenPinned(args.Netns)
  │     ├── If os.IsNotExist → return nil (namespace gone, interface already deleted)
  │     └── If other error → return error (fatal)
  │
  └── ns.Do(func() {                               // Enter container netns
        └── link.DeleteByName(args.IfName)          // Delete the container interface
      })
      ├── If error → log warning (not fatal, unlikely recoverable)
      └── Return nil
```

### DEL — Standard Mode Path (Windows)

```
Standard Mode DEL (Windows) [cmd/cmd_windows.go]
  │
  ├── c.EndpointDeleteMany(req)                    // Delete via DeletionFallbackClient
  │     └── req = {ContainerID: args.ContainerID}
  │
  ├── If n.IPAM.Type != "" (delegated IPAM):
  │     └── cniInvoke.DelegateDel()
  │
  └── Return nil
      (No netns or interface cleanup — agent handles all datapath teardown)
```

---

## Key Data Structures

### `Cmd` struct (platform-specific)

| Field                    | Type                       | Description                                 |
|--------------------------|----------------------------|---------------------------------------------|
| `logger`                 | `*slog.Logger`             | Scoped logger for CNI operations            |
| `version`                | `string`                   | Plugin version string                       |
| `cfg`                    | `EndpointConfigurator`     | Endpoint configuration factory              |
| `onConfigReady`          | `[]OnConfigReady`          | Hooks after config loaded                   |
| `onIPAMReady`            | `[]OnIPAMReady`            | Hooks after IPAM response received          |
| `onLinkConfigReady`      | `[]OnLinkConfigReady`      | Hooks before link creation (Linux only)     |
| `onInterfaceConfigReady` | `[]OnInterfaceConfigReady` | Hooks before endpoint creation              |

### `CmdState` struct

**Linux:**
| Field       | Type                    | Description            |
|-------------|-------------------------|------------------------|
| `IP6`       | `netip.Addr`            | IPv6 address           |
| `IP6routes` | `[]route.Route`         | IPv6 routes            |
| `IP6rules`  | `[]route.Rule`          | IPv6 ip rules          |
| `IP4`       | `netip.Addr`            | IPv4 address           |
| `IP4routes` | `[]route.Route`         | IPv4 routes            |
| `IP4rules`  | `[]route.Rule`          | IPv4 ip rules          |
| `HostAddr`  | `*models.NodeAddressing`| Host node addressing   |

**Windows** (simplified — no routes/rules):
| Field      | Type                    | Description            |
|------------|-------------------------|------------------------|
| `IP6`      | `netip.Addr`            | IPv6 address           |
| `IP4`      | `netip.Addr`            | IPv4 address           |
| `HostAddr` | `*models.NodeAddressing`| Host node addressing   |

### Hook Interfaces

| Hook Interface           | When Invoked                                | Purpose                                     |
|--------------------------|---------------------------------------------|---------------------------------------------|
| `OnConfigReady`          | After agent config loaded                   | Initialize state from config                |
| `OnIPAMReady`            | After IPAM allocation validated             | Derive endpoint config from IPAM            |
| `OnLinkConfigReady`      | Before link pair creation (Linux only)      | Modify link configuration                   |
| `OnInterfaceConfigReady` | Before endpoint creation request            | Modify endpoint request / CNI result        |

---

## Chaining Plugin Registry

Chaining plugins register themselves via `init()` functions using `chainingapi.Register(name, plugin)`.

| Plugin Name    | Implementation               | File                                    |
|----------------|------------------------------|-----------------------------------------|
| `generic-veth` | `GenericVethChainer`         | `chaining/generic-veth/generic-veth.go` |
| `aws-cni`      | `GenericVethChainer` (reuse) | `chaining/awscni/aws-cni.go`           |
| `azure`         | `GenericVethChainer` (reuse) | `chaining/azure/azure-cni.go`          |
| `flannel`       | `GenericVethChainer` (reuse) | `chaining/flannel/flannel.go`          |

All current chaining plugins delegate to `GenericVethChainer`, which:
- **ADD:** Discovers the veth pair created by the previous plugin, extracts addressing info, and creates a Cilium endpoint with `ExternalIpam: true`.
- **DEL:** Calls `EndpointDeleteMany` via `DeletionFallbackClient`.

---

## Deletion Fallback Queue

The `DeletionFallbackClient` (`lib/deletion_queue.go`) provides resilient endpoint deletion that survives Cilium agent unavailability:

```
DeletionFallbackClient.EndpointDeleteMany(req)
  │
  ├── Step 1: Try direct API call
  │     ├── tryConnect() → Lazy connect to Cilium agent socket
  │     │     └── If agent is bootstrapping (socket doesn't exist yet):
  │     │           └── Retry up to 3 times with 5s backoff
  │     └── cli.EndpointDeleteMany(req)
  │           ├── Success → return nil
  │           └── HTTP 503 (unavailable) → proceed to fallback
  │
  ├── Step 2: Acquire shared lock on deletion queue
  │     └── tryQueueLock()
  │           ├── os.MkdirAll(deleteQueueDir)
  │           ├── lockfile.NewLockfile(deleteQueueLockfile)
  │           └── lf.Lock(ctx, shared=false) with 1.5s timeout
  │
  ├── Step 3: Retry API call under lock
  │     └── deleteEndpointsBatch(req) — same logic as Step 1
  │
  └── Step 4: If still failing → enqueue to disk
        └── enqueueDeletionRequestLocked(req)
              ├── Marshal request to binary
              ├── Check queue size (max 256 files)
              ├── Write to <sha256-hash>.delete file
              └── Cilium agent processes queue on next startup
```

---

## ASCII Call Flow Diagrams

### CNI ADD — High-Level Flow

```
┌─────────────┐     ┌──────────────┐     ┌─────────────────────┐
│  Container   │     │   kubelet    │     │    cilium-cni        │
│  Runtime     │────>│  (via CNI)   │────>│    main()            │
└─────────────┘     └──────────────┘     └─────────┬───────────┘
                                                    │
                                                    v
                                           ┌────────────────┐
                                           │  PluginMain()   │
                                           │  skel dispatch  │
                                           └───────┬────────┘
                                                   │ CMD=ADD
                                                   v
                                           ┌────────────────┐
                                           │   Cmd.Add()     │
                                           └───────┬────────┘
                                                   │
                                    ┌──────────────┼──────────────┐
                                    │              │              │
                                    v              │              v
                          ┌─────────────┐          │    ┌─────────────────┐
                          │ LoadNetConf  │          │    │ Connect to      │
                          │ + LoadArgs   │          │    │ Cilium Agent    │
                          └──────┬──────┘          │    └────────┬────────┘
                                 │                 │             │
                                 v                 │             v
                          ┌──────────────┐         │    ┌────────────────┐
                          │ Setup Logging│         │    │ getConfigFrom  │
                          └──────┬───────┘         │    │ CiliumAgent()  │
                                 │                 │    └────────┬───────┘
                                 └─────────────────┘             │
                                                                 v
                                                    ┌────────────────────┐
                                                    │ RawPrevResult?     │
                                                    └───┬────────────┬───┘
                                              Yes       │            │  No
                                                        v            v
                                               ┌──────────┐  ┌──────────────┐
                                               │ Chaining  │  │  Standard    │
                                               │ Mode ADD  │  │  Mode ADD   │
                                               └────┬─────┘  └──────┬───────┘
                                                    │               │
                                                    v               v
                                            ┌─────────────┐  ┌────────────────────┐
                                            │ chainAction  │  │ For each endpoint: │
                                            │ .Add()       │  │ IPAM → Link →      │
                                            └──────┬──────┘  │ Configure → Create  │
                                                   │         └─────────┬──────────┘
                                                   v                   v
                                         ┌────────────────┐  ┌────────────────────┐
                                         │EndpointCreate() │  │ EndpointCreate()   │
                                         └────────┬───────┘  └────────┬───────────┘
                                                  │                   │
                                                  v                   v
                                          ┌──────────────┐   ┌──────────────────┐
                                          │ PrintResult  │   │  PrintResult     │
                                          └──────────────┘   └──────────────────┘
```

### CNI DEL — High-Level Flow

```
┌─────────────┐     ┌──────────────┐     ┌─────────────────────┐
│  Container   │     │   kubelet    │     │    cilium-cni        │
│  Runtime     │────>│  (via CNI)   │────>│    main()            │
└─────────────┘     └──────────────┘     └─────────┬───────────┘
                                                    │
                                                    v
                                           ┌────────────────┐
                                           │  PluginMain()   │
                                           │  skel dispatch  │
                                           └───────┬────────┘
                                                   │ CMD=DEL
                                                   v
                                           ┌────────────────┐
                                           │   Cmd.Del()     │
                                           └───────┬────────┘
                                                   │
                                    ┌──────────────┼──────────────┐
                                    │              │              │
                                    v              │              v
                          ┌─────────────┐          │    ┌──────────────────────┐
                          │ LoadNetConf  │          │    │ NewDeletionFallback  │
                          │ + LoadArgs   │          │    │ Client(logger)       │
                          └──────┬──────┘          │    └────────┬─────────────┘
                                 │                 │             │
                                 └─────────────────┘             v
                                                    ┌────────────────────┐
                                                    │ Chaining mode?     │
                                                    └───┬────────────┬───┘
                                              Yes       │            │  No
                                                        v            v
                                               ┌──────────┐  ┌─────────────────┐
                                               │ Chaining  │  │  Standard       │
                                               │ Mode DEL  │  │  Mode DEL      │
                                               └────┬─────┘  └──────┬──────────┘
                                                    │               │
                                                    v               v
                                            ┌─────────────┐  ┌──────────────────┐
                                            │ chainAction  │  │EndpointDeleteMany│
                                            │ .Delete()    │  └──────┬───────────┘
                                            └──────┬──────┘         │
                                                   │                v
                                                   │         ┌──────────────────┐
                                                   │         │DelegateDel  (if  │
                                                   │         │delegated IPAM)   │
                                                   │         └──────┬───────────┘
                                                   │                │
                                                   v                v
                                           ┌─────────────────┐  ┌─────────────────┐
                                           │EndpointDeleteMany│  │ Delete interface│ (Linux only)
                                           └─────────────────┘  │ in container    │
                                                                 │ netns           │
                                                                 └─────────────────┘
```

### Endpoint Deletion Fallback — Detailed Flow

```
EndpointDeleteMany(req)
        │
        v
┌───────────────────┐     ┌──────────────────┐
│ tryConnect()      │────>│ Agent available?  │
└───────────────────┘     └───┬──────────┬───┘
                        Yes   │          │  No
                              v          v
                     ┌────────────┐  ┌────────────────┐
                     │ Direct API │  │ Agent starting? │
                     │ Delete     │  └──┬──────────┬──┘
                     └──┬─────┬──┘  Yes │          │ No
                  OK    │     │Fail     v          v
                        v     │   ┌──────────┐  ┌──────────────┐
                     return   │   │ Retry 3x │  │ Take queue   │
                     nil      │   │ (5s each)│  │ lock         │
                              │   └────┬─────┘  └──────┬───────┘
                              │        │               │
                              v        v               v
                     ┌────────────────────┐   ┌────────────────┐
                     │ Return error       │   │ Retry API call │
                     │ (propagate to      │   └──┬──────────┬──┘
                     │  kubelet)          │ OK   │          │ Fail
                     └────────────────────┘      v          v
                                            return    ┌──────────────┐
                                            nil       │ Enqueue to   │
                                                      │ disk (.delete│
                                                      │ file)        │
                                                      └──────────────┘
```

---

## File Reference

| File | Purpose |
|------|---------|
| `main.go` | Binary entry point, calls `cmd.PluginMain()` |
| `cmd/cmd.go` | Shared logic: `PluginMain()`, config loading, logging, helpers |
| `cmd/cmd_linux.go` | Linux `Add()`, `Del()`, `Check()` implementations |
| `cmd/cmd_windows.go` | Windows `Add()`, `Del()`, `Check()` implementations |
| `cmd/hooks.go` | Hook interfaces: `OnConfigReady`, `OnIPAMReady`, `OnInterfaceConfigReady` |
| `cmd/hooks_linux.go` | Linux-only hook: `OnLinkConfigReady` |
| `cmd/endpoint.go` | `EndpointConfigurator` interface, `DefaultConfigurator`, `PrepareEndpoint()` |
| `cmd/endpoint_linux.go` | `ifindexFromMac()` for ENI IPAM |
| `cmd/endpoint_windows.go` | Stub `ifindexFromMac()` |
| `cmd/interface_linux.go` | `interfaceAdd()` — host-side routing for ENI/Azure/AlibabaCloud |
| `cmd/interface_windows.go` | Stub `interfaceAdd()` |
| `chaining/api/api.go` | `ChainingPlugin` interface, `Register()`, `Lookup()` |
| `chaining/generic-veth/generic-veth.go` | `GenericVethChainer` — shared chaining implementation |
| `chaining/awscni/aws-cni.go` | Registers `aws-cni` → `GenericVethChainer` |
| `chaining/azure/azure-cni.go` | Registers `azure` → `GenericVethChainer` |
| `chaining/flannel/flannel.go` | Registers `flannel` → `GenericVethChainer` |
| `lib/deletion_queue.go` | `DeletionFallbackClient` with offline queue support |
| `types/types.go` | `NetConf`, `ArgsSpec`, `LoadNetConf()` |
