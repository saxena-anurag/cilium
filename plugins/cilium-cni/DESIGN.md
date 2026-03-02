# Cilium CNI Plugin — Design Document

## Table of Contents

1. [Overview](#1-overview)
2. [How cilium-cni Is Invoked](#2-how-cilium-cni-is-invoked)
3. [CNI Operations (ADD / DEL / CHECK / STATUS)](#3-cni-operations)
4. [Cilium Agent API Interactions](#4-cilium-agent-api-interactions)
5. [What the Plugin Does vs. What the Agent Does](#5-what-the-plugin-does-vs-what-the-agent-does)
6. [Windows vs. Linux Implementation Differences](#6-windows-vs-linux-implementation-differences)
7. [Chaining Mode](#7-chaining-mode)
8. [Deletion Queue / Fallback Client](#8-deletion-queue--fallback-client)
9. [File Layout & Build Tags](#9-file-layout--build-tags)

---

## 1. Overview

`cilium-cni` is a [CNI (Container Network Interface)](https://github.com/containernetworking/cni) plugin binary. It is the component that is invoked by the container runtime (kubelet / containerd / CRI-O) whenever a pod is created, destroyed, or checked. It does **not** run as a long-lived daemon—it is a short-lived process that executes a single CNI verb (ADD, DEL, CHECK, or STATUS) and exits.

The plugin acts as a **thin client** to the Cilium agent (`cilium-agent`), which is the long-lived daemon responsible for all datapath programming (eBPF maps, network interfaces, routing rules, etc.). The plugin's primary responsibilities are:

- Receiving the CNI call from the container runtime.
- Communicating with `cilium-agent` via its REST API (over a Unix socket).
- Performing minimal host-side setup (interface creation on Linux, nothing on Windows).
- Returning the CNI result (IP addresses, routes, interfaces) to the runtime.

### Entry Point

```
plugins/cilium-cni/main.go
    → cmd.PluginMain()
        → skel.PluginMainFuncs(Add, Del, Check, Status)
```

`main.go` calls `runtime.LockOSThread()` in `init()` (required for Linux network namespace operations) and delegates to `cmd.PluginMain()`.

---

## 2. How cilium-cni Is Invoked

### 2.1 Invocation by the Container Runtime

The kubelet (or another CRI-compatible runtime) invokes `cilium-cni` as an executable. The CNI specification defines the calling convention:

| Mechanism | Description |
|-----------|-------------|
| **Environment Variables** | `CNI_COMMAND` (ADD/DEL/CHECK/STATUS), `CNI_CONTAINERID`, `CNI_NETNS`, `CNI_IFNAME`, `CNI_ARGS`, `CNI_PATH` |
| **Stdin** | JSON network configuration (the contents of the CNI config file, e.g., `/etc/cni/net.d/05-cilium.conflist`) |
| **Stdout** | JSON CNI result (on success for ADD) |
| **Exit code** | 0 on success, non-zero on failure |

The CNI framework library (`github.com/containernetworking/cni/pkg/skel`) parses these and dispatches to the appropriate handler.

### 2.2 Installation

The plugin binary is installed to the host's CNI bin directory (typically `/opt/cni/bin/cilium-cni`) by the `install-plugin.sh` script, which runs as part of the Cilium agent init container. The script performs an atomic copy-then-rename to avoid partial writes.

### 2.3 CNI Configuration

A typical CNI configuration file (`05-cilium.conflist`) references `cilium-cni` as the plugin type. The configuration is parsed into `types.NetConf`, which extends the standard `cniTypes.NetConf` with Cilium-specific fields:

```go
type NetConf struct {
    cniTypes.NetConf
    MTU          int
    ENI          eniTypes.ENISpec
    Azure        azureTypes.AzureSpec
    AlibabaCloud alibabaCloudTypes.Spec
    IPAM         IPAM             // may specify a delegated IPAM plugin
    EnableDebug  bool
    LogFormat    string
    LogFile      string
    ChainingMode string           // e.g., "aws-cni", "azure", "flannel", "generic-veth"
}
```

### 2.4 PluginMain Registration

```go
func PluginMain(opts ...Option) {
    cmd := &Cmd{
        logger:  logger,
        version: "Cilium CNI plugin " + version.Version,
        cfg:     &DefaultConfigurator{},
    }
    // Apply functional options (custom endpoint configurator, hooks, etc.)

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
```

Supported CNI spec versions: **0.1.0 through 1.1.0**.

---

## 3. CNI Operations

### 3.1 ADD — Create Network for a Container

The ADD operation is the most complex. It sets up networking for a newly created pod.

**High-level flow (both platforms):**

```
1. Parse CNI config (LoadNetConf)
2. Setup logging
3. Parse CNI_ARGS (K8S_POD_NAME, K8S_POD_NAMESPACE, K8S_POD_UID)
4. Connect to Cilium agent (Unix socket)
5. Fetch agent configuration (ConfigGet)
6. Fire OnConfigReady hooks
7. Check for chaining mode → if chained, delegate to chain plugin
8. Get endpoint configurations (EndpointConfigurator)
9. Allocate IPs (via agent IPAM or delegated IPAM plugin)
10. Fire OnIPAMReady hooks
11. PrepareEndpoint (build EndpointChangeRequest model)
12. [Platform-specific: create interfaces, configure routes]
13. Fire OnInterfaceConfigReady hooks
14. Call agent EndpointCreate API
15. Return CNI Result (IPs, routes, interfaces)
```

**Linux-specific steps (between 11 and 14):**
- Open the container's network namespace (`netns.OpenPinned`)
- Delete any pre-existing interface in the netns
- Create a veth/netkit link pair via `connector.NewLinkPair`
- Configure IP addresses and routes inside the netns (`configureIface`)
- Set sysctl parameters (IPv6 enable, congestion control, PMTUD, reserved ports)
- Get the netns cookie
- Set `ContainerNetnsPath` on the endpoint
- After `EndpointCreate`, optionally set MAC address from agent response

**Windows-specific steps:**
- No interface creation — the Cilium agent manages all datapath setup
- Populate IP addressing from IPAM response directly onto the CNI result
- Call `EndpointCreate` with `SyncBuildEndpoint=true`

### 3.2 DEL — Tear Down Network for a Container

**High-level flow:**

```
1. Parse CNI config
2. Setup logging
3. Parse CNI_ARGS
4. Create DeletionFallbackClient (handles agent-down scenarios)
5. Check for chaining mode → if chained, delegate
6. Call EndpointDeleteMany on the agent (by ContainerID)
7. If delegated IPAM, invoke DelegateDel
8. [Platform-specific cleanup]
```

**Linux-specific:**
- Open the container's network namespace
- Delete the container-side interface via `link.DeleteByName`
- Gracefully handle missing namespace (pod may already be gone)

**Windows-specific:**
- No CNI-side cleanup — the agent handles all datapath teardown when the endpoint is deleted via the API

### 3.3 CHECK — Verify Container Network Health

**High-level flow:**

```
1. Parse CNI config
2. Setup logging, parse CNI_ARGS
3. Connect to Cilium agent
4. Check for chaining mode → if chained, delegate
5. Query agent for endpoint health (EndpointHealthGet)
6. Verify endpoint is healthy
7. Parse PrevResult
8. Verify interface exists and has expected IPs
```

**Linux-specific:**
- `verifyInterface` enters the container netns via `netns.OpenPinned`
- Uses `netlink.LinkByName` and `netlink.AddrList` to verify interface and IPs

**Windows-specific:**
- `verifyInterface` uses Go standard library `net.InterfaceByName` and `iface.Addrs()`
- No netns traversal required

### 3.4 STATUS — Check Plugin Readiness

**Flow (cross-platform, defined in `cmd.go`):**

```
1. Parse CNI config
2. Connect to Cilium agent
3. If chained → delegate to chain plugin Status
4. Call agent Healthz endpoint
5. If delegated IPAM → invoke DelegateStatus on IPAM plugin
```

This is used by runtimes to determine if the CNI plugin is ready to accept ADD requests.

---

## 4. Cilium Agent API Interactions

The plugin communicates with `cilium-agent` over a Unix domain socket. The socket path is platform-dependent:

| Platform | Default Socket Path |
|----------|-------------------|
| Linux | `/var/run/cilium/cilium.sock` |
| Windows | `C:\var\run\cilium\cilium.sock` |

The path can be overridden via the `CILIUM_SOCK` environment variable.

### API Calls Made by the Plugin

| API Call | CNI Verb | Purpose |
|----------|----------|---------|
| `ConfigGet` | ADD | Retrieve agent's daemon configuration (IPAM mode, addressing, MTU, datapath mode, etc.) |
| `IPAMAllocate` | ADD | Allocate IP addresses for the new endpoint |
| `IPAMReleaseIP` | ADD (on failure) | Release allocated IPs if endpoint creation fails |
| `EndpointCreate` | ADD | Create the endpoint in the agent; agent programs BPF, sets up datapath |
| `EndpointDeleteMany` | DEL | Delete endpoint(s) by container ID; agent tears down datapath |
| `EndpointHealthGet` | CHECK | Query health status of an endpoint by its CNI attachment ID |
| `Daemon.GetHealthz` | STATUS | Health check on the agent daemon |

### Endpoint Identification

Endpoints are identified by a **CNI Attachment ID** of the form:

```
cni-attachment-id:<containerID>:<ifName>
```

This is constructed via `endpointid.NewCNIAttachmentID(containerID, ifName)`.

### EndpointChangeRequest

The `EndpointCreate` call sends an `EndpointChangeRequest` model containing:

```go
&models.EndpointChangeRequest{
    ContainerID:            containerID,
    Labels:                 models.Labels{},
    State:                  "waiting-for-identity",
    Addressing:             &models.AddressPair{IPV4: ..., IPV6: ...},
    K8sPodName:             podName,
    K8sNamespace:           namespace,
    K8sUID:                 uid,
    ContainerInterfaceName: ifName,
    DatapathConfiguration:  &models.EndpointDatapathConfiguration{},
    SyncBuildEndpoint:      true,
    // Linux-only fields:
    Mac:                    peerMAC,
    HostMac:                hostMAC,
    InterfaceIndex:         hostIfIndex,
    InterfaceName:          hostIfName,
    ContainerNetnsPath:     netnsPath,
    NetnsCookie:            cookie,
}
```

---

## 5. What the Plugin Does vs. What the Agent Does

### Plugin Responsibilities (cilium-cni)

| Responsibility | Linux | Windows |
|----------------|-------|---------|
| Parse CNI config and arguments | ✅ | ✅ |
| Connect to agent socket | ✅ | ✅ |
| Fetch agent configuration | ✅ | ✅ |
| Allocate IPs (via agent or delegated plugin) | ✅ | ✅ |
| Create veth/netkit link pair | ✅ | ❌ (agent does it) |
| Enter container netns | ✅ | ❌ |
| Configure IPs/routes inside container | ✅ | ❌ (agent does it) |
| Set sysctl parameters in container | ✅ | ❌ |
| Install host-side IP rules/routes (ENI modes) | ✅ | ❌ |
| Send EndpointCreate to agent | ✅ | ✅ |
| Delete container interface on DEL | ✅ | ❌ (agent does it) |
| Send EndpointDeleteMany to agent | ✅ | ✅ |
| Queue deletion if agent unreachable | ✅ | ✅ |
| Verify interface on CHECK | ✅ (via netlink in netns) | ✅ (via `net.InterfaceByName`) |
| Return CNI result | ✅ | ✅ |

### Agent Responsibilities (cilium-agent)

| Responsibility | Description |
|----------------|-------------|
| IPAM | Allocate/release IPs from configured pool |
| Endpoint lifecycle | Create, update, delete endpoints |
| BPF datapath | Compile and attach BPF programs to interfaces |
| Policy | Apply network policies to endpoints |
| Identity | Assign security identities to endpoints |
| Health | Track endpoint health status |
| **Windows datapath** | Create/configure/remove network adapters, HNS endpoints, etc. |
| Deletion queue replay | On startup, replay queued deletion requests from the fallback directory |

**Key insight:** On Linux, the plugin performs significant datapath setup (creating interfaces, configuring addresses and routes). On Windows, the plugin is a thin client — **all datapath operations are delegated to the agent**.

---

## 6. Windows vs. Linux Implementation Differences

### 6.1 Build Tags & File Organization

The codebase is split using Go build tags:

| File | Build Tag | Description |
|------|-----------|-------------|
| `cmd.go` | (none) | Cross-platform: `PluginMain`, `Status`, helpers |
| `cmd_linux.go` | `linux` | Full Linux ADD/DEL/CHECK with netlink, netns, connectors |
| `cmd_windows.go` | `windows` | Windows ADD/DEL/CHECK — agent-only model |
| `hooks.go` | (none) | Cross-platform hook interfaces |
| `hooks_linux.go` | `linux` | `OnLinkConfigReady` hook (uses `datapath/types`) |
| `endpoint.go` | (none) | Cross-platform endpoint configurator interfaces |
| `endpoint_linux.go` | `linux` | `ifindexFromMac` via netlink |
| `endpoint_windows.go` | `windows` | `ifindexFromMac` stub |
| `interface_linux.go` | `linux` | Host-side route/rule setup for ENI modes |
| `interface_windows.go` | `windows` | `interfaceAdd` stub (not applicable) |

### 6.2 Struct Differences

**Linux `Cmd` struct:**
```go
type Cmd struct {
    logger                 *slog.Logger
    version                string
    cfg                    EndpointConfigurator
    onConfigReady          []OnConfigReady
    onIPAMReady            []OnIPAMReady
    onLinkConfigReady      []OnLinkConfigReady    // Linux-only
    onInterfaceConfigReady []OnInterfaceConfigReady
}
```

**Windows `Cmd` struct:**
```go
type Cmd struct {
    logger                 *slog.Logger
    version                string
    cfg                    EndpointConfigurator
    onConfigReady          []OnConfigReady
    onIPAMReady            []OnIPAMReady
    // No onLinkConfigReady — Windows doesn't create link pairs
    onInterfaceConfigReady []OnInterfaceConfigReady
}
```

**Linux `CmdState`:**
```go
type CmdState struct {
    IP6       netip.Addr
    IP6routes []route.Route    // Linux-only
    IP6rules  []route.Rule     // Linux-only
    IP4       netip.Addr
    IP4routes []route.Route    // Linux-only
    IP4rules  []route.Rule     // Linux-only
    HostAddr  *models.NodeAddressing
}
```

**Windows `CmdState`:**
```go
type CmdState struct {
    IP6      netip.Addr
    IP4      netip.Addr
    HostAddr *models.NodeAddressing
}
```

### 6.3 ADD Differences

| Aspect | Linux | Windows |
|--------|-------|---------|
| Network namespace | Opens pinned netns, enters it for interface configuration | No netns operations |
| Interface creation | Creates veth/netkit pair via `connector.NewLinkPair` | None — agent creates adapters |
| IP configuration | Calls `configureIface` → `netlink.AddrAdd`, `netlink.RouteAdd` inside netns | None — agent configures IPs |
| Sysctl | Configures `disable_ipv6`, `tcp_congestion_control`, `ip_local_reserved_ports`, PMTUD | None |
| Host-side routes | `interfaceAdd` for ENI/Azure/AlibabaCloud IPAM modes | Not applicable |
| MAC address | Sets container MAC from agent response via `mac.ReplaceMacAddressWithLinkName` | Not applicable |
| Netns cookie | Reads via `netns.GetNetNSCookie()` | Not applicable (`getNetnsCookie = false`) |
| `ContainerNetnsPath` | Set on endpoint to `<NetNsPath>/<base(netns)>` | Not set |
| Result interfaces | Includes host-side and container-side interfaces with MACs | IPs only — no interface details |

### 6.4 DEL Differences

| Aspect | Linux | Windows |
|--------|-------|---------|
| Endpoint deletion | `EndpointDeleteMany` via `DeletionFallbackClient` | Same |
| Delegated IPAM release | `DelegateDel` | Same |
| Interface removal | Opens netns, calls `link.DeleteByName` | None — agent handles cleanup |
| Missing netns handling | Gracefully handles `os.IsNotExist` | Not applicable |

### 6.5 CHECK Differences

| Aspect | Linux | Windows |
|--------|-------|---------|
| Endpoint health | `EndpointHealthGet` by CNI attachment ID | Same |
| Interface verification | Enters netns, uses `netlink.LinkByName` + `netlink.AddrList` | Uses `net.InterfaceByName` + `iface.Addrs()` |
| Signature of `verifyInterface` | `verifyInterface(netnsPinPath, ifName string, expected *Result)` | `verifyInterface(ifName string, expected *Result)` |

### 6.6 Platform Defaults

| Constant | Linux | Windows |
|----------|-------|---------|
| `RuntimePath` | `/var/run/cilium` | `C:\var\run\cilium` |
| `LibraryPath` | `/var/lib/cilium` | `C:\var\lib\cilium` |
| `SockPath` | `/var/run/cilium/cilium.sock` | `C:\var\run\cilium\cilium.sock` |
| `DeleteQueueDir` | `/var/run/cilium/deleteQueue` | `C:\var\run\cilium\deleteQueue` |
| `BPFFSRoot` | `/sys/fs/bpf` | `""` (not applicable) |
| `DefaultCgroupRoot` | `/run/cilium/cgroupv2` | `""` (not applicable) |
| `NetNsPath` | `/var/run/cilium/netns` | `""` (not applicable) |

### 6.7 Chaining Plugins

All chaining plugins are **Linux-only** (build tag `//go:build linux`):

| Plugin | Registered Name | Implementation |
|--------|----------------|----------------|
| `generic-veth` | `generic-veth` | Full veth-based chaining |
| `aws-cni` | `aws-cni` | Delegates to `GenericVethChainer` |
| `azure` | `azure` | Delegates to `GenericVethChainer` |
| `flannel` | `flannel` | Delegates to `GenericVethChainer` |

On Windows, no chaining plugins are registered. If a chaining mode is configured, `getChainedAction` will return `nil, nil` (no match found) and the plugin will proceed with standard (non-chained) flow.

### 6.8 Lockfile Implementation

The deletion queue uses a lockfile for concurrency control:

| Platform | Implementation |
|----------|---------------|
| Linux | `flock()` syscall via `unix.Flock` |
| Windows | `LockFileEx` / `UnlockFileEx` via `golang.org/x/sys/windows` |
| Other | Returns "not implemented" error |

### 6.9 Dependencies Not Used on Windows

These Linux-specific packages are **not compiled** on Windows:

- `github.com/vishvananda/netlink` — Linux netlink socket interface
- `github.com/cilium/cilium/pkg/datapath/connector` — veth/netkit link creation
- `github.com/cilium/cilium/pkg/datapath/linux/route` — Linux routing table manipulation
- `github.com/cilium/cilium/pkg/datapath/linux/safenetlink` — Safe netlink wrappers
- `github.com/cilium/cilium/pkg/datapath/linux/sysctl` — sysctl parameter management
- `github.com/cilium/cilium/pkg/datapath/link` — Link deletion
- `github.com/cilium/cilium/pkg/datapath/types` — `LinkConfig` struct
- `github.com/cilium/cilium/pkg/netns` — Network namespace operations
- `github.com/cilium/cilium/pkg/mac` — MAC address replacement
- `github.com/cilium/cilium/pkg/datapath/linux/routing` — ENI routing
- `github.com/cilium/cilium/pkg/endpoint` — Masquerade property constants
- `go4.org/netipx` — IP conversion utilities
- `golang.org/x/sys/unix` — Unix syscalls

---

## 7. Chaining Mode

Cilium CNI can operate as a **chained plugin**, where another CNI plugin (e.g., AWS VPC CNI, Azure CNI, Flannel) runs first to set up the basic network plumbing, and Cilium is invoked afterward to layer on policy enforcement and observability.

### Detection

Chaining is detected in two ways:
1. **Explicit**: `ChainingMode` field in the CNI config (e.g., `"chaining-mode": "aws-cni"`)
2. **Implicit**: Network name matches a registered chaining plugin name (except `"cilium"` and `"portmap"`)

### Chaining Plugin Interface

```go
type ChainingPlugin interface {
    Add(ctx, pluginContext, client) (*Result, error)
    Delete(ctx, pluginContext, delClient) error
    Check(ctx, pluginContext, client) error
    Status(ctx, pluginContext, client) error
}
```

### Flow When Chained

When a `PrevResult` is present in the CNI config and a valid chaining mode is detected:

- **ADD**: The chain plugin's `Add` method is called. It receives the previous result, creates the Cilium endpoint in the agent, and returns the modified result. The standard ADD flow is **skipped entirely**.
- **DEL**: The chain plugin's `Delete` method is called instead of the standard flow.
- **CHECK/STATUS**: Similarly delegated.

If `PrevResult` is present but **no** valid chaining mode is configured, ADD returns an error.

---

## 8. Deletion Queue / Fallback Client

The `DeletionFallbackClient` in `lib/deletion_queue.go` provides resilience for DEL operations when the Cilium agent is temporarily unavailable.

### Flow

```
1. Try to connect to agent and delete endpoint directly
   → Success? Done.
2. Acquire shared lock on deletion queue directory
3. Retry the deletion (agent may have come up)
   → Success? Release lock, done.
4. Write the deletion request as a file to the queue directory
5. Release lock
```

The agent replays the queue on startup.

### File Format

Deletion requests are serialized as JSON and written to files named `<sha256>.delete` in the queue directory (`/var/run/cilium/deleteQueue` on Linux, `C:\var\run\cilium\deleteQueue` on Windows).

### Safeguards

- **Lock timeout**: 1.5 seconds (must complete before kubelet times out at ~30s)
- **Max queue depth**: 256 files (prevents runaway disk usage)
- **Agent startup detection**: If the agent socket doesn't exist yet but its directory does, the client waits up to 15 seconds (3 × 5s backoff) for the agent to start

---

## 9. File Layout & Build Tags

```
plugins/cilium-cni/
├── main.go                          # Entry point → cmd.PluginMain()
├── install-plugin.sh                # Copies binary to host CNI dir
├── cni-uninstall.sh                 # Removes CNI config on uninstall
├── fipsonly.go                      # FIPS-only build tag marker
├── Makefile                         # Build targets
│
├── cmd/
│   ├── cmd.go                       # Cross-platform: PluginMain, Status, helpers
│   ├── cmd_linux.go                 # Linux: Add, Del, Check, verifyInterface, link/route setup
│   ├── cmd_windows.go               # Windows: Add, Del, Check, verifyInterface (agent-only)
│   ├── hooks.go                     # Cross-platform hooks: OnConfigReady, OnIPAMReady, OnInterfaceConfigReady
│   ├── hooks_linux.go               # Linux-only: OnLinkConfigReady
│   ├── endpoint.go                  # Cross-platform: EndpointConfigurator, DefaultConfigurator
│   ├── endpoint_linux.go            # Linux: ifindexFromMac (netlink)
│   ├── endpoint_windows.go          # Windows: ifindexFromMac (stub)
│   ├── interface_linux.go           # Linux: interfaceAdd (ENI host-side routing)
│   └── interface_windows.go         # Windows: interfaceAdd (stub)
│
├── chaining/
│   ├── api/
│   │   ├── api.go                   # ChainingPlugin interface, Register/Lookup
│   │   └── api_test.go              # Tests
│   ├── generic-veth/
│   │   └── generic-veth.go          # [linux] GenericVethChainer implementation
│   ├── awscni/
│   │   └── aws-cni.go              # [linux] Registers "aws-cni" → GenericVethChainer
│   ├── azure/
│   │   └── azure-cni.go            # [linux] Registers "azure" → GenericVethChainer
│   └── flannel/
│       └── flannel.go              # [linux] Registers "flannel" → GenericVethChainer
│
├── lib/
│   ├── deletion_queue.go            # DeletionFallbackClient, queued deletion logic
│   └── deletion_queue_test.go       # Tests
│
└── types/
    ├── types.go                     # NetConf, ArgsSpec, IPAM, error codes
    └── types_test.go                # Tests
```

### Extensibility Points

The plugin supports customization via functional options passed to `PluginMain`:

| Option | Purpose |
|--------|---------|
| `WithVersion(v)` | Override the reported version string |
| `WithEPConfigurator(cfg)` | Custom endpoint configurator (multi-endpoint support) |
| `WithOnConfigReady(hook)` | Hook after config is loaded |
| `WithOnIPAMReady(hook)` | Hook after IPAM allocation |
| `WithOnInterfaceConfigReady(hook)` | Hook before endpoint creation |
| `WithOnLinkConfigReady(hook)` | **Linux-only.** Hook before link pair creation |
