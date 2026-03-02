# Cilium Agent Windows Porting Plan — Network & Endpoint Creation

## 1. Executive Summary

This document outlines the plan to port the Cilium agent (`daemon/`) to Windows, focusing on **network creation** and **endpoint creation** as the first milestone. On Linux, Cilium creates `veth` pairs (or `netkit` devices) and configures them via netlink to plumb Pod networking. On Windows, these operations must be replaced with **Host Compute Network (HCN)** API calls.

The approach is:
1. Identify every Linux-specific API surface used in the daemon for network and endpoint creation.
2. Introduce platform abstraction interfaces where they don't already exist.
3. Add Windows implementations behind build tags (`_linux.go` / `_windows.go`).
4. Keep all platform-agnostic control-plane logic (IPAM, identity, policy repository, k8s watchers, etc.) shared.

---

## 2. Architecture Overview

### 2.1 Daemon Bootstrap Flow (relevant to network/endpoint)

```
main.go
  └─ hive.New(cmd.Agent)
       ├─ Infrastructure   (k8s client, CNI, metrics, API server, healthz, ...)
       └─ ControlPlane
            ├─ infraendpoints.Cell     ← IP allocation + host/health/ingress endpoint creation
            ├─ hostIPSyncCell          ← syncs host IPs to BPF lxcmap & IPCache
            ├─ endpointRestoreCell     ← restores endpoints from disk on restart
            ├─ endpoint.Cell           ← endpoint lifecycle (pkg/endpoint/cell)
            ├─ loadbalancer_cell.Cell  ← LB service configuration
            ├─ policy.Cell             ← policy repository
            ├─ datapath.Cell           ← **the core Linux datapath** (BPF, maps, connector)
            └─ ... (identity, ipcache, IPAM, etc.)
```

### 2.2 Key Cells for Network & Endpoint Creation

| Cell | Location | Purpose | Linux-Specific? |
|------|----------|---------|-----------------|
| `datapath.Cell` | `pkg/datapath/` | BPF program compilation, map management, connector (veth/netkit) | **Yes — heavily** |
| `infraendpoints.Cell` | `daemon/infraendpoints/` | Allocate router/health/ingress IPs; create host & ingress endpoints | Partially (netlink for IP/route mgmt) |
| `endpointRestoreCell` | `daemon/cmd/endpoint_restore.go` | Restore existing endpoints on restart | Partially (veth validation, netlink) |
| `hostIPSyncCell` | `daemon/cmd/hostips-sync.go` | Sync host IPs to LXC BPF map & IPCache | Partially (BPF map) |
| `endpoint.Cell` | `pkg/endpoint/cell/` | Endpoint object lifecycle, regeneration | Partially (BPF regeneration) |
| `cni.Cell` | `daemon/cmd/cni/` | CNI configuration writing | Platform-agnostic |
| `healthz.Cell` | `daemon/healthz/` | Agent health, kube-proxy healthz | Partially (`SO_REUSEPORT` via `unix` syscall) |

---

## 3. Linux-Specific Dependencies in `daemon/` (File-by-File Analysis)

### 3.1 `daemon/cmd/daemon_main.go`
| Import / API | Usage | Windows Equivalent |
|---|---|---|
| `github.com/cilium/ebpf/rlimit` | `rlimit.RemoveMemlock()` — removes BPF memlock limit | N/A (no eBPF on Windows); guard with build tag or no-op |
| `github.com/cilium/cilium/pkg/bpf` | `bpf.CheckOrMountFS()`, `bpf.EnableMapPreAllocation()` | N/A; no-op on Windows |
| `github.com/cilium/cilium/pkg/cgroups` | `cgroups.CheckOrMountCgrpFS()` | N/A; no-op on Windows |
| `pkg/datapath/linux/probes` | `probes.CreateHeaderFiles()`, `probes.KernelHZ()`, `probes.Jiffies()`, `probes.HaveFibLookupTbid()` | N/A; no-op / skip on Windows |
| `pkg/common.RequireRootPrivilege()` | Checks for root | Replace with Windows admin check |
| `os.Chdir`, `os.MkdirAll` | State/runtime directory setup | Works on Windows (path separators) |

### 3.2 `daemon/cmd/daemon.go`
| Import / API | Usage | Windows Equivalent |
|---|---|---|
| `pkg/datapath/linux/ipsec` | `ipsec.ProbeXfrmStateOutputMask()` | N/A; IPsec not supported on Windows initially |
| `pkg/datapath/linux/probes` | `probes.HaveFibLookupTbid()` | N/A |
| `datapath.ConnectorConfig` | Interface used to query datapath mode (veth/netkit) | Need Windows HCN implementation |

### 3.3 `daemon/cmd/endpoint_restore.go`  (**High Priority**)
| Import / API | Usage | Windows Equivalent |
|---|---|---|
| `github.com/vishvananda/netlink` | `netlink.LinkDel()`, `netlink.Link` type, veth operations | HCN endpoint deletion |
| `pkg/datapath/linux/safenetlink` | `safenetlink.LinkByName()`, `safenetlink.LinkList()` | HCN endpoint enumeration |
| `lxcmap.Map` | BPF endpoint map operations | Windows equivalent endpoint tracking (or stub) |
| `datapath.ConnectorConfig` | `GetLinkCompatibility()`, `GetOperationalMode()` | HCN-based connector config |
| `checkLink()` | Validates veth interface exists | Validate HCN endpoint exists |
| `clearStaleCiliumEndpointVeths()` | Lists and deletes stale `lxc*` veth pairs | Delete stale HCN endpoints |
| `listVethIfaces()` | Enumerates veth interfaces | Enumerate HCN endpoints |
| `ValidateConnectorPlumbing()` | Validates endpoint's network device | Validate HCN endpoint plumbing |

### 3.4 `daemon/infraendpoints/infra_ip_allocation.go`  (**High Priority**)
| Import / API | Usage | Windows Equivalent |
|---|---|---|
| `github.com/vishvananda/netlink` | `netlink.FAMILY_V4/V6`, `netlink.AddrDel()`, `netlink.LinkNotFoundError{}`, `netlink.Addr` | Windows IP helper APIs / HNS |
| `golang.org/x/sys/unix` | `unix.IFF_SLAVE` flag check | N/A on Windows |
| `pkg/datapath/linux/safenetlink` | `safenetlink.LinkByName()`, `safenetlink.AddrList()`, `safenetlink.LinkList()` | HCN/HNS network adapter queries |
| `pkg/datapath/linux/routing` | `linuxrouting.NewRoutingInfo()`, `routingInfo.Configure()` | Windows routing table APIs |
| `waitForENI()` | Polls for ENI interface by MAC | Not needed (ENI is AWS-specific) |
| `removeOldRouterState()` | Removes stale IPs from `cilium_host` device | Remove stale IPs from HCN host endpoint |

### 3.5 `daemon/infraendpoints/netdev_linux.go`  (**Already Platform-Specific**)
| Import / API | Usage | Windows Equivalent |
|---|---|---|
| `safenetlink.LinkByName()` | Get `cilium_host` device | Query HCN host endpoint |
| `safenetlink.AddrList()` | List IPs on `cilium_host` | Query HCN endpoint IPs |
| Entire file | Linux-only (`_linux.go` suffix) | Need `netdev_windows.go` |

### 3.6 `daemon/healthz/sockopt.go`
| Import / API | Usage | Windows Equivalent |
|---|---|---|
| `golang.org/x/sys/unix` | `unix.SetsockoptInt(SO_REUSEADDR, SO_REUSEPORT)` | `windows.SetsockoptInt(SO_REUSEADDR)` — `SO_REUSEPORT` doesn't exist on Windows; use `SO_EXCLUSIVEADDRUSE` or skip |
| `unix.EADDRNOTAVAIL` | Error check in healthz listeners | `windows.WSAEADDRNOTAVAIL` or equivalent `syscall` error |

### 3.7 `daemon/restapi/config.go`
| Import / API | Usage | Windows Equivalent |
|---|---|---|
| `pkg/datapath/linux/bigtcp` | BigTCP GSO/GRO size configuration | N/A on Windows initially; stub returning 0 |

---

## 4. Platform Abstraction Strategy

### 4.1 Existing Abstractions (Already Interfaces)

These are already abstracted behind interfaces and only need a Windows implementation in `pkg/`:

| Interface | Defined In | Linux Impl | Windows Impl Needed |
|-----------|-----------|------------|---------------------|
| `datapath.ConnectorConfig` | `pkg/datapath/types/` | `pkg/datapath/linux/` | `pkg/datapath/windows/` |
| `datapath.NodeAddressing` | `pkg/datapath/types/` | Linux impl | Windows impl |
| `datapath.NodeHandler` | `pkg/datapath/types/` | Linux impl | Windows impl |
| `datapath.IPsecAgent` | `pkg/datapath/types/` | Linux impl | No-op / disabled on Windows |
| `endpointcreator.EndpointCreator` | `pkg/endpoint/creator/` | Creates veth/netkit | Create HCN endpoint |
| `lxcmap.Map` | `pkg/maps/lxcmap/` | BPF map | Stub or HCN-based map |
| `mtu.MTU` | `pkg/mtu/` | Linux MTU detection | Windows MTU detection |

### 4.2 New Abstractions Needed in `daemon/`

The following code in the `daemon/` directory currently calls Linux APIs directly and needs to be abstracted:

#### 4.2.1 Endpoint Restore — Link Validation & Cleanup
**Current**: `endpoint_restore.go` calls `safenetlink.LinkByName()`, `safenetlink.LinkList()`, `netlink.LinkDel()` directly.

**Plan**: Extract into a `NetworkDeviceManager` interface:
```go
// pkg/datapath/types/device_manager.go
type NetworkDeviceManager interface {
    CheckLinkExists(name string) error
    DeleteLink(name string) error
    ListEndpointDevices() ([]EndpointDeviceInfo, error)
    ClearStaleEndpointDevices() error
}
```
- Linux: wraps netlink veth operations (current code)
- Windows: wraps HCN endpoint enumeration/deletion

#### 4.2.2 Infra IP Allocation — IP & Route Management
**Current**: `infra_ip_allocation.go` calls netlink for IP address management on `cilium_host`, route configuration via `linuxrouting`.

**Plan**: Extract into a `HostNetworkManager` interface:
```go
// pkg/datapath/types/host_network.go
type HostNetworkManager interface {
    GetHostDeviceIPs(devName string) (ipv4, ipv6 net.IP)
    RemoveStaleHostIPs(ipv6 bool, restoredIP net.IP) error
    ConfigureRouting(routingInfo RoutingInfo) error
    WaitForNetworkInterface(ctx context.Context, macAddr string) error
}
```
- Linux: wraps `safenetlink`/`netlink` calls (current code)
- Windows: wraps HCN/HNS host network management

#### 4.2.3 Health Socket Options
**Current**: `healthz/sockopt.go` uses `unix.SetsockoptInt`.

**Plan**: Use build-tagged files:
- `sockopt_linux.go` — current implementation
- `sockopt_windows.go` — Windows socket options

---

## 5. Windows HCN Mapping

### 5.1 Network Creation (Linux → Windows)

| Linux Concept | Linux API | Windows Concept | Windows API |
|---|---|---|---|
| `cilium_host` / `cilium_net` veth pair | `netlink.LinkAdd(&netlink.Veth{...})` | HCN Network + Host Endpoint | `hcn.CreateNetwork()` |
| IP on cilium_host | `netlink.AddrAdd()` | Subnet on HCN Network | HCN Network subnet config |
| Routes via cilium_host | `netlink.RouteAdd()` | HCN Network policies (route) | `hcn.NetworkPolicy` |
| BPF lxcmap | eBPF map | Windows endpoint tracking | HCN endpoint list / in-memory map |

### 5.2 Endpoint Creation (Linux → Windows)

| Linux Concept | Linux API | Windows Concept | Windows API |
|---|---|---|---|
| veth pair (lxcXXXX ↔ eth0) | `netlink.LinkAdd(&netlink.Veth{...})` | HCN Endpoint | `hcn.CreateEndpoint()` |
| Move eth0 into container netns | `netlink.LinkSetNsFd()` | Attach endpoint to container | `hcn.HotAttachEndpoint()` |
| Set IP on endpoint | `netlink.AddrAdd()` on container eth0 | HCN Endpoint IP config | Endpoint IP in `hcn.EndpointSpec` |
| Set routes in container | `netlink.RouteAdd()` in netns | HCN Endpoint route policy | `hcn.EndpointPolicy` |
| BPF programs on veth | `bpf.LoadBPFProgram()` | VFP policies / HCN policies | HCN policy attachment |
| Endpoint state dir | `/var/run/cilium/` | Endpoint state dir | `C:\ProgramData\cilium\` |

---

## 6. Phased Implementation Plan

### Phase 1: Build Infrastructure & Stubs (Week 1-2)
- Set up cross-compilation and CI for `GOOS=windows`
- Add build-tag split for files that currently import Linux-only packages
- Create no-op / stub implementations for BPF, cgroups, eBPF rlimit on Windows
- Ensure `daemon/` compiles for `GOOS=windows` with stubs

### Phase 2: Platform Abstraction Interfaces (Week 2-3)
- Define `NetworkDeviceManager` and `HostNetworkManager` interfaces
- Refactor `endpoint_restore.go` to use `NetworkDeviceManager` interface
- Refactor `infra_ip_allocation.go` to use `HostNetworkManager` interface
- Move `netdev_linux.go` counterpart to interface-based design
- Split `sockopt.go` into `sockopt_linux.go` / `sockopt_windows.go`

### Phase 3: HCN Network Creation (Week 3-5)
- Implement `pkg/datapath/windows/` HCN connector
- Implement HCN network creation (equivalent to `cilium_host`/`cilium_net` setup)
- Implement `HostNetworkManager` for Windows (IP assignment, route setup via HCN)
- Handle Windows-specific host endpoint and IP management

### Phase 4: HCN Endpoint Creation (Week 5-7)
- Implement `EndpointCreator` for Windows using HCN endpoint APIs
- Implement `ConnectorConfig` for Windows (HCN mode)
- Implement endpoint plumbing validation for HCN endpoints
- Implement stale endpoint cleanup for HCN endpoints
- Handle endpoint restore for Windows (read from disk, validate HCN endpoint)

### Phase 5: CNI Integration (Week 7-8)
- Implement or adapt CNI plugin for Windows to call Cilium agent
- Ensure CNI `ADD`/`DEL` operations work with HCN endpoints
- Test Pod lifecycle (create → assign IP → plumb network → delete)

### Phase 6: Integration Testing (Week 8-10)
- Test network creation on Windows nodes
- Test endpoint creation and Pod connectivity
- Test endpoint restore after agent restart
- Test host endpoint and health endpoint creation

---

## 7. Detailed TODO List

### 7.1 Build System & Compilation
- [ ] **TODO-WIN-001**: Add `GOOS=windows` build target to Makefile
- [ ] **TODO-WIN-002**: Set up Windows CI pipeline for `daemon/` compilation
- [ ] **TODO-WIN-003**: Create `daemon/cmd/daemon_main_windows.go` with Windows-specific `initEnv()` (no BPF mount, no cgroups mount, no rlimit, Windows admin check instead of root check)
- [ ] **TODO-WIN-004**: Create `daemon/cmd/daemon_main_linux.go` and move Linux-specific `initEnv()` logic there (BPF mount, cgroup mount, rlimit removal, probes header generation)

### 7.2 Endpoint Restore (`daemon/cmd/endpoint_restore.go`)
- [ ] **TODO-WIN-010**: Extract `checkLink()` into `NetworkDeviceManager` interface
- [ ] **TODO-WIN-011**: Extract `clearStaleCiliumEndpointVeths()` into `NetworkDeviceManager.ClearStaleEndpointDevices()`
- [ ] **TODO-WIN-012**: Extract `listVethIfaces()` into `NetworkDeviceManager.ListEndpointDevices()`
- [ ] **TODO-WIN-013**: Move netlink imports (`vishvananda/netlink`, `safenetlink`) to build-tagged files
- [ ] **TODO-WIN-014**: Implement Windows `NetworkDeviceManager` using HCN API for endpoint enumeration and cleanup
- [ ] **TODO-WIN-015**: Update `validateEndpoint()` to use interface for connector plumbing check
- [ ] **TODO-WIN-016**: Update `validateDatapathModeCompatibility()` — on Windows, the datapath mode will be "hcn" (no veth/netkit)

### 7.3 Infra IP Allocation (`daemon/infraendpoints/`)
- [ ] **TODO-WIN-020**: Create `netdev_windows.go` with `getCiliumHostIPsFromNetDev()` using Windows networking APIs (HCN or `net` package)
- [ ] **TODO-WIN-021**: Extract `removeOldRouterState()` into `HostNetworkManager` interface
- [ ] **TODO-WIN-022**: Extract `waitForENI()` — guard with build tag (Linux/AWS only)
- [ ] **TODO-WIN-023**: Abstract `linuxrouting.RoutingInfo` usage behind platform interface; Windows impl uses HCN route policies
- [ ] **TODO-WIN-024**: Move `netlink.LinkNotFoundError{}` usage behind platform abstraction (Windows will use HCN error types)
- [ ] **TODO-WIN-025**: Move direct `netlink.AddrDel()` calls behind `HostNetworkManager`
- [ ] **TODO-WIN-026**: Move `safenetlink.LinkList()` / `unix.IFF_SLAVE` filtering behind platform abstraction

### 7.4 Health & Misc (`daemon/healthz/`)
- [ ] **TODO-WIN-030**: Split `sockopt.go` → `sockopt_linux.go` (current) + `sockopt_windows.go` (using `windows.SetsockoptInt`, handle missing `SO_REUSEPORT`)
- [ ] **TODO-WIN-031**: Replace `unix.EADDRNOTAVAIL` in `agenthealth.go` and `kube_proxy_healthz.go` with platform-aware error check
- [ ] **TODO-WIN-032**: Review `healthz/cell.go` for any implicit Linux dependencies

### 7.5 Daemon Core (`daemon/cmd/daemon.go`, `daemon_main.go`)
- [ ] **TODO-WIN-040**: Split `initEnv()` into platform files; Linux keeps BPF/cgroups/probes init; Windows gets HCN init
- [ ] **TODO-WIN-041**: Guard IPsec validation code with build tags (Linux only)
- [ ] **TODO-WIN-042**: Guard `probes.HaveFibLookupTbid()` with build tags (Linux only)
- [ ] **TODO-WIN-043**: Guard iptables-related validation (`InstallIptRules`, `InstallNoConntrackIptRules`) — these are N/A on Windows
- [ ] **TODO-WIN-044**: Replace `common.RequireRootPrivilege()` with platform-aware privilege check
- [ ] **TODO-WIN-045**: Guard `initClockSourceOption()` (probes.KernelHZ, Jiffies) — Linux only

### 7.6 REST API (`daemon/restapi/config.go`)
- [ ] **TODO-WIN-050**: Abstract `bigtcp.Configuration` usage — return zero/default on Windows
- [ ] **TODO-WIN-051**: Abstract `getIPLocalReservedPorts()` — may need Windows-specific port reservation logic

### 7.7 Datapath Package (outside `daemon/` but critical)
- [ ] **TODO-WIN-060**: Implement `pkg/datapath/windows/connector.go` — HCN endpoint connector implementing `ConnectorConfig`
- [ ] **TODO-WIN-061**: Implement `pkg/datapath/windows/node.go` — HCN node addressing implementing `NodeAddressing`
- [ ] **TODO-WIN-062**: Implement `pkg/datapath/windows/cell.go` — Windows datapath cell (replaces BPF compilation with HCN policy setup)
- [ ] **TODO-WIN-063**: Implement `pkg/maps/lxcmap/` stub or adapter for Windows (no BPF, use in-memory or HCN-backed)
- [ ] **TODO-WIN-064**: Implement `pkg/endpoint/creator/` Windows variant using HCN `CreateEndpoint`/`HotAttachEndpoint`

### 7.8 CNI Plugin
- [ ] **TODO-WIN-070**: Implement or adapt `plugins/cilium-cni/` for Windows CNI interface
- [ ] **TODO-WIN-071**: Ensure CNI config written by `cni.Cell` is valid for Windows container runtime (containerd/HCS)

### 7.9 Testing
- [ ] **TODO-WIN-080**: Unit tests for Windows `NetworkDeviceManager` (mock HCN)
- [ ] **TODO-WIN-081**: Unit tests for Windows `HostNetworkManager` (mock HCN)
- [ ] **TODO-WIN-082**: Unit tests for `sockopt_windows.go`
- [ ] **TODO-WIN-083**: Integration test: agent startup on Windows (compilation + stub datapath)
- [ ] **TODO-WIN-084**: Integration test: endpoint create/delete lifecycle on Windows
- [ ] **TODO-WIN-085**: Integration test: agent restart + endpoint restore on Windows

---

## 8. Files Requiring Changes (Summary)

### Files to Split into `_linux.go` / `_windows.go`:

| Current File | Reason |
|---|---|
| `daemon/cmd/daemon_main.go` | BPF mount, cgroups, rlimit, probes, root privilege check |
| `daemon/cmd/endpoint_restore.go` | netlink (veth listing, link validation, stale cleanup) |
| `daemon/infraendpoints/infra_ip_allocation.go` | netlink (IP mgmt, route config, ENI wait, `unix.IFF_SLAVE`) |
| `daemon/healthz/sockopt.go` | `unix.SetsockoptInt` |
| `daemon/healthz/agenthealth.go` | `unix.EADDRNOTAVAIL` |
| `daemon/healthz/kube_proxy_healthz.go` | `unix.EADDRNOTAVAIL` |

### Files Already Platform-Specific (need Windows counterpart):

| File | Windows File Needed |
|---|---|
| `daemon/infraendpoints/netdev_linux.go` | `daemon/infraendpoints/netdev_windows.go` |

### Files That Are Platform-Agnostic (no changes needed):

| File | Notes |
|---|---|
| `daemon/main.go` | Entry point; agnostic |
| `daemon/cmd/root.go` | CLI setup; agnostic |
| `daemon/cmd/cells.go` | Cell wiring; agnostic (depends on `datapath.Cell` which will be swapped) |
| `daemon/cmd/hostips-sync.go` | Uses `lxcmap.Map` interface; agnostic if map is abstracted |
| `daemon/cmd/cni/` | CNI config management; agnostic |
| `daemon/infraendpoints/cell.go` | Cell config; agnostic |
| `daemon/infraendpoints/host_endpoint.go` | Uses `EndpointCreator` interface; agnostic |
| `daemon/infraendpoints/ingress_endpoint.go` | Uses `EndpointCreator` interface; agnostic |
| `daemon/restapi/policy.go` | Pure policy REST handlers; agnostic |
| `daemon/k8s/` | K8s resource watchers; agnostic |
| `daemon/cmd/legacy/daemon_init.go` | Type definitions only; agnostic |

---

## 9. Key Windows Packages / Dependencies

| Package | Purpose |
|---|---|
| `github.com/Microsoft/hcsshim` | Go bindings for HCS (Host Compute Service) and HCN (Host Compute Network) |
| `github.com/Microsoft/hcsshim/hcn` | HCN API — network creation, endpoint management, policy attachment |
| `golang.org/x/sys/windows` | Windows system calls (socket options, process privileges, etc.) |
| `github.com/Microsoft/go-winio` | Windows named pipe and I/O utilities |

---

## 10. Risks & Open Questions

1. **BPF Map Equivalents**: The `lxcmap` (BPF endpoint map) is used for host IP sync and endpoint tracking. On Windows, we need either an in-memory equivalent or HCN-backed tracking. Decision: use HCN endpoint enumeration as the source of truth.

2. **Datapath Cell Scope**: `datapath.Cell` (`pkg/datapath/`) is massive and deeply Linux-specific (BPF compilation, map management, template rendering). The Windows equivalent will be significantly simpler (HCN policies). We need to define the minimal `datapath.Cell` interface for Windows.

3. **IPsec/WireGuard**: Not supported on Windows initially. Must be disabled/hidden.

4. **iptables**: Windows has no iptables. All references to iptables rules, masquerading via iptables, etc. must be gated. Windows uses HCN policies for equivalent functionality.

5. **Feature Parity**: Initial Windows port will NOT support: eBPF datapath, IPsec, WireGuard, BPF masquerade, host firewall, SRv6, L2 announcer, egress gateway. These can be added later as Windows eBPF matures.

6. **State Directory Paths**: Linux uses `/var/run/cilium/`. Windows should use `C:\ProgramData\cilium\` (or configurable). The `defaults` package needs Windows-aware defaults.

7. **Socket Path**: The UNIX socket API server needs to be replaced with Windows Named Pipes on Windows, or a TCP listener.
