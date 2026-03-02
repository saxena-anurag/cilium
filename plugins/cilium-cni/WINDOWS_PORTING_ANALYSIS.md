# Cilium CNI Plugin — Windows Compilation Analysis & Porting Plan

## 1. Can It Compile on Windows Today?

**No.** Cross-compiling with `GOOS=windows GOARCH=amd64` fails with multiple errors across both the plugin's own code and its upstream Cilium library dependencies.

---

## 2. Shortcomings for Compiling on Windows

The issues fall into two categories: **errors within the `cilium-cni` plugin code itself** (local) and **errors in upstream Cilium library packages** that the plugin imports (transitive).

### 2.1 Local Plugin Code Issues (within `plugins/cilium-cni/`)

| # | File | Issue | Root Cause |
|---|------|-------|------------|
| 1 | `cmd/cmd.go` | Imports `github.com/vishvananda/netlink` | `netlink` is a Linux-only library wrapping Netlink sockets. No Windows support. |
| 2 | `cmd/cmd.go` | Imports `golang.org/x/sys/unix` (uses `unix.IFA_F_NODAD`, `unix.ENOPROTOOPT`, `unix.IFF_SLAVE`) | `golang.org/x/sys/unix` only compiles on Unix-like systems. |
| 3 | `cmd/cmd.go` | Uses `github.com/cilium/cilium/pkg/datapath/linux/route` | Linux-specific route management using Netlink. |
| 4 | `cmd/cmd.go` | Uses `github.com/cilium/cilium/pkg/datapath/linux/safenetlink` | Thin wrapper around `vishvananda/netlink`. |
| 5 | `cmd/cmd.go` | Uses `github.com/cilium/cilium/pkg/datapath/linux/sysctl` | Reads/writes `/proc/sys` — does not exist on Windows. |
| 6 | `cmd/cmd.go` | Uses `github.com/cilium/cilium/pkg/netns` (`OpenPinned`, `GetNetNSCookie`) | Linux network namespaces (bind-mount based) don't directly map to Windows HNS/HCS. |
| 7 | `cmd/cmd.go` | Uses `github.com/cilium/cilium/pkg/datapath/connector` | Creates veth/netkit pairs via Netlink — Linux-only primitives. |
| 8 | `cmd/cmd.go` | Uses `github.com/cilium/cilium/pkg/datapath/link` | Wraps Netlink link operations. |
| 9 | `cmd/cmd.go` | Uses `github.com/cilium/cilium/pkg/mac` (`ReplaceMacAddressWithLinkName`) | Netlink-based MAC address manipulation. |
| 10 | `cmd/endpoint.go` | Calls `netlink.LinkList()`, `safenetlink.LinkList()`, checks `unix.IFF_SLAVE` | Direct Netlink + Unix constants. |
| 11 | `cmd/interface.go` | Uses `github.com/cilium/cilium/pkg/datapath/linux/routing` (`NewRoutingInfo`, `Configure`) | Linux ip-rule/ip-route management. |
| 12 | `chaining/generic-veth/generic-veth.go` | Uses `netlink.VethPeerIndex`, `netlink.FAMILY_V4`, `netlink.FAMILY_V6`, `netlink.AddrList`, `netlink.RouteList`, `netlink.RouteReplace` | All Linux Netlink APIs. |
| 13 | `chaining/generic-veth/generic-veth.go` | Uses `netns.OpenPinned` | Linux network namespace. |

### 2.2 Transitive Upstream Dependency Issues (within `pkg/`)

| # | Package | Error | Root Cause |
|---|---------|-------|------------|
| 1 | `pkg/monitor/agent/listener` | `unix.Errno`, `unix.EPIPE` undefined | Uses `golang.org/x/sys/unix` constants. |
| 2 | `pkg/loadinfo` | `memInfo.Buffers`, `.Cached`, `.SwapTotal`, `.SwapUsed`, `.SwapFree` undefined | `gopsutil/mem` `memory.Stats` struct fields differ on Windows. |
| 3 | `pkg/datapath/linux/linux_defaults` | `unix.RTPROT_KERNEL` undefined | Linux routing protocol constant. |
| 4 | `pkg/datapath/xdp` | `link.XDPAttachFlags`, `link.XDPDriverMode`, `link.XDPGenericMode` undefined | eBPF/XDP is Linux-specific (cilium/ebpf). |
| 5 | `daemon/cmd/cni` | `renameio.WriteFile` undefined | `google/renameio` doesn't support Windows. |
| 6 | `pkg/identity/cache` | `renameio.NewPendingFile`, `renameio.WithExistingPermissions`, `renameio.WithPermissions` undefined | Same `renameio` issue. |
| 7 | `pkg/loadbalancer/reflectors` | `netns.GetNetNSCookie`, `unix.ENOPROTOOPT` undefined | Linux netns and Unix constants. |

### 2.3 Conceptual / Architectural Barriers

Beyond compilation errors, there are deep **architectural differences** between Linux and Windows networking that affect the CNI plugin's runtime behavior:

| Area | Linux (Current) | Windows Equivalent |
|------|----------------|--------------------|
| **Network Namespaces** | `bind-mount` pinned netns in `/run/netns/` | HNS (Host Networking Service) network endpoints / HCS (Host Compute Service) compartments |
| **Container Interface Creation** | veth pairs or netkit pairs via Netlink | HNS endpoints attached to virtual switches |
| **IP/Route Configuration** | `netlink.AddrAdd`, `netlink.RouteAdd`, ip rules | HNS endpoint configuration or `netsh`/`Get-NetAdapter` PowerShell cmdlets |
| **Sysctl Tuning** | `/proc/sys/net/...` | Windows registry or `netsh` settings (partial equivalence) |
| **MAC Address Override** | `netlink.LinkSetHardwareAddr` | Limited; HNS endpoint MAC is typically auto-assigned |
| **eBPF / XDP** | Full eBPF datapath | eBPF for Windows exists (Microsoft's project) but is not feature-equivalent; Cilium uses advanced BPF features |
| **Datapath Connector** | Creates veth pair, sets up TC/BPF programs | Would need HNS-based endpoint + potentially Windows eBPF or VFP rules |
| **Socket-based Agent Communication** | Unix domain socket (`/var/run/cilium/cilium.sock`) | Named pipes (`\\.\pipe\cilium`) or TCP localhost |

---

## 3. Porting Plan

### Phase 1: Build Abstraction Layer (Enable Compilation)

**Goal:** Make the plugin compile on Windows by introducing OS-abstraction interfaces.

#### Step 1.1 — Abstract Network Operations

Create a `netops` interface package (e.g., `plugins/cilium-cni/cmd/netops/`) that abstracts:

```go
type NetOps interface {
    LinkList() ([]LinkInfo, error)
    LinkByName(name string) (LinkInfo, error)
    AddrAdd(link LinkInfo, addr netip.Prefix) error
    AddrList(link LinkInfo, family int) ([]netip.Prefix, error)
    RouteAdd(route RouteSpec) error
    RouteReplace(route RouteSpec) error
    LinkSetUp(link LinkInfo) error
    VethPeerIndex(link LinkInfo) (int, error)
    LinkDelete(name string) error
}
```

- **Linux implementation:** Delegates to `vishvananda/netlink` + `safenetlink` (existing code, wrapped).
- **Windows implementation:** Delegates to [Microsoft/hcsshim](https://github.com/microsoft/hcsshim) HNS APIs or PowerShell/WMI calls.

#### Step 1.2 — Abstract Network Namespace Operations

Create a `netns` abstraction:

```go
type NetNS interface {
    Open(path string) (NSHandle, error)
    Do(fn func() error) error
    Close() error
    GetCookie() (uint64, error)
}
```

- **Linux:** Wraps existing `pkg/netns` (bind-mount-based netns).
- **Windows:** Maps to HNS compartment IDs or HCS container network namespaces.

#### Step 1.3 — Abstract Sysctl Operations

Already partially abstracted behind `sysctl.Sysctl` interface. For Windows:
- Provide a no-op or registry-based implementation.
- Many sysctl knobs (e.g., `tcp_congestion_control`, `ip_local_reserved_ports`) have no Windows equivalent and should be skipped.

#### Step 1.4 — Platform Build Tags

Guard Linux-specific imports behind build tags in the plugin code:

```
cmd/cmd_linux.go       → imports netlink, unix, linux/* packages
cmd/cmd_windows.go     → imports Windows-specific HNS/HCS packages
cmd/cmd.go             → platform-independent logic only
```

Same pattern for:
- `cmd/endpoint.go` → `endpoint_linux.go` / `endpoint_windows.go`
- `cmd/interface.go` → `interface_linux.go` / `interface_windows.go`
- `chaining/generic-veth/` → `generic-veth_linux.go` / `generic-veth_windows.go` (or rename to `generic-link`)

#### Step 1.5 — Fix Upstream Dependency Issues

These require changes in the **main Cilium repository** (`pkg/`), not the plugin itself:

| Package | Fix |
|---------|-----|
| `pkg/monitor/agent/listener` | Add `_linux.go`/`_windows.go` split; use `syscall.Errno` on Windows |
| `pkg/loadinfo` | Guard Linux-specific `memory.Stats` fields with build tags |
| `pkg/datapath/linux/linux_defaults` | Already under `linux/` path; add a stub `_windows.go` or refactor imports |
| `pkg/datapath/xdp` | Guard behind `//go:build linux`; provide no-op Windows stub |
| `daemon/cmd/cni` | Replace `renameio` with `os.Rename` or a cross-platform wrapper |
| `pkg/identity/cache` | Same `renameio` fix |
| `pkg/loadbalancer/reflectors` | Guard `GetNetNSCookie` behind build tags |

### Phase 2: Windows CNI Runtime Implementation

**Goal:** Make the plugin actually functional on Windows (not just compilable).

#### Step 2.1 — HNS Endpoint Management

Replace veth-pair creation with HNS endpoint creation:
- Use [microsoft/hcsshim](https://github.com/microsoft/hcsshim) `hcn` package.
- Create HNS endpoints attached to a virtual switch.
- Attach endpoints to container network compartments.

#### Step 2.2 — IP/Route Configuration via HNS

- IP addresses and routes are configured as part of the HNS endpoint policy.
- Use `hcn.HostComputeEndpoint` with `IpConfigurations` and `Routes`.

#### Step 2.3 — Agent Communication

Replace Unix socket communication with Windows named pipes:
- The Cilium agent client (`pkg/client`) already uses HTTP; just change the socket path to a named pipe path or TCP endpoint.

#### Step 2.4 — Chaining Mode Adaptation

- `generic-veth` chainer is deeply tied to veth semantics.
- Create a `generic-hns` chainer (or platform-aware variant) that understands HNS endpoints rather than veth pairs.
- Keep AWS-CNI, Azure, and Flannel chaining as Linux-only (they have no Windows meaning).

### Phase 3: Datapath & eBPF (Long-Term)

This is the most challenging phase and may not be fully achievable:

- **Windows eBPF** ([microsoft/ebpf-for-windows](https://github.com/microsoft/ebpf-for-windows)) provides a subset of eBPF, but Cilium's advanced BPF programs (CT, NAT, policy enforcement, DSR, etc.) require significant eBPF features that may not yet be available.
- **Alternative:** Use Windows VFP (Virtual Filtering Platform) rules for basic policy enforcement, and defer full eBPF datapath to future Windows eBPF maturity.
- **Interim approach:** Run the CNI plugin in a "policy-less" mode where it only handles network plumbing (IP assignment, endpoint creation) and leaves policy enforcement to Cilium's proxy-based or kube-proxy-based path.

---

## 4. Estimated Effort

| Phase | Scope | Effort Estimate |
|-------|-------|-----------------|
| Phase 1 | Build-tag abstraction + compilation | 2–4 weeks |
| Phase 2 | HNS-based Windows runtime | 4–8 weeks |
| Phase 3 | eBPF/datapath on Windows | 3–6+ months (depends on Windows eBPF maturity) |

---

## 5. Summary

The cilium-cni plugin **cannot be trivially ported to Windows** due to deep coupling with Linux-specific networking primitives (Netlink, network namespaces, sysctl, veth pairs, eBPF/XDP). A significant refactoring effort is required to:

1. Introduce OS-abstraction interfaces with build-tag-guarded platform implementations.
2. Fix multiple upstream `pkg/` dependencies that use Linux-only APIs without build tags.
3. Implement a Windows-specific networking backend using HNS/HCS.
4. Eventually adapt the eBPF datapath for Windows eBPF or alternative enforcement mechanisms.

The plugin is **not a candidate for simple cross-compilation**; it requires a deliberate multi-phase porting project.
