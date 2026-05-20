# Windows Pod Networking — Work Breakdown & Estimation

> **Scope:** Phase 1 — Pod-to-pod networking only.  
> **Companion document:** [windows-pod-networking-design.md](windows-pod-networking-design.md)  
> **Assumptions:** 1 dev-week = 5 working days. Estimates include design, implementation, unit tests, and code review. Integration testing is a separate block.

---

## Summary

| Block | Description | Estimate |
|-------|-------------|----------|
| **Block 1** | Define platform shim interfaces | 1.5 weeks |
| **Block 2** | Linux platform implementation (refactor) | 3–4 weeks |
| **Block 3** | Windows platform implementation (wcnagent integration) | 3–4 weeks |
| **Block 4** | CNI plugin refactoring | 1.5–2 weeks |
| **Block 5** | Daemon refactoring (endpoint lifecycle) | 2–3 weeks |
| **Block 6** | Daemon refactoring (node init & infra) | 1.5–2 weeks |
| **Block 7** | Build system & cross-compilation | 1 week |
| **Block 8** | Integration testing & validation | 2–3 weeks |
| **Block 9** | Documentation & cleanup | 0.5–1 week |
| | **Total** | **16–22 weeks** (1 engineer) |
| | | **8–11 weeks** (2 engineers, parallelized) |

---

## Detailed Work Breakdown

### Block 1: Define Platform Shim Interfaces (1.5 weeks)

Define the new Go interfaces and shared data types that form the platform abstraction layer.

| Task ID | Task | Files | Estimate | Dependencies |
|---------|------|-------|----------|--------------|
| B1.1 | Define `PlatformDatapath` aggregate interface | `pkg/datapath/types/platform.go` | 0.5d | None |
| B1.2 | Define `PlatformNode` interface and types (`NodeConfig`, `NodeState`, `RemoteNodeInfo`) | `pkg/datapath/types/platform_node.go` | 1d | None |
| B1.3 | Define `PlatformNetwork` interface and types (`NetworkConfig`, `NetworkState`, `SubnetConfig`) | `pkg/datapath/types/platform_network.go` | 1d | None |
| B1.4 | Define `PlatformNamespace` interface and types (`SandboxConfig`, `SandboxState`) | `pkg/datapath/types/platform_ns.go` | 0.5d | None |
| B1.5 | Define `PlatformEndpoint` interface and types (`EndpointNetworkConfig`, `EndpointState`, `RouteConfig`) | `pkg/datapath/types/platform_endpoint.go` | 1d | None |
| B1.6 | Define shared types (`DNSConfig`, error types) | `pkg/datapath/types/platform_types.go` | 0.5d | None |
| B1.7 | Review interface definitions against both Linux and Windows flows; iterate | — | 2d | B1.1–B1.6 |
| | **Block 1 Total** | | **1.5 weeks** | |

**Parallelization:** B1.2–B1.6 can be done in parallel. B1.7 requires all to be complete.

---

### Block 2: Linux Platform Implementation — Refactor (3–4 weeks)

Wrap existing Linux code behind the new shim interfaces. **No behavioral changes.** This is the highest-risk block because it touches the existing Linux data path.

| Task ID | Task | Files | Estimate | Dependencies |
|---------|------|-------|----------|--------------|
| B2.1 | Implement `linuxPlatform` struct and `Name()` | `pkg/datapath/linux/platform_linux.go` | 0.5d | B1 |
| B2.2 | Implement `PlatformNode.InitializeNode()` — wrap `setupBaseDevice()`, `enableForwarding()`, `loader.Reinitialize()` | `pkg/datapath/linux/platform_linux.go` | 3d | B1 |
| B2.3 | Implement `PlatformNode.ConfigureNodeRouting()` — wrap `addHostDeviceAddr()`, sysctl, iptables setup | `pkg/datapath/linux/platform_linux.go` | 2d | B2.2 |
| B2.4 | Implement `PlatformNode.HandleRemoteNode()` / `RemoveRemoteNode()` — wrap `linuxNodeHandler.NodeAdd/Delete()` | `pkg/datapath/linux/platform_linux.go` | 1d | B2.2 |
| B2.5 | Implement `PlatformNode.CleanupNode()` | `pkg/datapath/linux/platform_linux.go` | 0.5d | B2.2 |
| B2.6 | Implement `PlatformNetwork` methods — thin wrappers for Linux (network is implicit) | `pkg/datapath/linux/platform_linux.go` | 1d | B1 |
| B2.7 | Implement `PlatformNamespace` methods — no-ops on Linux | `pkg/datapath/linux/platform_linux.go` | 0.5d | B1 |
| B2.8 | Implement `PlatformEndpoint.CreateEndpoint()` — wrap `connector.NewLinkPair()`, `configureIface()` | `pkg/datapath/linux/platform_linux.go` | 3d | B1 |
| B2.9 | Implement `PlatformEndpoint.AttachEndpoint()` — wrap `loader.ReloadDatapath()`, TC attachment | `pkg/datapath/linux/platform_linux.go` | 2d | B2.8 |
| B2.10 | Implement `PlatformEndpoint.DetachEndpoint()` / `DeleteEndpoint()` — wrap `loader.Unload()`, `netlink.LinkDel()` | `pkg/datapath/linux/platform_linux.go` | 1d | B2.8 |
| B2.11 | Implement `PlatformEndpoint.ValidateEndpoint()` — wrap `checkLink()`, `ValidateConnectorPlumbing()` | `pkg/datapath/linux/platform_linux.go` | 1d | B2.8 |
| B2.12 | Implement `PlatformEndpoint.ListEndpoints()` — wrap `listVethIfaces()` | `pkg/datapath/linux/platform_linux.go` | 0.5d | B2.8 |
| B2.13 | Register `linuxPlatform` in Hive dependency injection (build-tagged) | `pkg/datapath/linux/cell.go` | 1d | B2.1–B2.12 |
| B2.14 | Unit tests for Linux platform implementation | `pkg/datapath/linux/platform_linux_test.go` | 3d | B2.1–B2.12 |
| | **Block 2 Total** | | **3–4 weeks** | |

**Risk:** Refactoring active Linux code paths. Must be done carefully with extensive testing. Consider feature-flagging the shim usage to allow rollback.

---

### Block 3: Windows Platform Implementation — WcnAgent Integration (3–4 weeks)

Implement the Windows side of the platform shim by loading wcnagent.dll and calling its APIs.

| Task ID | Task | Files | Estimate | Dependencies |
|---------|------|-------|----------|--------------|
| B3.1 | Implement wcnagent DLL loader (`loadWcnAgent()`, `WcnAgentFunctionTableOpen` binding) | `pkg/datapath/windows/wcnagent.go` | 2d | B1 |
| B3.2 | Define Go-side HCN JSON schema types for serialization | `pkg/datapath/windows/types.go` | 2d | None |
| B3.3 | Implement Cilium ↔ HCN JSON converters (`endpointConfigToHCNJSON`, `networkConfigToHCNJSON`, etc.) | `pkg/datapath/windows/convert.go` | 2d | B3.2 |
| B3.4 | Implement `windowsPlatform` struct, `Name()`, and `PlatformNode.InitializeNode()` — calls `wcnagent.Initialize()` + `CreateNetwork()` | `pkg/datapath/windows/platform_windows.go` | 2d | B3.1, B3.3 |
| B3.5 | Implement `PlatformNode.ConfigureNodeRouting()`, `HandleRemoteNode()`, `RemoveRemoteNode()`, `CleanupNode()` | `pkg/datapath/windows/platform_windows.go` | 2d | B3.4 |
| B3.6 | Implement `PlatformNetwork` methods — calls `wcnagent.CreateNetwork()`, `DeleteNetwork()`, `QueryNetworkProperties()` | `pkg/datapath/windows/platform_windows.go` | 1.5d | B3.1, B3.3 |
| B3.7 | Implement `PlatformNamespace` methods — calls `wcnagent.CreateNamespace()`, `DeleteNamespace()` | `pkg/datapath/windows/platform_windows.go` | 1d | B3.1, B3.3 |
| B3.8 | Implement `PlatformEndpoint.CreateEndpoint()` — calls `wcnagent.CreateEndpoint()` | `pkg/datapath/windows/platform_windows.go` | 2d | B3.1, B3.3 |
| B3.9 | Implement `PlatformEndpoint.AttachEndpoint()` — calls `wcnagent.ModifyNamespace(Add, endpoint)` | `pkg/datapath/windows/platform_windows.go` | 2d | B3.7, B3.8 |
| B3.10 | Implement `PlatformEndpoint.DetachEndpoint()` / `DeleteEndpoint()` | `pkg/datapath/windows/platform_windows.go` | 1d | B3.8 |
| B3.11 | Implement `PlatformEndpoint.ValidateEndpoint()` / `ListEndpoints()` | `pkg/datapath/windows/platform_windows.go` | 1d | B3.8 |
| B3.12 | Register `windowsPlatform` in Hive dependency injection (build-tagged) | `pkg/datapath/windows/cell.go` | 1d | B3.4–B3.11 |
| B3.13 | Unit tests for Windows platform implementation (mock wcnagent) | `pkg/datapath/windows/platform_windows_test.go` | 3d | B3.4–B3.11 |
| | **Block 3 Total** | | **3–4 weeks** | |

**Risk:** wcnagent DLL ABI stability. Need to validate that the Go DLL loading works correctly with the C++ function table. Consider building a small proof-of-concept first (0.5d from B3.1).

---

### Block 4: CNI Plugin Refactoring (1.5–2 weeks)

Split the CNI plugin into platform-agnostic and platform-specific files.

| Task ID | Task | Files | Estimate | Dependencies |
|---------|------|-------|----------|--------------|
| B4.1 | Move Linux-specific CNI ADD code from `cmd.go` to `cmd_linux.go` | `plugins/cilium-cni/cmd/cmd_linux.go` | 1d | None |
| B4.2 | Create `cmd_windows.go` — thin CNI plugin that delegates to agent | `plugins/cilium-cni/cmd/cmd_windows.go` | 2d | B1 |
| B4.3 | Move Linux-specific endpoint listing to `endpoint_linux.go` | `plugins/cilium-cni/cmd/endpoint_linux.go` | 0.5d | None |
| B4.4 | Create `endpoint_windows.go` (stub or HCN-based) | `plugins/cilium-cni/cmd/endpoint_windows.go` | 0.5d | None |
| B4.5 | Move Linux-specific routing to `interface_linux.go` | `plugins/cilium-cni/cmd/interface_linux.go` | 0.5d | None |
| B4.6 | Create `interface_windows.go` (no-op for ENI/Azure) | `plugins/cilium-cni/cmd/interface_windows.go` | 0.5d | None |
| B4.7 | Ensure `cmd.go` only contains platform-agnostic code | `plugins/cilium-cni/cmd/cmd.go` | 1d | B4.1 |
| B4.8 | Unit tests for Windows CNI plugin | — | 1.5d | B4.2 |
| B4.9 | Verify existing Linux CNI tests pass after refactoring | — | 1d | B4.1, B4.7 |
| | **Block 4 Total** | | **1.5–2 weeks** | |

**Note:** Some of this split already exists (`cmd_linux.go` exists). The work is primarily creating Windows counterparts and ensuring clean separation.

---

### Block 5: Daemon Refactoring — Endpoint Lifecycle (2–3 weeks)

Update the daemon's endpoint creation and restoration paths to use the platform shim.

| Task ID | Task | Files | Estimate | Dependencies |
|---------|------|-------|----------|--------------|
| B5.1 | Add `PlatformDatapath` to orchestrator dependencies | `pkg/datapath/orchestrator/orchestrator.go` | 1d | B1 |
| B5.2 | Route endpoint regeneration through platform shim: update `regenerateBPF()` to call `PlatformEndpoint.AttachEndpoint()` on Windows | `pkg/endpoint/bpf.go` | 2d | B5.1 |
| B5.3 | Add platform sandbox creation to endpoint creation flow (for Windows: auto-create compartment if not exists) | `pkg/endpoint/api/endpoint_api_manager.go` | 1.5d | B5.1 |
| B5.4 | Split `endpoint_restore.go`: extract `checkLink()`, `listVethIfaces()`, `clearStaleCiliumEndpointVeths()` to platform interface | `daemon/cmd/endpoint_restore.go`, `endpoint_restore_linux.go`, `endpoint_restore_windows.go` | 3d | B1, B2 |
| B5.5 | Refactor `validateEndpoint()` to use `PlatformEndpoint.ValidateEndpoint()` | `daemon/cmd/endpoint_restore.go` | 1d | B5.4 |
| B5.6 | Refactor `validateDatapathModeCompatibility()` for Windows (no veth/netkit mode) | `daemon/cmd/endpoint_restore.go` | 0.5d | B5.4 |
| B5.7 | Update endpoint deletion path to use `PlatformEndpoint.DeleteEndpoint()` + `PlatformNamespace.DeletePodSandbox()` | `pkg/endpoint/endpoint.go`, `pkg/endpointmanager/manager.go` | 1.5d | B5.1 |
| B5.8 | Unit tests for refactored endpoint lifecycle | — | 2d | B5.1–B5.7 |
| | **Block 5 Total** | | **2–3 weeks** | |

**Risk:** This touches the endpoint lifecycle hot path. Must ensure backward compatibility with existing Linux flow.

---

### Block 6: Daemon Refactoring — Node Init & Infrastructure (1.5–2 weeks)

Update daemon startup, infrastructure IP allocation, and miscellaneous platform-specific code.

| Task ID | Task | Files | Estimate | Dependencies |
|---------|------|-------|----------|--------------|
| B6.1 | Split `daemon_main.go`: move BPF mount, cgroups, rlimit, probes to `daemon_main_linux.go` | `daemon/cmd/daemon_main.go`, `daemon_main_linux.go`, `daemon_main_windows.go` | 1.5d | None |
| B6.2 | Create `daemon_main_windows.go`: Windows admin check, wcnagent init, skip BPF/cgroups | `daemon/cmd/daemon_main_windows.go` | 1d | B3 |
| B6.3 | Create `netdev_windows.go`: Windows host IP management | `daemon/infraendpoints/netdev_windows.go` | 1d | B1 |
| B6.4 | Refactor `infra_ip_allocation.go`: extract netlink calls (`safenetlink.LinkByName`, `AddrList`, `AddrDel`, `unix.IFF_SLAVE`) behind platform interface | `daemon/infraendpoints/infra_ip_allocation.go` | 2d | B1, B2 |
| B6.5 | Split `sockopt.go` → `sockopt_linux.go` + `sockopt_windows.go` | `daemon/healthz/` | 0.5d | None |
| B6.6 | Fix `unix.EADDRNOTAVAIL` references in health check files | `daemon/healthz/agenthealth.go`, `kube_proxy_healthz.go` | 0.5d | None |
| B6.7 | Guard IPsec, iptables, BigTCP references with build tags | Various daemon files | 1d | None |
| B6.8 | Configure Windows state directory paths (`C:\ProgramData\cilium\` vs `/var/run/cilium/`) | `pkg/defaults/` | 0.5d | None |
| B6.9 | Unit tests for refactored daemon init | — | 1.5d | B6.1–B6.8 |
| | **Block 6 Total** | | **1.5–2 weeks** | |

**Parallelization:** B6.1, B6.5, B6.6, B6.7 are independent and can be done in parallel.

---

### Block 7: Build System & Cross-Compilation (1 week)

Set up the build infrastructure for Windows compilation.

| Task ID | Task | Estimate | Dependencies |
|---------|------|----------|--------------|
| B7.1 | Add `GOOS=windows GOARCH=amd64` build target to Makefile | 1d | None |
| B7.2 | Resolve transitive upstream dependency issues (see WINDOWS_PORTING_ANALYSIS.md §2.2): `pkg/monitor/agent/listener`, `pkg/loadinfo`, `pkg/datapath/xdp`, `renameio` replacements, etc. | 2d | None |
| B7.3 | Create no-op / stub implementations for BPF, cgroups, eBPF rlimit on Windows | 1d | None |
| B7.4 | Set up Windows CI pipeline (compilation check, unit tests) | 1d | B7.1–B7.3 |
| | **Block 7 Total** | **1 week** | |

**Note:** B7.2 involves changes in upstream `pkg/` packages that are outside the `daemon/` and `plugins/` directories. Some of these may require discussions with the Cilium maintainers. The estimate assumes simple build-tag splits, not behavioral changes.

---

### Block 8: Integration Testing & Validation (2–3 weeks)

End-to-end testing on actual Windows nodes.

| Task ID | Task | Estimate | Dependencies |
|---------|------|----------|--------------|
| B8.1 | Set up Windows test environment (Windows Server node with containerd, Kubernetes) | 2d | B7 |
| B8.2 | Test: Agent startup on Windows — initialization, wcnagent loading, network creation | 2d | B3, B6 |
| B8.3 | Test: Pod creation — CNI ADD, compartment creation, endpoint creation, IP assignment | 3d | B3, B4, B5 |
| B8.4 | Test: Pod-to-pod connectivity within same node | 2d | B8.3 |
| B8.5 | Test: Pod-to-pod connectivity across nodes (remote endpoints) | 2d | B8.3 |
| B8.6 | Test: Pod deletion — CNI DEL, endpoint cleanup, compartment deletion | 1d | B8.3 |
| B8.7 | Test: Agent restart — endpoint restoration from state | 2d | B5.4 |
| B8.8 | Test: Verify existing Linux tests still pass (regression) | 1.5d | B2 |
| B8.9 | Fix issues discovered during testing | 3d (buffer) | B8.2–B8.8 |
| | **Block 8 Total** | **2–3 weeks** | |

---

### Block 9: Documentation & Cleanup (0.5–1 week)

| Task ID | Task | Estimate | Dependencies |
|---------|------|----------|--------------|
| B9.1 | Update README/contributing docs with Windows build instructions | 0.5d | B7 |
| B9.2 | Document platform shim API for future implementers | 1d | B1 |
| B9.3 | Code cleanup: remove dead code, fix TODOs, ensure consistent naming | 1d | All |
| B9.4 | Final review and PR preparation | 1d | All |
| | **Block 9 Total** | **0.5–1 week** | |

---

## Dependency Graph

```
Block 1 (Interfaces)
    │
    ├──────────────────────┬────────────────────┬──────────────────┐
    ▼                      ▼                    ▼                  ▼
Block 2 (Linux impl)   Block 3 (Win impl)   Block 4 (CNI)   Block 7 (Build)
    │                      │                    │                  │
    ├──────────────────────┼────────────────────┘                  │
    ▼                      ▼                                       │
Block 5 (Daemon endpoint lifecycle)                                │
    │                                                              │
    ▼                                                              │
Block 6 (Daemon node init & infra) ◄───────────────────────────────┘
    │
    ▼
Block 8 (Integration testing)
    │
    ▼
Block 9 (Docs & cleanup)
```

### Parallelization Opportunities

With 2 engineers:

| Engineer A | Engineer B |
|-----------|-----------|
| Block 1 (interfaces — collaborative) | Block 1 (collaborative) |
| Block 2 (Linux refactoring) | Block 3 (Windows wcnagent integration) |
| Block 5 (Daemon endpoint lifecycle) | Block 4 (CNI plugin refactoring) |
| Block 8 (Integration testing — Linux regression) | Block 6 (Daemon node init) |
| Block 9 (Docs) | Block 7 (Build system) |
| — | Block 8 (Integration testing — Windows) |

This reduces the critical path to approximately **8–11 weeks**.

---

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Linux regression from refactoring | Medium | High | Feature-flag shim usage; extensive unit tests (B2.14); run existing CI suite (B8.8) |
| wcnagent DLL loading issues (Go ↔ C++ ABI) | Medium | Medium | Build proof-of-concept early (B3.1); consider cgo if needed |
| Upstream `pkg/` dependency issues blocking compilation | High | Medium | Start B7.2 early; some fixes may need upstream PRs |
| Interface design doesn't fit both platforms well | Low | High | B1.7 (review iteration); having both platform experts review before committing |
| Windows test environment setup delays | Medium | Medium | Start B8.1 in parallel with development |
| Performance regression on Linux hot path (CNI ADD) | Low | High | Keep Option A (CNI creates veth directly on Linux) |

---

## Out of Scope (Phase 1)

The following are explicitly out of scope for this phase and will be addressed in subsequent phases:

- Load balancer service configuration (Phase 2)
- Network policies and identities (Phase 2)
- BPF program loading on Windows via eBPF-for-Windows (Phase 3)
- IPsec / WireGuard on Windows
- Tunnel devices (VXLAN/Geneve) on Windows
- iptables-equivalent functionality on Windows
- Host firewall on Windows
- Egress gateway on Windows
- Multi-pool IPAM on Windows
- ENI/Azure IPAM modes on Windows (not applicable)
