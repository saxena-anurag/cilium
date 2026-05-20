# Windows Load Balancing — Work Breakdown & Estimation

> **Scope:** Phase 2 — Kubernetes Service load balancing (ClusterIP, NodePort, LoadBalancer, ExternalIPs, HostPort).  
> **Companion document:** [windows-load-balancing-design.md](windows-load-balancing-design.md)  
> **Prerequisites:** [windows-pod-networking-design.md](windows-pod-networking-design.md) platform shim must be in place.  
> **Assumptions:** 1 dev-week = 5 working days. Estimates include design, implementation, unit tests, and code review. Integration testing is a separate block.

---

## Summary

| Block | Description | Estimate |
|-------|-------------|----------|
| **Block 1** | Windows LBMaps implementation | 2–3 weeks |
| **Block 2** | Reconciler platform splits (build tags) | 1–1.5 weeks |
| **Block 3** | Socket LB platform split | 2–3 weeks |
| **Block 4** | eBPF program loading / config maps (Windows) | 1.5–2 weeks |
| **Block 5** | K8s reflector platform splits | 0.5–1 week |
| **Block 6** | LB cell wiring & Hive integration | 0.5–1 week |
| **Block 7** | Integration testing & validation | 2–3 weeks |
| **Block 8** | Documentation & cleanup | 0.5 week |
| | **Total** | **10.5–15 weeks** (1 engineer) |
| | | **5.5–8 weeks** (2 engineers, parallelized) |

> **Why this is smaller than pod networking:** Cilium's LB system already has the `LBMaps` interface as a clean abstraction boundary. The entire control plane (reflectors, Writer, StateDB, reconciler logic) is platform-agnostic. Only the `LBMaps` implementation and BPF program attachment need Windows equivalents.

---

## Dependency Graph

```
Block 1 (LBMaps impl)
    │
    ├──► Block 2 (Reconciler splits) ──► Block 6 (Cell wiring)
    │                                        │
    │                                        ▼
    │                                    Block 7 (Integration testing)
    │                                        ▲
    ├──► Block 3 (Socket LB split)  ─────────┘
    │        ▲
    │        │
    └──► Block 4 (eBPF program loading)
    
Block 5 (Reflector splits) ──────────► Block 7

Block 8 (Docs) — after all blocks
```

**Critical path:** Block 1 → Block 2 → Block 6 → Block 7

**Parallelizable with 2 engineers:**
- Engineer A: Block 1 → Block 2 → Block 6
- Engineer B: Block 3 → Block 4 → Block 5
- Both: Block 7 (integration testing)

---

## Detailed Work Breakdown

### Block 1: Windows LBMaps Implementation (2–3 weeks)

Implement the `LBMaps` interface for Windows. The approach depends on the decision in the design doc (§5.3): direct libbpf map writes (A.1) or CNC API adapter (A.2). Both are estimated here; actual work will follow whichever is chosen.

#### Option A.1: Direct libbpf Map Writes

| Task ID | Task | Files | Estimate | Dependencies |
|---------|------|-------|----------|--------------|
| B1.1 | Create Go bindings for libbpf map operations (`bpf_map_update_elem`, `bpf_map_delete_elem`, `bpf_map_lookup_elem`) | `pkg/ebpf/libbpf_windows.go` | 2d | None |
| B1.2 | Implement `LibbpfLBMaps` struct — map open/pin/close lifecycle | `pkg/loadbalancer/maps/lbmaps_windows.go` | 1d | B1.1 |
| B1.3 | Implement `serviceMaps` (UpdateService, DeleteService, DumpService) via libbpf | `pkg/loadbalancer/maps/lbmaps_windows.go` | 1.5d | B1.2 |
| B1.4 | Implement `backendMaps` via libbpf | `pkg/loadbalancer/maps/lbmaps_windows.go` | 1d | B1.2 |
| B1.5 | Implement `revNatMaps` via libbpf | `pkg/loadbalancer/maps/lbmaps_windows.go` | 1d | B1.2 |
| B1.6 | Implement `affinityMaps` via libbpf (or no-op stub if not supported) | `pkg/loadbalancer/maps/lbmaps_windows.go` | 0.5d | B1.2 |
| B1.7 | Implement `sourceRangeMaps` via libbpf (LPM trie — verify Windows support) | `pkg/loadbalancer/maps/lbmaps_windows.go` | 1d | B1.2 |
| B1.8 | Implement `maglevMaps` via libbpf (map-in-map — verify Windows support) or no-op | `pkg/loadbalancer/maps/lbmaps_windows.go` | 1d | B1.2 |
| B1.9 | Implement `sockRevNatMaps` via libbpf or no-op stub | `pkg/loadbalancer/maps/lbmaps_windows.go` | 0.5d | B1.2 |
| B1.10 | Implement `IsEmpty()` | `pkg/loadbalancer/maps/lbmaps_windows.go` | 0.5d | B1.3–B1.9 |
| B1.11 | Unit tests with mock libbpf maps | `pkg/loadbalancer/maps/lbmaps_windows_test.go` | 2d | B1.3–B1.10 |
| | **Option A.1 Total** | | **~2 weeks** | |

#### Option A.2: CNC API Adapter

| Task ID | Task | Files | Estimate | Dependencies |
|---------|------|-------|----------|--------------|
| B1.1 | Create Go bindings for CNC LB APIs (`CncCreateLoadBalancerService`, etc.) via wcnagent DLL | `pkg/datapath/windows/wcnagent_lb.go` | 2d | Pod networking shim DLL loader (Block 3 of pod networking) |
| B1.2 | Implement `CNCLBMaps` struct — state tracking, buffering logic | `pkg/loadbalancer/maps/cnc_lbmaps_windows.go` | 2d | B1.1 |
| B1.3 | Implement `serviceMaps` with slot buffering and master-slot flush logic | `pkg/loadbalancer/maps/cnc_lbmaps_windows.go` | 2d | B1.2 |
| B1.4 | Implement `backendMaps` with CNC backend lifecycle tracking | `pkg/loadbalancer/maps/cnc_lbmaps_windows.go` | 1.5d | B1.2 |
| B1.5 | Implement `revNatMaps` — translate to CNC (likely implicit in CNC service) | `pkg/loadbalancer/maps/cnc_lbmaps_windows.go` | 0.5d | B1.2 |
| B1.6 | Implement `affinityMaps` — translate to CNC service config flags or no-op | `pkg/loadbalancer/maps/cnc_lbmaps_windows.go` | 0.5d | B1.2 |
| B1.7 | Implement `sourceRangeMaps` — translate to CNC service config or no-op | `pkg/loadbalancer/maps/cnc_lbmaps_windows.go` | 0.5d | B1.2 |
| B1.8 | Implement `maglevMaps` — no-op (CNC handles distribution internally) | `pkg/loadbalancer/maps/cnc_lbmaps_windows.go` | 0.5d | B1.2 |
| B1.9 | Implement `sockRevNatMaps` — translate to CNC or no-op | `pkg/loadbalancer/maps/cnc_lbmaps_windows.go` | 0.5d | B1.2 |
| B1.10 | Implement `IsEmpty()` and `DumpService/Backend/RevNat` using CNC query APIs | `pkg/loadbalancer/maps/cnc_lbmaps_windows.go` | 1d | B1.3–B1.9 |
| B1.11 | Implement service type mapping: `ServiceFlags` → CNC service type enum | `pkg/loadbalancer/maps/cnc_lbmaps_windows.go` | 0.5d | B1.3 |
| B1.12 | Unit tests with mock CNC API | `pkg/loadbalancer/maps/cnc_lbmaps_windows_test.go` | 2d | All above |
| | **Option A.2 Total** | | **~2.5 weeks** | |

**Parallelization:** Within either option, B1.3–B1.9 can be partially parallelized.

---

### Block 2: Reconciler Platform Splits (1–1.5 weeks)

The `BPFOps` reconciler in `pkg/loadbalancer/reconciler/` is mostly platform-agnostic but has a small number of Linux-specific references that need build-tag splits.

| Task ID | Task | Files | Estimate | Dependencies |
|---------|------|-------|----------|--------------|
| B2.1 | Audit `bpf_reconciler.go` for `unix.` and other Linux-specific references | `pkg/loadbalancer/reconciler/bpf_reconciler.go` | 0.5d | None |
| B2.2 | Extract socket termination logic into build-tagged files | `pkg/loadbalancer/reconciler/termination_linux.go`, `termination_windows.go` | 1d | B2.1 |
| B2.3 | Build-tag or replace `unix.IPPROTO_TCP` reference (use `syscall.IPPROTO_TCP` which is cross-platform) | `pkg/loadbalancer/reconciler/bpf_reconciler.go` | 0.5d | B2.1 |
| B2.4 | Handle `netns.GetNetNSCookie` usage in reconciler (Windows stub or skip) | `pkg/loadbalancer/reconciler/bpf_reconciler.go` | 0.5d | B2.1 |
| B2.5 | Verify `BPFOps` works with Windows `LBMaps` implementation via `FakeLBMaps` tests | `pkg/loadbalancer/reconciler/bpf_reconciler_test.go` | 1d | B1 |
| B2.6 | Windows-specific backend state handling: terminating backend sweep timer | `pkg/loadbalancer/reconciler/backend_state_windows.go` | 1d | B2.2 |
| B2.7 | Unit tests for reconciler on Windows (use `FakeLBMaps` with Windows build tags) | `pkg/loadbalancer/reconciler/bpf_reconciler_windows_test.go` | 1d | B2.2–B2.6 |
| | **Block 2 Total** | | **1–1.5 weeks** | |

**Risk:** Low. The reconciler is already well-abstracted. Most changes are mechanical build-tag splits.

---

### Block 3: Socket LB Platform Split (2–3 weeks)

Split the socket LB subsystem (`pkg/socketlb/`) into platform-specific implementations.

| Task ID | Task | Files | Estimate | Dependencies |
|---------|------|-------|----------|--------------|
| B3.1 | Define `SocketLB` interface: `Enable(ctx, cfg)`, `Disable()` | `pkg/socketlb/types.go` | 0.5d | None |
| B3.2 | Move existing `Enable/Disable` into `socketlb_linux.go` behind build tags | `pkg/socketlb/socketlb_linux.go` | 1d | B3.1 |
| B3.3 | Move cgroup attachment code into `cgroup_linux.go` (already mostly there) | `pkg/socketlb/cgroup_linux.go` | 0.5d | B3.2 |
| B3.4 | Implement Windows socket LB stub | `pkg/socketlb/socketlb_windows.go` | 0.5d | B3.1 |
| B3.5 | Research Windows eBPF socket hook availability (cgroup-equivalent hooks) | — | 2d | None |
| B3.6 | Implement Windows socket LB attachment using libbpf (if hooks available) | `pkg/socketlb/socketlb_windows.go` | 3d | B3.5, B4 |
| B3.7 | Implement fallback: if no socket hooks, LB via VFP/TC-equivalent hooks | `pkg/socketlb/socketlb_windows.go` | 2d | B3.5 |
| B3.8 | Build-tag the `PostBind` / `PreBind` programs (Linux-only port protection) | `pkg/socketlb/socketlb_linux.go` | 0.5d | B3.2 |
| B3.9 | Windows port protection via Windows APIs (e.g., `CreatePersistentUdpPortReservation`) | `pkg/socketlb/portprotect_windows.go` | 1d | B3.4 |
| B3.10 | Unit tests for socket LB platform split | `pkg/socketlb/socketlb_test.go` | 1d | B3.2–B3.9 |
| | **Block 3 Total** | | **2–3 weeks** | |

**Risk:** Medium-high. The Windows eBPF socket hook availability is uncertain (B3.5). If socket hooks are not available, the fallback path (B3.7) is more complex and may have performance implications.

---

### Block 4: eBPF Program Loading / Config Maps (Windows) (1.5–2 weeks)

Handle the difference between Linux (compile-on-demand with #defines) and Windows (pre-compiled programs with config maps).

| Task ID | Task | Files | Estimate | Dependencies |
|---------|------|-------|----------|--------------|
| B4.1 | Define configuration map schema for socket LB programs (`SockLBConfigKey/Value`) | `pkg/socketlb/config_map.go` | 1d | None |
| B4.2 | Implement config map writer: translate `SocketLBConfig` → BPF config map entries | `pkg/socketlb/config_map_windows.go` | 1d | B4.1 |
| B4.3 | Implement pre-compiled BPF program loader for Windows (using libbpf `bpf_object__open`) | `pkg/datapath/windows/loader_lb.go` | 2d | B1.1 (libbpf bindings) |
| B4.4 | Map Linux compile-time #defines to Windows config map entries for LB programs | `pkg/socketlb/config_map_windows.go` | 1d | B4.1, B4.2 |
| B4.5 | Handle BPF program pinning on Windows (pin path conventions) | `pkg/datapath/windows/loader_lb.go` | 1d | B4.3 |
| B4.6 | Unit tests for config map writer and program loader | `pkg/socketlb/config_map_windows_test.go` | 1d | B4.2–B4.5 |
| | **Block 4 Total** | | **1.5–2 weeks** | |

**Note:** This block has a dependency on the libbpf Go bindings created in Block 1 (A.1). If CNC API adapter (A.2) is chosen instead, this block may need different bindings.

---

### Block 5: K8s Reflector Platform Splits (0.5–1 week)

The K8s reflectors are mostly platform-agnostic, but have a few Linux-specific references.

| Task ID | Task | Files | Estimate | Dependencies |
|---------|------|-------|----------|--------------|
| B5.1 | Audit `reflectors/k8s.go` for `netns.GetNetNSCookie` and other Linux references | `pkg/loadbalancer/reflectors/k8s.go` | 0.5d | None |
| B5.2 | Build-tag `netns.GetNetNSCookie` call in HostPort handling | `pkg/loadbalancer/reflectors/k8s_linux.go`, `k8s_windows.go` | 0.5d | B5.1 |
| B5.3 | Verify NodePort address expansion works on Windows (NodeAddress table population) | `pkg/loadbalancer/reflectors/` | 1d | B5.2 |
| B5.4 | Windows node IP discovery: ensure NodeAddress table is populated from Windows APIs | `pkg/node/` | 1d | B5.3 |
| B5.5 | Unit tests for reflector changes on Windows build | `pkg/loadbalancer/reflectors/k8s_windows_test.go` | 0.5d | B5.2–B5.4 |
| | **Block 5 Total** | | **0.5–1 week** | |

**Risk:** Low. Small number of platform-specific references.

---

### Block 6: LB Cell Wiring & Hive Integration (0.5–1 week)

Wire up the Windows `LBMaps` implementation in the Hive dependency injection framework.

| Task ID | Task | Files | Estimate | Dependencies |
|---------|------|-------|----------|--------------|
| B6.1 | Split `maps.Cell` into `cell_linux.go` / `cell_windows.go` | `pkg/loadbalancer/maps/cell_linux.go`, `cell_windows.go` | 0.5d | B1 |
| B6.2 | Linux cell provides `BPFLBMaps`; Windows cell provides `CNCLBMaps` or `LibbpfLBMaps` | Same as B6.1 | 0.5d | B6.1 |
| B6.3 | Update `pkg/loadbalancer/cell/cell.go` if needed (should be platform-agnostic already) | `pkg/loadbalancer/cell/cell.go` | 0.5d | B6.1 |
| B6.4 | Wire socket LB cell for Windows | `pkg/socketlb/cell_windows.go` | 0.5d | B3 |
| B6.5 | Verify full LB cell starts on Windows (inject all deps, lifecycle check) | — | 1d | B6.1–B6.4 |
| B6.6 | Configuration validation: disable unsupported features on Windows (Maglev, DSR, etc.) | `pkg/loadbalancer/config.go` or `config_windows.go` | 0.5d | B6.5 |
| | **Block 6 Total** | | **0.5–1 week** | |

---

### Block 7: Integration Testing & Validation (2–3 weeks)

End-to-end testing of the LB subsystem on Windows.

| Task ID | Task | Files | Estimate | Dependencies |
|---------|------|-------|----------|--------------|
| B7.1 | Set up Windows Kubernetes test environment (Windows node with eBPF support) | — | 2d | All blocks |
| B7.2 | Test ClusterIP service: create service + endpoints, verify pod→VIP connectivity | — | 1.5d | B7.1 |
| B7.3 | Test NodePort service: create NodePort service, verify external→node:port connectivity | — | 1.5d | B7.1 |
| B7.4 | Test LoadBalancer service: create LB service with external IPs | — | 1d | B7.2, B7.3 |
| B7.5 | Test HostPort: create pod with hostPort, verify host:port → pod connectivity | — | 1d | B7.2 |
| B7.6 | Test ExternalIPs: create service with externalIPs, verify connectivity | — | 0.5d | B7.2 |
| B7.7 | Test service update: add/remove backends, verify traffic shifts correctly | — | 1d | B7.2 |
| B7.8 | Test service delete: delete service, verify cleanup (no leaked BPF entries / CNC state) | — | 0.5d | B7.2 |
| B7.9 | Test backend graceful termination: set backend to terminating, verify draining | — | 1d | B7.7 |
| B7.10 | Test session affinity: create service with sessionAffinity, verify client stickiness | — | 0.5d | B7.2 |
| B7.11 | Stress test: create 100+ services with 10 backends each, verify memory and map usage | — | 1d | B7.2 |
| B7.12 | Cross-platform test: Mixed Linux/Windows cluster, verify LB works across node types | — | 2d | B7.2–B7.6 |
| B7.13 | Crash recovery test: restart Cilium agent, verify LB state is reconciled | — | 1d | B7.2 |
| B7.14 | Regression: verify Linux LB is unaffected by all refactoring (run existing CI) | — | 1d | All blocks |
| | **Block 7 Total** | | **2–3 weeks** | |

**Risk:** High if Windows eBPF test environment is difficult to set up (B7.1). Consider using the existing `FakeLBMaps` pattern for unit-level validation first.

---

### Block 8: Documentation & Cleanup (0.5 week)

| Task ID | Task | Files | Estimate | Dependencies |
|---------|------|-------|----------|--------------|
| B8.1 | Update this design doc with implementation decisions (libbpf vs CNC, socket hooks) | `docs/design/windows-load-balancing-design.md` | 0.5d | All blocks |
| B8.2 | Add Windows LB architecture to Cilium developer docs | `Documentation/` | 0.5d | All blocks |
| B8.3 | Code comments in new Windows files explaining CNC mapping | — | 0.5d | B1 |
| B8.4 | Clean up any TODO/FIXME markers from implementation | — | 0.5d | All blocks |
| | **Block 8 Total** | | **0.5 week** | |

---

## Risk Assessment

| Risk | Impact | Likelihood | Mitigation |
|------|--------|------------|------------|
| Windows eBPF does not support socket hooks (cgroup equivalent) | High — ClusterIP socket LB requires a different mechanism | Medium | Research early (B3.5). Fallback: VFP/TC-level interception |
| Windows eBPF does not support LPM trie maps | Medium — source range filtering (loadBalancerSourceRanges) won't work | Low | Stub out sourceRangeMaps; implement CIDR checks in userspace |
| Windows eBPF does not support map-in-map | Low — only affects Maglev | Low | Disable Maglev on Windows; use random selection |
| CNC API latency for bulk operations | Medium — creating 100s of services during agent restart | Medium | Batch CNC calls; parallelize backend creation |
| libbpf Go bindings on Windows | Medium — if bindings are unstable | Medium | Use CGo with C libbpf directly; fallback to CNC APIs |
| eBPF map layout differences between Linux and Windows | High — breaks direct libbpf approach (A.1) | Low | Verify map layouts early. Fall back to CNC API adapter (A.2) |
| Reconciler has hidden Linux assumptions | Low — mostly caught in audit | Low | Comprehensive build attempt early (B2.1); fix build errors |

---

## Effort Comparison: LB vs Pod Networking

| Dimension | Pod Networking | Load Balancing |
|-----------|---------------|----------------|
| **Total estimate** | 16–22 weeks | 10.5–15 weeks |
| **Existing abstraction?** | No — new `PlatformDatapath` interface needed | Yes — `LBMaps` interface already exists |
| **Platform-agnostic code changes** | Significant — daemon, CNI plugin, connector | Minimal — build-tag splits only |
| **New interface design** | 4 sub-interfaces, 25+ methods | 0 new interfaces (use existing `LBMaps`) |
| **Linux refactoring risk** | High — touching active data paths | Low — wrapping existing `BPFLBMaps` |
| **Windows implementation** | Load wcnagent DLL, implement 4 interfaces | Implement 1 interface (`LBMaps`) |
| **Build system** | Cross-compilation, CGo, Windows SDK | Incremental (reuse pod networking build changes) |

The LB work is **~35–40% smaller** than pod networking primarily because Cilium already has the right abstraction boundary.

---

## Task Sequence for 1 Engineer

```
Week 1–2:   Block 1 (LBMaps implementation)
Week 3:     Block 2 (Reconciler platform splits)  
Week 3–4:   Block 5 (Reflector splits, parallel with Block 2)
Week 4:     Block 6 (Cell wiring)
Week 5–7:   Block 3 (Socket LB split)
Week 6–7:   Block 4 (eBPF program loading, overlaps with Block 3)
Week 8–10:  Block 7 (Integration testing)
Week 10:    Block 8 (Documentation)
```

## Task Sequence for 2 Engineers

```
Engineer A                          Engineer B
──────────                          ──────────
Week 1–2: Block 1 (LBMaps)         Week 1–2: Block 3 (Socket LB, B3.1–B3.5)
Week 3:   Block 2 (Reconciler)     Week 3:   Block 4 (eBPF loading)
Week 3:   Block 5 (Reflectors)     Week 3–4: Block 3 (B3.6–B3.10, needs B4)
Week 4:   Block 6 (Cell wiring)    Week 4:   Block 5 (verify, support)
Week 5–7: Block 7 (Integration)    Week 5–7: Block 7 (Integration)
Week 7:   Block 8 (Documentation)
```

---

## Decisions Required Before Starting

| # | Decision | Options | Impact |
|---|----------|---------|--------|
| 1 | **libbpf direct (A.1) vs CNC API adapter (A.2)?** | A.1: simpler, same map layout; A.2: richer CNC integration | Determines Block 1 approach and Block 4 dependencies |
| 2 | **Windows socket hook availability?** | Available: clean parity; Not available: fallback path | Determines Block 3 scope (1 week vs 2.5 weeks) |
| 3 | **Maglev on Windows?** | Enable (if map-in-map supported): more work; Disable: simpler | Affects B1.8 and feature parity |
| 4 | **Crash recovery strategy?** | Via wcnagent journaling; Via Cilium reconciler alone | Affects whether CNC adapter or direct libbpf is better |
| 5 | **Session affinity on Windows?** | BPF LRU hash (if supported); CNC-managed; Disabled initially | Affects B1.6 and B7.10 |
