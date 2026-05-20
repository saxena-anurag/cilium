# Cilium Agent — Windows Load Balancing: Detailed Design

> **Scope:** Phase 1 — Kubernetes Service load balancing (ClusterIP, NodePort, LoadBalancer, ExternalIPs, HostPort).  
> **Prerequisites:** [windows-pod-networking-design.md](windows-pod-networking-design.md) (pod networking shim must be in place).  
> **Status:** Draft for team review.  
> **Audience:** Engineering team, Copilot (for future implementation).

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Current Architecture Analysis](#2-current-architecture-analysis)
   - 2.1 [Cilium Linux: LB Architecture](#21-cilium-linux-lb-architecture)
   - 2.2 [WcnAgent Windows: LB Architecture](#22-wcnagent-windows-lb-architecture)
   - 2.3 [Conceptual Mapping: Linux ↔ Windows](#23-conceptual-mapping-linux--windows)
3. [Key Architectural Insight: The LBMaps Seam](#3-key-architectural-insight-the-lbmaps-seam)
4. [Proposed Architecture](#4-proposed-architecture)
   - 4.1 [Layered Architecture Overview](#41-layered-architecture-overview)
   - 4.2 [What Stays Common](#42-what-stays-common)
   - 4.3 [What Becomes Platform-Specific](#43-what-becomes-platform-specific)
5. [Shim API Design](#5-shim-api-design)
   - 5.1 [Option A: LBMaps Adapter (Recommended)](#51-option-a-lbmaps-adapter-recommended)
   - 5.2 [Option B: Higher-Level Platform LB Interface](#52-option-b-higher-level-platform-lb-interface)
   - 5.3 [Recommendation and Rationale](#53-recommendation-and-rationale)
6. [Linux Implementation (Existing — No Changes)](#6-linux-implementation-existing--no-changes)
7. [Windows Implementation](#7-windows-implementation)
   - 7.1 [CNC LBMaps Adapter](#71-cnc-lbmaps-adapter)
   - 7.2 [State Tracking](#72-state-tracking)
   - 7.3 [WcnAgent Integration](#73-wcnagent-integration)
   - 7.4 [BPF Program Attachment Differences](#74-bpf-program-attachment-differences)
8. [Socket-Level LB on Windows](#8-socket-level-lb-on-windows)
9. [Data Flow Diagrams](#9-data-flow-diagrams)
10. [eBPF Considerations for Windows](#10-ebpf-considerations-for-windows)
11. [Open Questions & Decisions](#11-open-questions--decisions)

---

## 1. Executive Summary

Cilium's load balancing subsystem converts Kubernetes Service objects into datapath rules that redirect traffic from service VIPs to backend pod IPs. On Linux, these rules are stored in **eBPF maps** that are consulted by BPF programs attached to various hooks (TC, XDP, cgroup/socket).

On Windows, the equivalent datapath is programmed via **CNC APIs** (`CncCreateLoadBalancerService`, `CncCreateLoadBalancerBackends`, etc.) which populate similar eBPF maps in the Windows eBPF datapath.

**Key finding:** Cilium's LB architecture already has a clean abstraction boundary — the `LBMaps` interface in `pkg/loadbalancer/maps/`. The entire control plane (K8s reflectors, StateDB tables, Writer, Frontend reconciler) is **already platform-agnostic**. Only the `LBMaps` implementation and BPF program attachment are platform-specific.

This means the refactoring effort for LB is **significantly smaller** than for pod networking. The primary work is:
1. Implement a Windows `LBMaps` adapter that translates map operations into CNC API calls (or direct eBPF map writes via libbpf).
2. Handle BPF program loading/attachment differences on Windows.
3. Address a small number of Linux-specific references in the reconciler.

---

## 2. Current Architecture Analysis

### 2.1 Cilium Linux: LB Architecture

Cilium's LB system follows a **data-driven reconciliation** pattern built on StateDB:

```
┌──────────────────────────────────────────────────────────────────┐
│                    K8s API Server                                 │
│  Service objects │  EndpointSlice objects │  Pod objects           │
└────────┬─────────────────┬───────────────────────┬───────────────┘
         │                 │                       │
         ▼                 ▼                       ▼
┌──────────────────────────────────────────────────────────────────┐
│  K8s Reflector (pkg/loadbalancer/reflectors/k8s.go)              │
│                                                                  │
│  convertService() ──► Writer.UpsertServiceAndFrontends()         │
│  convertEndpoints() ─► Writer.UpsertBackends()                   │
│  Pod HostPort ───────► Writer.UpsertServiceAndFrontends()        │
│                                                                  │
│  Batches: 500 events / 500ms window for throughput               │
└────────────────────────────┬─────────────────────────────────────┘
                             │ (StateDB writes)
                             ▼
┌──────────────────────────────────────────────────────────────────┐
│  StateDB Tables (pkg/loadbalancer/writer/)                       │
│                                                                  │
│  Table[*Service]  ──  ServiceByName index                        │
│  Table[*Frontend] ──  FrontendByAddress, FrontendByServiceName   │
│  Table[*Backend]  ──  BackendByAddress, BackendByServiceName     │
│                                                                  │
│  Writer validates, deduplicates, resolves references,            │
│  selects backends per frontend, sets Status=Pending              │
└────────────────────────────┬─────────────────────────────────────┘
                             │ (reconciler watches Frontends)
                             ▼
┌──────────────────────────────────────────────────────────────────┐
│  BPF Reconciler (pkg/loadbalancer/reconciler/bpf_reconciler.go)  │
│                                                                  │
│  BPFOps.Update(frontend):                                        │
│    1. Allocate ServiceID (1-65535)                                │
│    2. Allocate BackendIDs for each backend                       │
│    3. Create ServiceKey{IP, Port, Proto, Scope, Slot}            │
│    4. Create ServiceValue{BackendID, Flags, RevNat, Count}       │
│    5. For each backend slot: UpdateService(key, val)             │
│    6. For each backend: UpdateBackend(key, val)                  │
│    7. UpdateRevNat(serviceID → frontend addr)                    │
│    8. UpdateMaglev (if enabled)                                  │
│    9. UpdateAffinityMatch (if session affinity)                  │
│   10. UpdateSourceRange (if CIDR filtering)                      │
│   11. Write master slot (slot 0) with backend count              │
│                                                                  │
│  BPFOps.Delete(frontend):                                        │
│    1. Delete all service slots                                   │
│    2. Delete orphan backends                                     │
│    3. Delete RevNat, Maglev, Affinity, SourceRange entries       │
│    4. Release ServiceID and BackendIDs                           │
└────────────────────────────┬─────────────────────────────────────┘
                             │ (map operations)
                             ▼
┌──────────────────────────────────────────────────────────────────┐
│  LBMaps Interface (pkg/loadbalancer/maps/lbmaps.go)              │
│                                                                  │
│  UpdateService(ServiceKey, ServiceValue)                         │
│  UpdateBackend(BackendKey, BackendValue)                         │
│  UpdateRevNat(RevNatKey, RevNatValue)                            │
│  UpdateMaglev(MaglevOuterKey, []BackendID, ipv6)                 │
│  UpdateAffinityMatch(AffinityMatchKey, AffinityMatchValue)       │
│  UpdateSourceRange(SourceRangeKey, SourceRangeValue)             │
│  UpdateSockRevNat(cookie, addr, port, revNatIndex)               │
│  + Delete* and Dump* counterparts for each                       │
└────────────────────────────┬─────────────────────────────────────┘
                             │
                             ▼
┌──────────────────────────────────────────────────────────────────┐
│  BPFLBMaps (Linux implementation)                                │
│                                                                  │
│  14 BPF maps (2 per IP family for service, backend, revnat,     │
│  maglev, sockrevnat, sourcerange + 1 shared affinity match)     │
│                                                                  │
│  Map names: cilium_lb4_services_v2, cilium_lb4_backends_v3,     │
│             cilium_lb4_reverse_nat, cilium_lb4_maglev, etc.     │
└──────────────────────────────────────────────────────────────────┘
```

**Key source files:**

| File | Purpose |
|------|---------|
| `pkg/loadbalancer/service.go` | `Service` struct (K8s service properties) |
| `pkg/loadbalancer/frontend.go` | `Frontend` struct (VIP + backends + reconciliation status) |
| `pkg/loadbalancer/backend.go` | `Backend` / `BackendParams` (pod endpoint addresses) |
| `pkg/loadbalancer/loadbalancer.go` | Core types: `SVCType`, `L3n4Addr`, `ServiceID`, `BackendID`, `ServiceFlags` |
| `pkg/loadbalancer/reflectors/k8s.go` | K8s Service/EndpointSlice → Writer |
| `pkg/loadbalancer/reflectors/conversions.go` | `convertService()`, `convertEndpoints()` |
| `pkg/loadbalancer/writer/writer.go` | `Writer` — validated writes to StateDB tables |
| `pkg/loadbalancer/reconciler/bpf_reconciler.go` | `BPFOps` — Frontend → BPF map reconciliation |
| `pkg/loadbalancer/maps/lbmaps.go` | `LBMaps` interface + `BPFLBMaps` Linux implementation |
| `pkg/loadbalancer/maps/types.go` | BPF map key/value types (Service4Key, Backend4KeyV3, etc.) |
| `pkg/loadbalancer/cell/cell.go` | Hive wiring for the complete LB subsystem |
| `pkg/socketlb/socketlb.go` | Socket-level LB program attachment |
| `pkg/socketlb/cgroup.go` | Cgroup BPF link management |

**Service types supported:**

| SVCType | Linux Behavior |
|---------|---------------|
| `ClusterIP` | BPF entry for cluster VIP; socket LB intercepts connect() |
| `NodePort` | Expanded to entries for each node IP + wildcard; TC/XDP intercepts |
| `LoadBalancer` | Like ClusterIP + ExternalIPs from cloud LB; TC/XDP intercepts |
| `ExternalIPs` | BPF entries for each external IP |
| `HostPort` | Expanded per-node-IP; container port → host port mapping |
| `LocalRedirect` | Redirects traffic to local pod instead of service backends |

**BPF program attachment points for LB:**

| Program | Attach Point | Purpose |
|---------|-------------|---------|
| `bpf_sock.c` → `cil_sock4_connect` | cgroup/connect4 | Intercept connect() for ClusterIP LB |
| `bpf_sock.c` → `cil_sock4_sendmsg` | cgroup/sendmsg4 | Intercept UDP sendmsg() for LB |
| `bpf_sock.c` → `cil_sock4_recvmsg` | cgroup/recvmsg4 | Reverse NAT on recv for LB |
| `bpf_sock.c` → `cil_sock4_getpeername` | cgroup/getpeername4 | Return original VIP to app |
| `bpf_lxc.c` → `cil_from_container` | TC ingress on lxc veth | NodePort/ExternalIP LB from pod traffic |
| `bpf_host.c` → `cil_from_host` | TC ingress on cilium_host | NodePort LB from host traffic |
| `bpf_xdp.c` | XDP on physical NIC | NodePort LB acceleration |

### 2.2 WcnAgent Windows: LB Architecture

WcnAgent exposes an explicit CRUD API for load balancers. The flow is:

```
┌──────────────────────────────────────────────────────────────────┐
│  Caller (HNS / orchestrator)                                     │
│                                                                  │
│  WcnAgentCreateLoadBalancer(Id, Settings)                        │
│  WcnAgentModifyLoadBalancer(Handle, Settings)                    │
│  WcnAgentDeleteLoadBalancer(Id)                                  │
└────────────────────────────┬─────────────────────────────────────┘
                             │
                             ▼
┌──────────────────────────────────────────────────────────────────┐
│  Handler (src/handlers/loadbalancer_handler.cpp)                 │
│                                                                  │
│  1. Acquire global lock                                          │
│  2. Validate + deserialize HCN JSON → load_balancer struct       │
│  3. Delegate to core                                             │
└────────────────────────────┬─────────────────────────────────────┘
                             │
                             ▼
┌──────────────────────────────────────────────────────────────────┐
│  Core (src/core/loadbalancer.cpp)                                │
│                                                                  │
│  create_loadbalancer():                                          │
│    1. Validate frontend (IP, port, proto)                        │
│    2. Allocate wcn_id (unique LB ID)                             │
│    3. create_backends() → assign backend IDs                     │
│    4. CncCreateLoadBalancerBackends()  ← eBPF map entries        │
│    5. CncCreateLoadBalancerService()   ← eBPF service entry      │
│    6. CncUpdateLoadBalancerServiceBackends()  ← link them        │
│    7. Store in load_balancer_store                                │
│    8. Persist to registry                                        │
│                                                                  │
│  update_loadbalancer():                                          │
│    1. Compute backend delta (add/remove)                         │
│    2. Recover any terminating backends (readiness flaps)          │
│    3. Create new backends                                        │
│    4. CncUpdateLoadBalancerServiceBackends(add, remove)          │
│    5. Update store + persist                                     │
│                                                                  │
│  delete_loadbalancer():                                          │
│    1. CncDeleteLoadBalancerService()                              │
│    2. CncDeleteLoadBalancerBackends() (active + terminating)      │
│    3. Free backend IDs, free LB ID                               │
│    4. Remove from store + persist                                │
└──────────────────────────────────────────────────────────────────┘
```

**Key data structures:**

```cpp
// Frontend (VIP)
struct frontend_t {
    std::wstring ip_address;    // VIP IP
    UINT16 port;                // VIP port
    UINT8 protocol;             // TCP=6, UDP=17
};

// Backend (pod endpoint)
struct backend_t {
    std::wstring ip_address;
    UINT16 port;
    backend_id_t id;            // CNC backend ID
    backend_state state;        // ACTIVE, TERMINATING, QUARANTINED, MAINTENANCE
    load_balancer_id_t lb_id;   // Parent LB
};

// Load balancer config
struct load_balancer {
    frontend_t frontend;
    std::vector<backend_t> backends;
    std::unordered_map<GUID, backend_t> terminating_backends;
    UINT32 flags;               // EXTERNALIP, NODEPORT, HOSTPORT, L4PROXY
    load_balancer_id_t wcn_id;
    GUID hcn_id;
};
```

**Service types in wcnagent:**

| Flag | CNC Service Type | Equivalent |
|------|-----------------|------------|
| `LOAD_BALANCER_SUPPORTED` | `CNC_SERVICE_TYPE_LOAD_BALANCER` | ExternalIP / LoadBalancer |
| `LOAD_BALANCER_NODEPORT` | `CNC_SERVICE_TYPE_NODE_PORT` | NodePort |
| `LOAD_BALANCER_HOSTPORT` | `CNC_SERVICE_TYPE_HOST_PORT` | HostPort |
| (default) | `CNC_SERVICE_TYPE_CLUSTER_IP` | ClusterIP |
| `LOAD_BALANCER_L4PROXY` | (special) | L4 proxy forwarding |

**CNC APIs (Windows eBPF datapath programming):**

| CNC API | Purpose |
|---------|---------|
| `CncCreateLoadBalancerBackends(count, cnc_backend_info_t[])` | Create eBPF backend entries |
| `CncCreateLoadBalancerService(lb_id, cnc_load_balancer_info_t)` | Create eBPF service entry |
| `CncUpdateLoadBalancerServiceBackends(lb_id, add[], remove[])` | Atomic backend update |
| `CncDeleteLoadBalancerService(lb_id, info)` | Delete eBPF service |
| `CncDeleteLoadBalancerBackends(af, backend_ids[])` | Delete eBPF backends |
| `CncGetLoadBalancerService(frontend_info)` | Query for reconciliation |
| `CncGetLoadBalancerBackends(af, ids[])` | Query for reconciliation |

### 2.3 Conceptual Mapping: Linux ↔ Windows

| Concept | Cilium Linux | WcnAgent Windows |
|---------|-------------|-----------------|
| **Service entry** | BPF map: `cilium_lb4_services_v2` (ServiceKey→ServiceValue) | CNC: `CncCreateLoadBalancerService()` → eBPF map |
| **Backend entry** | BPF map: `cilium_lb4_backends_v3` (BackendKey→BackendValue) | CNC: `CncCreateLoadBalancerBackends()` → eBPF map |
| **Service→Backend link** | Service slot entries (slot 1..N point to BackendIDs) | CNC: `CncUpdateLoadBalancerServiceBackends()` |
| **Reverse NAT** | BPF map: `cilium_lb4_reverse_nat` (ServiceID→FrontendAddr) | Handled internally by CNC |
| **Session affinity** | BPF map: `cilium_lb4_affinity_match` + LRU affinity maps | CNC service flags |
| **Source ranges** | BPF map: LPM trie `cilium_lb4_source_range` | CNC service configuration |
| **Maglev hashing** | BPF map: `cilium_lb4_maglev` (inner map per service) | Not applicable (CNC handles distribution) |
| **Socket LB** | cgroup BPF programs intercept connect/sendmsg/recvmsg | Different hook points on Windows |
| **Service ID** | `ServiceID uint16` (allocated by BPFOps) | `load_balancer_id_t` (allocated by wcnagent) |
| **Backend ID** | `BackendID uint32` (allocated by BPFOps) | `backend_id_t` (allocated by wcnagent) |
| **Service type flags** | `ServiceFlags uint16` (15+ bit flags) | `UINT32 flags` + CNC service type enum |
| **NodePort expansion** | Per-node-IP frontend entries in BPF | CNC `CNC_SERVICE_TYPE_NODE_PORT` handles internally |
| **Graceful termination** | Backend state: Active→Terminating; quarantine count in master | `terminating_backends` map + 30s sweep |

---

## 3. Key Architectural Insight: The LBMaps Seam

The most important finding from the code analysis is that Cilium's LB system already has a **clean interface boundary** at the `LBMaps` level:

```go
// pkg/loadbalancer/maps/lbmaps.go

type LBMaps interface {
    // Service maps
    UpdateService(key ServiceKey, value ServiceValue) error
    DeleteService(key ServiceKey) error
    DumpService(cb func(ServiceKey, ServiceValue)) error

    // Backend maps
    UpdateBackend(BackendKey, BackendValue) error
    DeleteBackend(BackendKey) error
    DumpBackend(cb func(BackendKey, BackendValue)) error

    // Reverse NAT maps
    UpdateRevNat(RevNatKey, RevNatValue) error
    DeleteRevNat(RevNatKey) error
    DumpRevNat(cb func(RevNatKey, RevNatValue)) error

    // Session affinity maps
    UpdateAffinityMatch(*AffinityMatchKey, *AffinityMatchValue) error
    DeleteAffinityMatch(*AffinityMatchKey) error
    DumpAffinityMatch(cb func(*AffinityMatchKey, *AffinityMatchValue)) error

    // Source range (CIDR) maps
    UpdateSourceRange(SourceRangeKey, *SourceRangeValue) error
    DeleteSourceRange(SourceRangeKey) error
    DumpSourceRange(cb func(SourceRangeKey, *SourceRangeValue)) error

    // Maglev consistent hashing maps
    UpdateMaglev(key MaglevOuterKey, backendIDs []BackendID, ipv6 bool) error
    DeleteMaglev(key MaglevOuterKey, ipv6 bool) error
    DumpMaglev(cb func(MaglevOuterKey, MaglevOuterVal, MaglevInnerKey, *MaglevInnerVal, bool)) error

    // Socket reverse NAT maps
    UpdateSockRevNat(cookie uint64, addr net.IP, port uint16, revNatIndex uint16) error
    DeleteSockRevNat(cookie uint64, addr net.IP, port uint16) error
    ExistsSockRevNat(cookie uint64, addr net.IP, port uint16) bool
    SockRevNat() (*bpf.Map, *bpf.Map)

    IsEmpty() bool
}
```

**Everything above this interface is platform-agnostic:**
- K8s reflectors (`pkg/loadbalancer/reflectors/`) — convert K8s objects to StateDB writes
- Writer (`pkg/loadbalancer/writer/`) — validated writes, backend selection, frontend refresh
- StateDB tables (Service, Frontend, Backend) — in-memory state store
- BPFOps reconciler (`pkg/loadbalancer/reconciler/`) — Frontend → map operation translation
- ID allocation (ServiceID, BackendID) — managed by BPFOps
- NodePort expansion — managed by BPFOps
- Health server — platform-agnostic HTTP

**Only the `LBMaps` implementation is platform-specific** (plus the socket LB program attachment).

This existing `FakeLBMaps` test implementation already proves the interface is sufficient — the reconciler can function with any implementation that satisfies `LBMaps`.

---

## 4. Proposed Architecture

### 4.1 Layered Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│               Platform-Agnostic (UNCHANGED)                      │
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────────────────┐  │
│  │ K8s Reflectors│  │  StateDB     │  │  BPFOps Reconciler    │  │
│  │              │  │  Tables       │  │  (ID alloc, NodePort  │  │
│  │ Service ────►│  │              │  │   expansion, flag     │  │
│  │ EndpointSlice│  │ Service      │  │   computation, slot   │  │
│  │ Pod ────────►│  │ Frontend     │  │   management)         │  │
│  │              │  │ Backend      │  │                       │  │
│  │  Writer API ─┤  │              │  │                       │  │
│  └──────────────┘  └──────────────┘  └───────────┬───────────┘  │
│                                                  │               │
├──────────────────────────────────────────────────┼───────────────┤
│                  LBMaps Interface                 │               │
│                                                  ▼               │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │  UpdateService / UpdateBackend / UpdateRevNat / ...      │    │
│  └──────────────────────┬───────────────────────────────────┘    │
│                         │                                        │
├─────────────────────────┼────────────────────────────────────────┤
│     Platform-Specific   │   Implementations                      │
│                         │                                        │
│    ┌────────────────────┼────────────────────┐                   │
│    │                    │                    │                   │
│    ▼                    │                    ▼                   │
│ ┌────────────┐          │         ┌──────────────────┐          │
│ │ BPFLBMaps  │          │         │ CNCLBMaps        │          │
│ │ (Linux)    │          │         │ (Windows)        │          │
│ │            │          │         │                  │          │
│ │ 14 BPF maps│          │         │ CNC API calls    │          │
│ │ via ebpf-go│          │         │ or direct eBPF   │          │
│ │            │          │         │ map writes via   │          │
│ └────────────┘          │         │ libbpf           │          │
│                         │         └──────────────────┘          │
│                         │                                        │
│ ┌────────────────────┐  │  ┌──────────────────────────────┐     │
│ │ Socket LB          │  │  │ Socket LB                    │     │
│ │ (Linux)            │  │  │ (Windows)                    │     │
│ │ cgroup BPF attach  │  │  │ Windows eBPF attach points   │     │
│ └────────────────────┘  │  └──────────────────────────────┘     │
└─────────────────────────┴────────────────────────────────────────┘
```

### 4.2 What Stays Common (No Changes Needed)

| Component | Package | Reason |
|-----------|---------|--------|
| K8s reflectors | `pkg/loadbalancer/reflectors/` | Converts K8s objects to Writer calls; no platform code |
| Writer | `pkg/loadbalancer/writer/` | Validated StateDB writes; pure Go logic |
| Service/Frontend/Backend types | `pkg/loadbalancer/` | Data types; no platform code |
| BPFOps reconciler | `pkg/loadbalancer/reconciler/` | Frontend→map ops translation; uses `LBMaps` interface |
| ID allocation | `pkg/loadbalancer/reconciler/` | ServiceID/BackendID allocators; pure Go |
| Health server | `pkg/loadbalancer/healthserver/` | HTTP health checks; platform-agnostic |
| Redirect policy | `pkg/loadbalancer/redirectpolicy/` | CiliumLocalRedirectPolicy; pure Go |
| Config | `pkg/loadbalancer/config.go` | Configuration types; platform-agnostic |
| LB cell wiring | `pkg/loadbalancer/cell/cell.go` | Hive cell composition |
| Map key/value types | `pkg/loadbalancer/maps/types.go` | BPF struct definitions (shared data format) |

### 4.3 What Becomes Platform-Specific

| Component | Current | Change Needed |
|-----------|---------|---------------|
| `LBMaps` implementation | `BPFLBMaps` (Linux BPF maps via ebpf-go) | Add `CNCLBMaps` (Windows CNC API or libbpf) |
| `maps.Cell` provider | Always provides `BPFLBMaps` | Conditionally provide platform implementation |
| Socket LB attachment | `pkg/socketlb/` (cgroup BPF hooks) | Windows equivalent hook attachment |
| `BPFOps` reconciler | Has one `unix.` reference for socket termination | Build-tag the socket termination |
| NodePort address handling | Uses `netns.GetNetNSCookie` (Linux netns) | Build-tag or skip on Windows |

---

## 5. Shim API Design

### 5.1 Option A: LBMaps Adapter (Recommended)

**Approach:** Provide a Windows implementation of the existing `LBMaps` interface. The reconciler (`BPFOps`) remains unchanged — it calls the same `UpdateService`, `UpdateBackend`, etc. methods, but on Windows these operations are routed to CNC APIs instead of BPF map writes.

```go
// pkg/loadbalancer/maps/cnc_lbmaps_windows.go

// CNCLBMaps implements LBMaps for Windows by translating map operations
// to CNC API calls via wcnagent.
type CNCLBMaps struct {
    wcnagent    *wcnagentLib        // wcnagent DLL handle
    log         *slog.Logger

    // State tracking: the reconciler calls individual map operations
    // (UpdateService, UpdateBackend) but CNC APIs operate on complete
    // service objects. We need to buffer map writes and flush them
    // as CNC API calls.
    services    map[serviceAddr]*cncServiceState
    backends    map[BackendID]*cncBackendState
    mu          sync.Mutex
}

// UpdateService stores the service entry. When the master slot (slot 0) is
// written, this signals that all slots are complete and we can flush to CNC.
func (c *CNCLBMaps) UpdateService(key ServiceKey, value ServiceValue) error {
    c.mu.Lock()
    defer c.mu.Unlock()

    addr := serviceAddrFromKey(key)
    state := c.getOrCreateServiceState(addr)

    if key.GetBackendSlot() == 0 {
        // Master slot — contains backend count and flags
        state.masterValue = value
        state.masterWritten = true
        // Flush complete service to CNC
        return c.flushServiceToCNC(addr, state)
    }

    // Backend slot — record the backend reference
    state.slots[key.GetBackendSlot()] = value.GetBackendID()
    return nil
}

// UpdateBackend stores the backend entry for later CNC flush.
func (c *CNCLBMaps) UpdateBackend(key BackendKey, value BackendValue) error {
    c.mu.Lock()
    defer c.mu.Unlock()

    c.backends[key.GetID()] = &cncBackendState{
        id:      key.GetID(),
        address: value.GetAddress(),
        port:    value.GetPort(),
        proto:   value.GetProtocol(),
        state:   value.GetState(),
    }
    return nil
}

// flushServiceToCNC converts buffered map operations into CNC API calls.
func (c *CNCLBMaps) flushServiceToCNC(addr serviceAddr, state *cncServiceState) error {
    // Build cnc_backend_info_t[] from state.slots + c.backends
    // Call CncCreateLoadBalancerBackends or CncUpdateLoadBalancerServiceBackends
    // Call CncCreateLoadBalancerService or update
    // ...
}
```

**Advantages:**
- No changes to the reconciler (`BPFOps`), Writer, reflectors, or any platform-agnostic code
- The `FakeLBMaps` test pattern proves this works
- Minimal new code — only the `CNCLBMaps` adapter + CNC API bindings
- All existing tests continue to work with `FakeLBMaps`

**Challenges:**
- The reconciler writes individual map entries (per-slot, per-backend), but CNC APIs operate on complete services. The adapter must buffer and flush.
- Some LBMaps sub-interfaces (Maglev, SockRevNat) may not have direct CNC equivalents and need stubs or alternative implementations.

### 5.2 Option B: Higher-Level Platform LB Interface

**Approach:** Define a new higher-level interface at the reconciler level that abstracts service/backend lifecycle.

```go
// pkg/loadbalancer/types/platform_lb.go

type PlatformLB interface {
    UpsertService(svc PlatformServiceConfig) error
    DeleteService(serviceID ServiceID) error
    UpsertBackend(backend PlatformBackendConfig) error
    DeleteBackend(backendID BackendID) error
    AssociateBackends(serviceID ServiceID, backendIDs []BackendID) error
}
```

**Advantages:**
- Cleaner mapping to CNC APIs (1:1 correspondence)
- No buffering needed

**Disadvantages:**
- Requires refactoring the reconciler to use this interface instead of (or in addition to) `LBMaps`
- Duplicates logic that already exists in `BPFOps`
- Breaks the existing test pattern
- More invasive changes to platform-agnostic code

### 5.3 Recommendation and Rationale

**Recommended: Option A (LBMaps Adapter)**

The `LBMaps` interface is already the perfect abstraction point. The buffering challenge is manageable because:

1. The reconciler always writes slots 1..N before writing slot 0 (master). The master write is the natural "commit" signal.
2. Backend entries are always written before service slots that reference them.
3. The `FakeLBMaps` implementation already handles this pattern (it stores everything in-memory maps).

However, there is an **important refinement** for Windows. If Windows uses the same eBPF map layout as Linux (which is the case since CNC programs the same eBPF maps), then the simplest implementation is:

**Option A.1: Direct eBPF map writes via libbpf on Windows**

Since Windows supports libbpf APIs and the eBPF maps have the same structure, the Windows `LBMaps` implementation could **write directly to the eBPF maps** using libbpf, just like Linux uses ebpf-go. This completely eliminates the need for CNC API translation and buffering.

```go
// pkg/loadbalancer/maps/libbpf_lbmaps_windows.go

type LibbpfLBMaps struct {
    // Same map structure as BPFLBMaps, but using libbpf Go bindings
    // instead of cilium/ebpf (ebpf-go).
    service4Map *libbpf.Map
    backend4Map *libbpf.Map
    // ...
}
```

**Option A.2: CNC API adapter (if CNC APIs must be used)**

If the Windows datapath requires using CNC APIs (e.g., because CNC manages additional state beyond the eBPF maps), then the buffering adapter from Option A is the right approach.

**Decision:** The choice between A.1 and A.2 depends on whether the Windows eBPF datapath can be programmed directly via libbpf or requires CNC as an intermediary. We should validate this with the team.

---

## 6. Linux Implementation (Existing — No Changes)

The Linux `BPFLBMaps` implementation remains exactly as it is today. No refactoring is needed because the `LBMaps` interface already exists and `BPFLBMaps` implements it.

The only changes needed on the Linux side are:
1. Move `maps.Cell` provider to conditionally select `BPFLBMaps` on Linux and the Windows implementation on Windows (via build tags).
2. Build-tag the `unix.` references in the reconciler's socket termination code.

---

## 7. Windows Implementation

### 7.1 CNC LBMaps Adapter

If CNC APIs are required (Option A.2), the adapter translates fine-grained map operations into CNC service lifecycle calls:

```
BPFOps calls:                      CNC translation:
─────────────                      ─────────────────
UpdateBackend(be1)     ──────►     Buffer be1
UpdateBackend(be2)     ──────►     Buffer be2
UpdateService(svc, slot=1, be1) ─► Buffer slot 1 → be1
UpdateService(svc, slot=2, be2) ─► Buffer slot 2 → be2
UpdateRevNat(id, addr)  ──────►    Buffer revnat
UpdateService(svc, slot=0, ...)  ─► FLUSH:
                                     CncCreateLoadBalancerBackends([be1, be2])
                                     CncCreateLoadBalancerService(svc)
                                     CncUpdateLoadBalancerServiceBackends(svc, [be1, be2])
```

**Key implementation details:**

```go
type cncServiceState struct {
    // Frontend identification
    frontendAddr    netip.AddrPort
    protocol        uint8
    serviceID       ServiceID

    // State from master slot
    masterValue     ServiceValue
    masterWritten   bool
    flags           ServiceFlags

    // Backend slot references
    slots           map[int]BackendID

    // CNC state
    cncCreated      bool    // Has CNC service been created?
    prevBackendIDs  []BackendID  // For computing deltas on update
}

type cncBackendState struct {
    id       BackendID
    address  netip.Addr
    port     uint16
    proto    uint8
    state    uint8     // Active/Terminating/Quarantined
    cncCreated bool
}
```

### 7.2 State Tracking

The adapter needs to track which services/backends have been created in CNC to determine whether to call `Create` vs `Update`:

| Map Operation | CNC Action (first time) | CNC Action (update) |
|---------------|------------------------|---------------------|
| `UpdateService` (master flush) | `CncCreateLoadBalancerService` + `CncUpdateLoadBalancerServiceBackends` | `CncUpdateLoadBalancerServiceBackends` (delta) |
| `UpdateBackend` | `CncCreateLoadBalancerBackends` | No-op (backends are immutable once created) |
| `DeleteService` | `CncDeleteLoadBalancerService` | — |
| `DeleteBackend` | `CncDeleteLoadBalancerBackends` | — |

### 7.3 WcnAgent Integration

The CNC API calls can be made in two ways:

**A. Via wcnagent DLL (wcnagent as LB backend):**
```
CNCLBMaps → wcnagent.CreateLoadBalancer(json) → CncCreateLoadBalancerService
```
This wraps CNC calls inside wcnagent's existing transaction/journaling/crash-recovery framework.

**B. Direct CNC API calls (bypass wcnagent):**
```
CNCLBMaps → CncCreateLoadBalancerService(directly)
```
This is simpler but loses wcnagent's crash-recovery journaling.

**Recommendation:** Use wcnagent DLL for the LB operations as well, for consistency with the pod networking shim and to benefit from wcnagent's crash-recovery mechanism. The JSON schema conversion is straightforward — wcnagent already accepts HCN `HostComputeLoadBalancer` schema.

### 7.4 BPF Program Attachment Differences

On Linux, socket LB programs are attached to cgroup hooks. On Windows, the attachment points differ:

| Linux Hook | Windows Equivalent | Notes |
|-----------|-------------------|-------|
| `cgroup/connect4` | Windows eBPF socket hook (if available) | Intercepts TCP connect |
| `cgroup/sendmsg4` | Windows eBPF socket hook | Intercepts UDP send |
| `cgroup/recvmsg4` | Windows eBPF socket hook | Reverse NAT on receive |
| `cgroup/getpeername4` | Windows eBPF socket hook | Return original VIP |
| TC ingress on veth | Windows eBPF on VFP/FL interface | NodePort from pod |
| XDP on physical NIC | Windows eBPF XDP-equivalent | NodePort acceleration |

The socket LB program attachment needs a Windows-specific implementation. Since the programs are pre-compiled on Windows (as noted in the constraints), the attachment logic differs:

```go
// pkg/socketlb/socketlb_windows.go

func Enable(logger *slog.Logger, cfg *datapath.LocalNodeConfiguration) error {
    // On Windows:
    // 1. Programs are pre-compiled (.sys or .o files)
    // 2. Load via libbpf APIs (bpf_object__open, bpf_object__load)
    // 3. Attach to Windows-specific hook points
    // 4. Some configuration passed via maps instead of compile-time constants
    return attachWindowsSocketLB(logger, cfg)
}
```

---

## 8. Socket-Level LB on Windows

Socket-level LB is critical for ClusterIP service access from pods. On Linux, BPF programs intercept `connect()` at the cgroup level. On Windows, the equivalent mechanism depends on the Windows eBPF stack:

**If Windows eBPF supports cgroup-like socket hooks:**
- The same logical programs can be used, pre-compiled for Windows.
- Attachment uses libbpf APIs instead of cilium/ebpf.
- Configuration that is compiled in on Linux (e.g., `ENABLE_IPV4`, `ENABLE_SOCKET_LB_HOST_ONLY`) must be passed via maps on Windows.

**If Windows eBPF does not support socket hooks:**
- Socket LB must be handled by VFP rules or CNC routing.
- ClusterIP traffic would be intercepted at the network interface level (TC-equivalent) rather than at the socket level.
- This has performance implications (packets are fully formed before interception).

**Shim for socket LB attachment:**

```go
// pkg/socketlb/cell.go — existing cell, updated with build tags

// socketlb_linux.go
func newSocketLB() SocketLB { return &linuxSocketLB{} }

// socketlb_windows.go  
func newSocketLB() SocketLB { return &windowsSocketLB{} }

type SocketLB interface {
    Enable(ctx context.Context, cfg *SocketLBConfig) error
    Disable() error
}
```

---

## 9. Data Flow Diagrams

### 9.1 Service Creation — Linux (Current)

```
K8s Service (ClusterIP: 10.96.0.1:80, TCP)
  + EndpointSlice (backends: 10.0.1.10:8080, 10.0.1.11:8080)
    │
    ▼
K8s Reflector
    │ convertService() → Service{ClusterIP, ...}
    │ convertEndpoints() → [Backend{10.0.1.10:8080}, Backend{10.0.1.11:8080}]
    │ Writer.UpsertServiceAndFrontends()
    │ Writer.UpsertBackends()
    ▼
StateDB: Frontend{addr=10.96.0.1:80/TCP, status=Pending}
    │
    ▼ (reconciler detects Pending)
BPFOps.Update(frontend)
    │
    ├─ ServiceID = 42 (allocated)
    ├─ BackendID[1] = 101 (for 10.0.1.10:8080)
    ├─ BackendID[2] = 102 (for 10.0.1.11:8080)
    │
    ├─ LBMaps.UpdateBackend(Backend4Key{101}, Backend4Value{10.0.1.10, 8080, TCP})
    ├─ LBMaps.UpdateBackend(Backend4Key{102}, Backend4Value{10.0.1.11, 8080, TCP})
    ├─ LBMaps.UpdateService(Svc4Key{10.96.0.1, 80, TCP, slot=1}, SvcVal{backendID=101})
    ├─ LBMaps.UpdateService(Svc4Key{10.96.0.1, 80, TCP, slot=2}, SvcVal{backendID=102})
    ├─ LBMaps.UpdateRevNat(RevNat4Key{42}, RevNat4Val{10.96.0.1, 80})
    └─ LBMaps.UpdateService(Svc4Key{10.96.0.1, 80, TCP, slot=0}, SvcVal{count=2, revnat=42})
```

### 9.2 Service Creation — Windows (After Refactoring)

```
K8s Service (ClusterIP: 10.96.0.1:80, TCP)
  + EndpointSlice (backends: 10.0.1.10:8080, 10.0.1.11:8080)
    │
    ▼
K8s Reflector                         ◄── UNCHANGED
    │
    ▼
StateDB: Frontend{addr=10.96.0.1:80/TCP, status=Pending}    ◄── UNCHANGED
    │
    ▼ (reconciler detects Pending)
BPFOps.Update(frontend)              ◄── UNCHANGED
    │
    ├─ ServiceID = 42
    ├─ BackendID[1] = 101, BackendID[2] = 102
    │
    ├─ LBMaps.UpdateBackend(101, ...) ──► CNCLBMaps: buffer backend 101
    ├─ LBMaps.UpdateBackend(102, ...) ──► CNCLBMaps: buffer backend 102
    ├─ LBMaps.UpdateService(slot=1)   ──► CNCLBMaps: buffer slot 1 → 101
    ├─ LBMaps.UpdateService(slot=2)   ──► CNCLBMaps: buffer slot 2 → 102
    ├─ LBMaps.UpdateRevNat(42, ...)   ──► CNCLBMaps: buffer revnat
    └─ LBMaps.UpdateService(slot=0)   ──► CNCLBMaps: FLUSH
                                            │
                                            ├─ wcnagent.CreateLoadBalancer(json)
                                            │   └─ CncCreateLoadBalancerBackends()
                                            │   └─ CncCreateLoadBalancerService()
                                            │   └─ CncUpdateLoadBalancerServiceBackends()
                                            │
                                            └─ (or direct libbpf map writes)
```

### 9.3 NodePort Service — Cross-Platform

```
K8s Service (NodePort: 30080, ClusterIP: 10.96.0.1:80)
    │
    ▼
K8s Reflector → Writer.UpsertServiceAndFrontends()
    │
    │ Creates frontends:
    │   Frontend{10.96.0.1:80/TCP, ClusterIP}     ← ClusterIP VIP
    │   Frontend{0.0.0.0:30080/TCP, NodePort}      ← Wildcard NodePort
    │
    ▼
BPFOps.Update(ClusterIP frontend)  → LBMaps operations (as above)

BPFOps.Update(NodePort frontend)
    │
    ├─ Query NodeAddress table for all node IPs
    ├─ For each node IP (e.g., 192.168.1.10, 192.168.1.11):
    │   ├─ Create LBMaps entry: ServiceKey{192.168.1.10, 30080, TCP}
    │   └─ Create LBMaps entry: ServiceKey{192.168.1.11, 30080, TCP}
    │
    │  Linux: Each entry goes to BPF map via BPFLBMaps
    │  Windows: Each entry goes to CNCLBMaps → CNC with NODE_PORT type
    └─
```

---

## 10. eBPF Considerations for Windows

The constraints mention key differences in eBPF between Linux and Windows. Here is how they affect LB:

### 10.1 Pre-compiled Programs

On Linux, BPF programs are compiled on demand with configuration baked in as `#define` constants. On Windows, programs are pre-compiled, so configuration must be passed via maps.

**Impact on LB:**
- The socket LB programs (`bpf_sock.c`) on Linux use compile-time defines like `ENABLE_IPV4`, `ENABLE_SOCKET_LB_HOST_ONLY`, `ENABLE_SOCKET_LB_PEER`.
- On Windows, these must be read from a configuration map at runtime.
- The `LBMaps` interface itself is not affected — the map data format is the same regardless of how programs read it.

**Proposed approach:**
```go
// pkg/socketlb/config_map_windows.go

// WriteConfigToMap writes socket LB configuration to a BPF map
// that the pre-compiled Windows programs read at runtime.
func WriteConfigToMap(cfg SocketLBConfig) error {
    configMap, err := libbpf.OpenMap("cilium_sock_config")
    if err != nil { return err }

    var config SockLBConfigValue
    if cfg.EnableIPv4 { config.Flags |= SOCK_LB_FLAG_IPV4 }
    if cfg.EnableIPv6 { config.Flags |= SOCK_LB_FLAG_IPV6 }
    if cfg.HostOnly   { config.Flags |= SOCK_LB_FLAG_HOST_ONLY }
    // ...
    return configMap.Update(SockLBConfigKey{0}, config)
}
```

### 10.2 Different Attachment Points

The BPF programs for LB are attached at different points on Windows. The reconciler and `LBMaps` are not affected — attachment is handled by the socket LB loader (see §8).

### 10.3 Same Map Data Format (libbpf APIs)

Since Windows supports libbpf APIs and uses the same eBPF map structures, the `ServiceKey`, `BackendKey`, `RevNatKey` types from `pkg/loadbalancer/maps/types.go` can be used directly on Windows if the maps are accessed via libbpf.

This is the strongest argument for **Option A.1 (direct libbpf map writes)** — the Windows implementation can share the same key/value types and just use a different map access library.

---

## 11. Open Questions & Decisions

### Q1: Direct libbpf vs CNC API for map programming?

**Options:**
- **A.1: Direct libbpf map writes** — Uses libbpf Go bindings to write to the same BPF maps as Linux. Simpler, no buffering needed. Requires that the Windows eBPF maps have the same layout.
- **A.2: CNC API adapter** — Translates map operations to CNC calls. Required if CNC manages additional state (e.g., NodePort address binding, connection tracking integration). More complex due to buffering.
- **A.3: WcnAgent DLL** — Goes through wcnagent's CreateLoadBalancer/ModifyLoadBalancer APIs. Gets crash-recovery journaling for free. Most complex mapping (reconciler's per-slot model ↔ wcnagent's full-service model).

**Recommendation:** Validate with the team whether libbpf direct access (A.1) is possible. If yes, it's the simplest path. If CNC APIs are required, use A.2. Avoid A.3 unless wcnagent's crash-recovery is essential for LB.

### Q2: Maglev consistent hashing on Windows?

Maglev requires a BPF map-in-map (outer map → inner map with hash table). This is supported on Linux but may not be available on Windows eBPF.

**Options:**
- If Windows eBPF supports map-in-map: Implement Maglev maps via libbpf.
- If not: Disable Maglev on Windows; use random backend selection. The reconciler already handles this based on configuration (`ops.useMaglev(fe)` checks `cfg.LBAlgorithm`).

### Q3: Session affinity maps on Windows?

Session affinity uses LRU hash maps (`cilium_lb4_affinity`, `cilium_lb6_affinity`). These are per-client-IP maps managed by the BPF programs, not by the control plane. The control plane only manages the `affinity_match` map (which backends are eligible for affinity).

**If Windows eBPF supports LRU hash:** Works as-is.
**If not:** Session affinity would need a different mechanism (e.g., CNC-managed affinity state).

### Q4: Socket termination on Windows?

When a backend is removed, Cilium terminates existing TCP connections to that backend (`SocketTerminationCell`). On Linux, this uses `unix.IPPROTO_TCP` and socket iteration via BPF.

On Windows, this would need a platform-specific implementation using Windows socket APIs or CNC.

### Q5: `unix.` references in the reconciler

The `BPFOps` reconciler has a small number of `unix.` references:
- Socket termination code uses `unix.IPPROTO_TCP`
- `netns.GetNetNSCookie` is used in the K8s reflector for HostPort handling

These need build-tag splits or platform-agnostic replacements.

### Q6: NodePort address binding protection

On Linux, `PostBind` BPF programs prevent userspace from binding to NodePort ports. On Windows, this would need an equivalent mechanism or be handled at a different level (e.g., Windows port reservation APIs like `CreatePersistentUdpPortReservation`, which wcnagent already uses).

---

## Appendix A: LBMaps Sub-Interface Mapping for Windows

| LBMaps Sub-Interface | Linux (BPFLBMaps) | Windows Option A.1 (libbpf) | Windows Option A.2 (CNC) |
|---------------------|-------------------|---------------------------|-------------------------|
| `serviceMaps` | BPF hash map writes | libbpf map writes (same layout) | `CncCreateLoadBalancerService` + buffering |
| `backendMaps` | BPF hash map writes | libbpf map writes | `CncCreateLoadBalancerBackends` |
| `revNatMaps` | BPF hash map writes | libbpf map writes | CNC handles internally |
| `affinityMaps` | BPF hash map writes | libbpf map writes | CNC service config flags |
| `sourceRangeMaps` | BPF LPM trie writes | libbpf LPM trie writes | CNC service config |
| `maglevMaps` | BPF map-in-map | libbpf map-in-map (if supported) | Not applicable (CNC handles distribution) |
| `sockRevNatMaps` | BPF LRU hash writes | libbpf LRU hash writes | CNC handles internally |

## Appendix B: Files Changed / Created

### New Files

| File | Purpose |
|------|---------|
| `pkg/loadbalancer/maps/lbmaps_windows.go` | Windows `LBMaps` implementation (CNC adapter or libbpf) |
| `pkg/loadbalancer/maps/cell_linux.go` | Linux cell provider (moved from `cell.go`) |
| `pkg/loadbalancer/maps/cell_windows.go` | Windows cell provider |
| `pkg/socketlb/socketlb_windows.go` | Windows socket LB attachment |
| `pkg/socketlb/cgroup_windows.go` | Windows BPF hook management (or no-op stub) |
| `pkg/loadbalancer/reconciler/termination_linux.go` | Build-tagged socket termination (from existing code) |
| `pkg/loadbalancer/reconciler/termination_windows.go` | Windows socket termination stub |

### Modified Files

| File | Change |
|------|--------|
| `pkg/loadbalancer/maps/cell.go` | Split into `cell_linux.go` / `cell_windows.go` for platform provider |
| `pkg/loadbalancer/reconciler/bpf_reconciler.go` | Build-tag `unix.` references (minimal) |
| `pkg/loadbalancer/reflectors/k8s.go` | Build-tag `netns.GetNetNSCookie` reference |
| `pkg/socketlb/socketlb.go` | Split into `socketlb_linux.go` / `socketlb_windows.go` |
| `pkg/socketlb/cgroup.go` | Rename to `cgroup_linux.go` |

### Unchanged Files (Platform-Agnostic)

| File | Notes |
|------|-------|
| `pkg/loadbalancer/service.go` | Service type — no platform code |
| `pkg/loadbalancer/frontend.go` | Frontend type — no platform code |
| `pkg/loadbalancer/backend.go` | Backend type — no platform code |
| `pkg/loadbalancer/loadbalancer.go` | Core types — no platform code |
| `pkg/loadbalancer/config.go` | Configuration — no platform code |
| `pkg/loadbalancer/writer/writer.go` | Writer — no platform code |
| `pkg/loadbalancer/reconciler/bpf_reconciler.go` | BPFOps — uses `LBMaps` interface (unchanged except build-tags) |
| `pkg/loadbalancer/reconciler/cell.go` | Reconciler cell — no platform code |
| `pkg/loadbalancer/reflectors/conversions.go` | K8s conversion — no platform code |
| `pkg/loadbalancer/cell/cell.go` | LB meta cell — no platform code |
| `pkg/loadbalancer/maps/types.go` | BPF struct types — shared data format |
| `pkg/loadbalancer/healthserver/` | Health checks — no platform code |
| `pkg/loadbalancer/redirectpolicy/` | Redirect policies — no platform code |

## Appendix C: WcnAgent LB API Mapping

| CNC API | LBMaps Method(s) Equivalent | Notes |
|---------|---------------------------|-------|
| `CncCreateLoadBalancerBackends` | `UpdateBackend` (multiple) | Multiple backends in single call |
| `CncCreateLoadBalancerService` | `UpdateService` (slot 0) | Service master entry |
| `CncUpdateLoadBalancerServiceBackends` | `UpdateService` (slots 1..N) | Backend association |
| `CncDeleteLoadBalancerService` | `DeleteService` (all slots) | Full service removal |
| `CncDeleteLoadBalancerBackends` | `DeleteBackend` (multiple) | Multiple backends in single call |
| `CncGetLoadBalancerService` | `DumpService` (filtered) | Query for reconciliation |
| `CncGetLoadBalancerBackends` | `DumpBackend` (filtered) | Query for reconciliation |
