# Cilium Agent — Windows Pod Networking: Detailed Design

> **Scope:** Phase 1 — Pod-to-pod networking only (endpoint creation, namespace/compartment management, node configuration).  
> **Status:** Draft for team review.  
> **Audience:** Engineering team, Copilot (for future implementation).

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Current Architecture Analysis](#2-current-architecture-analysis)
   - 2.1 [Cilium Linux: CNI Plugin + Agent Flow](#21-cilium-linux-cni-plugin--agent-flow)
   - 2.2 [WcnAgent Windows: Pod Networking Flow](#22-wcnagent-windows-pod-networking-flow)
   - 2.3 [Conceptual Mapping: Linux ↔ Windows](#23-conceptual-mapping-linux--windows)
3. [Namespace and Network Creation: Linux vs. Windows](#3-namespace-and-network-creation-linux-vs-windows)
4. [Proposed Architecture](#4-proposed-architecture)
   - 4.1 [Layered Architecture Overview](#41-layered-architecture-overview)
   - 4.2 [Platform Shim Interface Design](#42-platform-shim-interface-design)
   - 4.3 [CNI Plugin Refactoring](#43-cni-plugin-refactoring)
   - 4.4 [Daemon Endpoint Lifecycle Refactoring](#44-daemon-endpoint-lifecycle-refactoring)
   - 4.5 [Node Initialization Refactoring](#45-node-initialization-refactoring)
5. [Shim API Definitions](#5-shim-api-definitions)
   - 5.1 [PlatformNetwork Interface](#51-platformnetwork-interface)
   - 5.2 [PlatformEndpoint Interface](#52-platformendpoint-interface)
   - 5.3 [PlatformNode Interface](#53-platformnode-interface)
   - 5.4 [PlatformNamespace Interface](#54-platformnamespace-interface)
6. [Linux Platform Implementation](#6-linux-platform-implementation)
7. [Windows Platform Implementation](#7-windows-platform-implementation)
   - 7.1 [Integration with WcnAgent](#71-integration-with-wcnagent)
   - 7.2 [HNS/HCS Direct Integration](#72-hnshcs-direct-integration)
   - 7.3 [Recommended Approach](#73-recommended-approach)
8. [Data Flow Diagrams](#8-data-flow-diagrams)
9. [Interface Contract Details](#9-interface-contract-details)
10. [Open Questions & Decisions](#10-open-questions--decisions)

---

## 1. Executive Summary

This document proposes a design to refactor the Cilium agent's pod networking path so that **platform-agnostic control-plane logic is shared** between Linux and Windows, while **platform-specific networking operations are isolated behind a shim interface layer**.

### Key Principles

1. **Minimal disruption to existing Linux code** — The Linux path should continue to work exactly as it does today. Refactoring moves existing Linux code behind interfaces without changing behavior.
2. **WcnAgent as the Windows networking backend** — On Windows, the Cilium agent delegates pod networking operations to wcnagent (loaded as a DLL), which already implements HNS/compartment/FL-virtual-interface management.
3. **Shim interfaces designed from both sides** — The shim API is designed by analyzing both the Cilium Linux flow and the wcnagent Windows flow, ensuring it can be naturally implemented by both.
4. **Phase 1 scope: pod networking only** — This design covers endpoint creation, IP assignment, routing, DNS, and namespace/compartment management. Load balancing and network policies will be covered in subsequent phases.

---

## 2. Current Architecture Analysis

### 2.1 Cilium Linux: CNI Plugin + Agent Flow

On Linux, pod networking involves two components working together:

#### CNI Plugin (`plugins/cilium-cni/`)

The CNI plugin is a short-lived process invoked by the container runtime (containerd/CRI-O) for each pod lifecycle event. For pod creation (CNI ADD):

```
CNI ADD Flow (Linux):
┌──────────────────────────────────────────────────────────────────────┐
│  1. Parse CNI config & pod metadata (K8S_POD_NAME, K8S_POD_NAMESPACE)│
│  2. Connect to Cilium agent via Unix socket                          │
│  3. Get agent config (IPAM mode, MTU, datapath mode)                 │
│  4. Allocate IP from agent IPAM (POST /ipam)                         │
│  5. Create veth/netkit pair:                                         │
│     - Host side: lxc<hash> (stays in host netns)                     │
│     - Peer side: tmp<id> → renamed to eth0 (moved to container netns)│
│  6. Configure container interface (inside container netns):          │
│     - Bring up eth0                                                  │
│     - Add IP address (netlink.AddrAdd)                               │
│     - Add routes (netlink.RouteAdd): default via host link-local     │
│  7. Build EndpointChangeRequest with IPs, MACs, interface info       │
│  8. Send to agent (PUT /endpoint/{id}) — agent compiles BPF programs │
│  9. Return CNI result to container runtime                           │
└──────────────────────────────────────────────────────────────────────┘
```

**Key files:**
- `plugins/cilium-cni/cmd/cmd_linux.go` — Platform-specific CNI ADD/DEL
- `pkg/datapath/connector/veth.go` — Veth pair creation via netlink
- `pkg/datapath/connector/link.go` — Link pair management (`NewLinkPair`)
- `pkg/datapath/connector/ipam.go` — Route calculation for container

#### Cilium Agent / Daemon

The daemon receives the `EndpointChangeRequest` and handles the control-plane lifecycle:

```
Agent Endpoint Creation Flow:
┌──────────────────────────────────────────────────────────────────────┐
│  1. Receive PUT /endpoint/{id} with EndpointChangeRequest            │
│  2. Create Endpoint object from change request                       │
│     (EndpointCreator.NewEndpointFromChangeModel)                     │
│  3. Allocate endpoint ID (1-65535 from ID pool)                      │
│  4. Register endpoint in EndpointManager                             │
│     (maps: by ID, by container ID, by IPv4, by IPv6, by pod name)    │
│  5. Fetch K8s pod metadata (labels, annotations)                     │
│  6. Assign identity labels                                           │
│  7. Trigger endpoint regeneration:                                   │
│     a. Wait for host datapath initialization                         │
│     b. Write endpoint BPF header (lxc_config.h)                     │
│     c. Compile BPF programs (bpf_lxc.c → bpf_lxc.o)                │
│     d. Load BPF programs into kernel                                 │
│     e. Attach to TC hooks on host-side veth (cil_from_container,     │
│        cil_to_container)                                             │
│     f. Insert policy program into tail-call map                      │
│     g. Optionally create per-endpoint routes                         │
│  8. Update lxcmap (BPF endpoint map) with endpoint info              │
│  9. Sync CiliumEndpoint CRD to Kubernetes                            │
│  10. Return endpoint model to CNI plugin                             │
└──────────────────────────────────────────────────────────────────────┘
```

**Key files:**
- `pkg/endpoint/api/endpoint_api_manager.go` — `CreateEndpoint()` orchestration
- `pkg/endpoint/creator/creator.go` — `EndpointCreator` interface
- `pkg/endpointmanager/manager.go` — Endpoint registration and lifecycle
- `pkg/endpoint/bpf.go` — BPF regeneration (`regenerateBPF`)
- `pkg/datapath/loader/endpoint.go` — BPF program loading (`ReloadDatapath`)
- `pkg/datapath/loader/tc.go` — TC hook attachment

#### Existing Abstraction Interfaces

Cilium already has several interfaces that provide extension points:

| Interface | Location | Purpose |
|-----------|----------|---------|
| `datapath.Loader` | `pkg/datapath/types/loader.go` | BPF compilation, loading, initialization |
| `datapath.Orchestrator` | `pkg/datapath/types/orchestrator.go` | High-level datapath orchestration |
| `datapath.ConnectorConfig` | `pkg/datapath/types/connector.go` | Link pair creation (veth/netkit) |
| `datapath.EndpointConfiguration` | `pkg/datapath/types/config.go` | Endpoint compile/load-time config |
| `datapath.NodeHandler` | `pkg/datapath/types/node.go` | Node lifecycle (add/update/delete) |
| `datapath.ConfigWriter` | `pkg/datapath/types/config.go` | BPF header generation |
| `EndpointCreator` | `pkg/endpoint/creator/creator.go` | Endpoint object creation |

These existing interfaces already provide the **seams** where platform-specific implementations can be plugged in.

### 2.2 WcnAgent Windows: Pod Networking Flow

WcnAgent is a Windows DLL (`wcnagent.dll`) that provides pod networking via an explicit API-driven model. The pod creation flow is a 4-step process:

```
WcnAgent Pod Creation Flow:
┌──────────────────────────────────────────────────────────────────────┐
│                                                                      │
│  Step 1: CreateNamespace (Isolation Boundary)                        │
│  ├── Create Windows kernel network compartment (CreateCompartment)   │
│  ├── Reserve UDP ports in compartment                                │
│  ├── Persist to registry                                             │
│  └── Result: compartment_id, compartment_guid                        │
│                                                                      │
│  Step 2: CreateNetwork (IP Fabric) — typically once per node         │
│  ├── Validate network type (L2Bridge)                                │
│  ├── Initialize IP pool from subnets                                 │
│  ├── Check subnet overlap with existing networks                     │
│  ├── Program SNAT exclusions (CncAddSnatExcludedSubnets)             │
│  ├── Select and configure host adapter (GetAdaptersAddresses)        │
│  ├── Register node config with CNC (CncAddOrUpdateNodeConfiguration) │
│  ├── Create L4 proxy port-forwarding rules                           │
│  ├── Persist to registry                                             │
│  └── Result: network with adapter_luid, IP pool, mac_address         │
│                                                                      │
│  Step 3: CreateEndpoint (Pod NIC Identity)                           │
│  ├── Validate host ports                                             │
│  ├── Determine local vs. remote endpoint                             │
│  ├── Set MAC address from network adapter                            │
│  ├── Allocate wcn_id (local only)                                    │
│  ├── For remote: program CNC neighbors (CncAddOrUpdateNeighbor)      │
│  ├── Store in endpoint_store                                         │
│  ├── Persist to registry                                             │
│  └── Result: endpoint object with IP, MAC, wcn_id                    │
│                                                                      │
│  Step 4: ModifyNamespace / attach_endpoint_to_namespace              │
│  ├── Create FL virtual interface in compartment                      │
│  │   (CreateFlVirtualInterface — both IPv4 and IPv6)                 │
│  ├── Assign IP addresses (CreateUnicastIpAddressEntry)               │
│  ├── Configure DNS (SetInterfaceDnsSettings)                         │
│  ├── Disable DHCP on interface                                       │
│  ├── Create routes and ARP entries (CreateIpForwardEntry2,           │
│  │   CreateIpNetEntry2)                                              │
│  ├── Register endpoint with CNC (CncAddOrUpdateEndpoint)             │
│  ├── Apply ACL policies (CncSetIdentity, CncAddOrUpdateEndpointPolicies)│
│  ├── Create port-forwarding rules                                    │
│  └── Persist updated state to registry                               │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

**Key source files:**
- `include/api/wcnagent.h` — API function table definition
- `src/core/namespace.cpp` — `create_namespace()`, `attach_endpoint_to_namespace()`
- `src/core/network.cpp` — `create_network()`
- `src/core/endpoint.cpp` — `create_endpoint()`
- `src/core/node_config.cpp` — Node adapter selection and CNC config

**Key data structures:**
```
namespace_config:
  ├─ compartment_guid, compartment_id  (Windows kernel network compartment)
  ├─ endpoint_ids                       (attached endpoints)
  └─ container_ids                      (attached containers)

network:
  ├─ adapter_luid, adapter_mac          (host adapter identity)
  ├─ ip_pool                            (subnet CIDRs)
  └─ mgmt_ipv4/ipv6_address            (host management IPs)

endpoint:
  ├─ wcn_id                             (unique endpoint ID)
  ├─ network_wcn_id                     (parent network)
  ├─ ipv4/ipv6_address                  (pod IPs)
  ├─ virtual_interface_luid/index/guid  (FL virtual interface — set during attachment)
  ├─ namespace_guid                     (owning compartment)
  ├─ routes, dns, acl_policies          (networking config)
  └─ flags (local vs remote)
```

### 2.3 Conceptual Mapping: Linux ↔ Windows

| Concept | Linux (Cilium) | Windows (WcnAgent) |
|---------|---------------|---------------------|
| **Pod isolation** | Network namespace (pre-created by container runtime) | Network compartment (`CreateCompartment` — created by wcnagent) |
| **Pod network interface** | Veth pair: `lxc<hash>` ↔ `eth0` | FL Virtual Interface (`CreateFlVirtualInterface`) |
| **Interface creation** | `netlink.LinkAdd(&netlink.Veth{...})` | `CreateFlVirtualInterface()` inside compartment |
| **Move interface to pod** | `netlink.LinkSetNsFd(peer, nsFd)` | N/A — FL vif is created directly inside compartment |
| **IP assignment** | `netlink.AddrAdd()` inside container netns | `CreateUnicastIpAddressEntry()` scoped to compartment |
| **Route setup** | `netlink.RouteAdd()` inside container netns | `CreateIpForwardEntry2()` in compartment routing table |
| **DNS** | Not handled by Cilium (kubelet manages resolv.conf) | `SetInterfaceDnsSettings()` on virtual interface |
| **Host adapter** | `cilium_host`/`cilium_net` veth pair | Host network adapter (selected by `GetAdaptersAddresses`) |
| **Node-level init** | `Reinitialize()` → creates base devices, loads BPF | `CreateNetwork()` → configures adapter, SNAT, CNC node config |
| **Datapath programming** | BPF programs attached to TC hooks on veth | CNC API calls (`CncAddOrUpdateEndpoint`, etc.) |
| **ARP/neighbor** | Implicit (kernel ARP on veth) | `CreateIpNetEntry2()` for local; `CncAddOrUpdateNeighbor()` for remote |
| **State persistence** | Filesystem (`/var/run/cilium/`) | Windows registry (`RegSetValueExW`) |
| **Remote endpoint** | Node routes via `netlink.RouteReplace()` | `CncAddOrUpdateNeighbor()` for IP→MAC mapping |

---

## 3. Namespace and Network Creation: Linux vs. Windows

### Key Finding: No Equivalent in Linux

Cilium on Linux **does not have explicit CreateNetwork or CreateNamespace APIs**. This is a fundamental architectural difference:

| Aspect | Linux (Cilium) | Windows (WcnAgent) |
|--------|---------------|---------------------|
| **Network creation** | Implicit during daemon startup: `setupBaseDevice()` creates `cilium_host`/`cilium_net` veth pair; IPs allocated during `AllocateIPs()` | Explicit API: `CreateNetwork()` validates subnets, selects adapter, programs SNAT, configures CNC node |
| **Namespace creation** | Not managed by Cilium — created by container runtime (containerd/CRI-O) before CNI ADD | Explicit API: `CreateNamespace()` creates kernel network compartment via `CreateCompartment()` |
| **IP fabric** | Configured per-node at agent startup; per-pod IPs allocated from IPAM pool | Configured once via `CreateNetwork()` with subnet definitions |
| **Host adapter** | `cilium_host` veth pair created by agent | Physical adapter selected from system via `GetAdaptersAddresses()` |

### Design Implication

The shim layer must accommodate this asymmetry:
- **Network initialization** becomes a node-level operation that is called once during agent startup on both platforms, but does different things on each.
- **Namespace/compartment management** needs to be an explicit operation on Windows (creating compartments) but can be a thin wrapper or no-op on Linux (namespaces are pre-created).
- The shim API should model these as **node setup** and **isolation boundary** operations rather than mirroring either platform's terminology directly.

---

## 4. Proposed Architecture

### 4.1 Layered Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Cilium Agent (Platform-Agnostic)                   │
│                                                                      │
│  ┌─────────────────┐  ┌──────────────┐  ┌──────────────────────┐    │
│  │  K8s Watchers    │  │ IPAM         │  │ Identity / Policy    │    │
│  │  (Pods, Nodes,   │  │ (IP alloc,   │  │ (Labels, identities, │    │
│  │   Services)      │  │  pool mgmt)  │  │  policy resolution)  │    │
│  └────────┬─────────┘  └──────┬───────┘  └──────────┬───────────┘    │
│           │                   │                     │                │
│  ┌────────▼───────────────────▼─────────────────────▼───────────┐    │
│  │              Endpoint Manager (pkg/endpointmanager)           │    │
│  │  - Endpoint lifecycle (create, update, delete, restore)       │    │
│  │  - ID allocation                                              │    │
│  │  - K8s CiliumEndpoint CRD sync                                │    │
│  └────────────────────────────┬──────────────────────────────────┘    │
│                               │                                      │
│  ┌────────────────────────────▼──────────────────────────────────┐    │
│  │           Datapath Orchestrator (pkg/datapath/orchestrator)    │    │
│  │  - Coordinates node init and endpoint regeneration            │    │
│  │  - Manages compilation lock                                   │    │
│  │  - Caches BPF templates (Linux) / no-op (Windows)             │    │
│  └────────────────────────────┬──────────────────────────────────┘    │
│                               │                                      │
├───────────────────────────────┼──────────────────────────────────────┤
│                    Platform Shim Layer                                │
│  ┌────────────────────────────▼──────────────────────────────────┐    │
│  │              PlatformDatapath Interface                        │    │
│  │                                                               │    │
│  │  ┌──────────────┐ ┌──────────────┐ ┌──────────────────────┐   │    │
│  │  │ PlatformNode │ │ Platform     │ │ PlatformEndpoint     │   │    │
│  │  │              │ │ Namespace    │ │                      │   │    │
│  │  │ •Initialize  │ │              │ │ •CreateEndpoint      │   │    │
│  │  │  Node        │ │ •CreatePod   │ │ •ConfigureEndpoint   │   │    │
│  │  │ •Configure   │ │  Sandbox     │ │  Networking          │   │    │
│  │  │  HostNetwork │ │ •DeletePod   │ │ •AttachEndpoint      │   │    │
│  │  │ •Cleanup     │ │  Sandbox     │ │ •DetachEndpoint      │   │    │
│  │  │  Node        │ │              │ │ •DeleteEndpoint      │   │    │
│  │  └──────────────┘ └──────────────┘ └──────────────────────┘   │    │
│  └───────────────────────────────────────────────────────────────┘    │
│                               │                                      │
├───────────────────────────────┼──────────────────────────────────────┤
│              Platform-Specific Implementations                       │
│                               │                                      │
│         ┌─────────────────────┼─────────────────────┐                │
│         │                     │                     │                │
│         ▼                     │                     ▼                │
│  ┌──────────────┐             │          ┌──────────────────┐        │
│  │ Linux Impl   │             │          │ Windows Impl     │        │
│  │              │             │          │                  │        │
│  │ •netlink     │             │          │ •wcnagent.dll    │        │
│  │ •veth/netkit │             │          │  (loaded as lib) │        │
│  │ •BPF loader  │             │          │ •HNS/HCS APIs   │        │
│  │ •TC attach   │             │          │ •CNC APIs        │        │
│  │ •sysctl      │             │          │ •FL virtual ifs  │        │
│  │ •ip route    │             │          │ •IP Helper APIs  │        │
│  └──────────────┘             │          └──────────────────┘        │
│                               │                                      │
└───────────────────────────────┴──────────────────────────────────────┘
```

### 4.2 Platform Shim Interface Design

The shim layer introduces **four interface groups** that abstract all platform-specific networking operations. These are designed by analyzing the operations performed on both Linux and Windows, finding the common semantics:

1. **`PlatformNode`** — Node-level initialization and teardown (called once at agent startup)
2. **`PlatformNamespace`** — Pod isolation boundary management (namespace/compartment lifecycle)
3. **`PlatformEndpoint`** — Pod network interface lifecycle (create, configure, attach, delete)
4. **`PlatformNetwork`** — Network/subnet management (IP fabric setup)

The design follows these principles:
- Each interface method maps to a clear operation on both Linux and Windows.
- Methods accept platform-agnostic data structures and return platform-agnostic results.
- Platform-specific details (veth names, compartment GUIDs, FL interface LUIDs) are hidden inside the implementations and stored in opaque `PlatformState` objects.

### 4.3 CNI Plugin Refactoring

The CNI plugin is the entry point for pod networking. Today it is entirely Linux-specific (`cmd_linux.go`). The refactoring splits it into:

```
plugins/cilium-cni/cmd/
├── cmd.go                  ← Platform-agnostic: config loading, agent client, IPAM
├── cmd_linux.go            ← Linux: veth creation, netns configuration, sysctl
├── cmd_windows.go          ← Windows: delegates to agent (which calls wcnagent)
├── endpoint.go             ← Platform-agnostic: EndpointChangeRequest building
├── endpoint_linux.go       ← Linux: safenetlink endpoint listing
├── endpoint_windows.go     ← Windows: stub or HCN endpoint listing
├── interface_linux.go      ← Linux: ENI/Azure routing setup
└── interface_windows.go    ← Windows: no-op (routing handled by wcnagent)
```

**Key design decision:** On Windows, the CNI plugin does significantly less work than on Linux. The heavy lifting (compartment creation, interface creation, IP assignment, route setup) is performed by the Cilium agent calling into wcnagent, not by the CNI plugin directly. The CNI plugin on Windows:
1. Allocates an IP from the agent's IPAM.
2. Sends an `EndpointChangeRequest` to the agent.
3. The agent calls wcnagent to set up the full networking stack.
4. Returns the CNI result.

This is because Windows networking operations (compartment creation, FL virtual interfaces) require elevated system APIs that are more naturally called from a long-lived agent process than from a short-lived CNI binary.

### 4.4 Daemon Endpoint Lifecycle Refactoring

The daemon's endpoint creation path is mostly platform-agnostic today, with Linux-specific code concentrated in the datapath layer. The refactoring:

1. **Keeps the endpoint manager, identity resolution, and K8s sync unchanged** — these are already platform-agnostic.
2. **Routes endpoint regeneration through the platform shim** — instead of always compiling BPF programs, the `Orchestrator` calls the platform-appropriate datapath setup.
3. **Adds a "configure networking" step** that the platform shim handles:
   - Linux: BPF program compilation and TC attachment (existing flow).
   - Windows: wcnagent calls to create compartment, virtual interface, assign IPs, program CNC.

```
Refactored Endpoint Creation (both platforms):
┌──────────────────────────────────────────────────────────────────────┐
│  1. CNI plugin sends EndpointChangeRequest to agent                  │
│  2. EndpointCreator.NewEndpointFromChangeModel() — platform-agnostic │
│  3. EndpointManager.AddEndpoint() — platform-agnostic                │
│  4. Fetch K8s metadata, resolve identity — platform-agnostic         │
│  5. Trigger endpoint regeneration:                                   │
│     ┌─────────────────────────────────────────────────────────────┐  │
│     │ Platform Shim: ConfigureEndpointNetworking()                │  │
│     │                                                             │  │
│     │  Linux:                    │  Windows:                      │  │
│     │  - Write BPF headers       │  - Call wcnagent               │  │
│     │  - Compile BPF programs    │    CreateNamespace (if needed) │  │
│     │  - Load into kernel        │    CreateEndpoint              │  │
│     │  - Attach to TC hooks      │    ModifyNamespace (attach)    │  │
│     │  - Create endpoint routes  │  - CNC programs datapath      │  │
│     └─────────────────────────────────────────────────────────────┘  │
│  6. Update endpoint map (lxcmap on Linux / in-memory on Windows)     │
│  7. Sync CiliumEndpoint CRD — platform-agnostic                     │
│  8. Return to CNI plugin                                             │
└──────────────────────────────────────────────────────────────────────┘
```

### 4.5 Node Initialization Refactoring

Node-level networking setup is fundamentally different on each platform but serves the same purpose: prepare the node to host pod networking.

| Phase | Linux | Windows |
|-------|-------|---------|
| **1. Discover host adapter** | `GetAdaptersAddresses` → select `cilium_host` pair | `GetAdaptersAddresses` → select physical adapter (wcnagent) |
| **2. Create node-level interfaces** | `setupVethPair(cilium_host, cilium_net)` | `CreateNetwork()` → configure adapter + IP pool |
| **3. Assign node IPs** | `addHostDeviceAddr()` on `cilium_host` | IPs from adapter; management IPs stored in network object |
| **4. Program datapath** | Load BPF programs on cilium_host/cilium_net | `CncAddOrUpdateNodeConfiguration()` |
| **5. Configure routing** | Sysctl tuning, iptables rules | SNAT exclusions, L4 proxy rules |

The `PlatformNode` interface abstracts this:

```go
type PlatformNode interface {
    // InitializeNode sets up node-level networking.
    // Linux: creates cilium_host/cilium_net, loads base BPF programs.
    // Windows: calls wcnagent CreateNetwork, configures CNC node.
    InitializeNode(ctx context.Context, cfg NodeConfig) (*NodeState, error)

    // CleanupNode tears down node-level networking.
    CleanupNode(ctx context.Context) error
}
```

---

## 5. Shim API Definitions

### Package Structure

```
pkg/datapath/
├── types/
│   ├── platform.go          ← NEW: PlatformDatapath aggregate interface
│   ├── platform_node.go     ← NEW: PlatformNode interface
│   ├── platform_ns.go       ← NEW: PlatformNamespace interface
│   ├── platform_endpoint.go ← NEW: PlatformEndpoint interface
│   ├── platform_network.go  ← NEW: PlatformNetwork interface
│   ├── platform_types.go    ← NEW: Shared data types
│   ├── loader.go            ← EXISTING (kept for BPF-specific operations)
│   ├── connector.go         ← EXISTING (kept, used by Linux impl)
│   └── ...
├── linux/
│   ├── platform_linux.go    ← NEW: Linux PlatformDatapath implementation
│   ├── node.go              ← EXISTING (refactored to implement PlatformNode)
│   ├── connector/           ← EXISTING (used by Linux platform impl)
│   └── ...
└── windows/
    ├── platform_windows.go  ← NEW: Windows PlatformDatapath implementation
    ├── wcnagent.go          ← NEW: wcnagent DLL integration
    └── types.go             ← NEW: Windows-specific types
```

### 5.1 PlatformNetwork Interface

```go
// pkg/datapath/types/platform_network.go

package types

import (
    "context"
    "net/netip"
)

// NetworkConfig contains the configuration for creating a node-level network.
// On Linux, this maps to the cilium_host/cilium_net setup.
// On Windows, this maps to wcnagent's CreateNetwork.
type NetworkConfig struct {
    // NetworkID is a unique identifier for this network.
    // On Windows, this is the HCN GUID. On Linux, this is typically a single
    // network identified by the node's PodCIDR.
    NetworkID string

    // Subnets defines the IP address ranges for pods on this network.
    Subnets []SubnetConfig

    // NetworkType identifies the type of network.
    // Linux: "veth" or "netkit"
    // Windows: "L2Bridge"
    NetworkType string

    // HostAdapterName optionally specifies the host adapter to bind to.
    // If empty, the platform selects the best adapter.
    HostAdapterName string

    // MTU is the desired MTU for pod interfaces.
    MTU int

    // DNSConfig contains default DNS settings for pods on this network.
    DNSConfig *DNSConfig
}

// SubnetConfig defines a subnet within a network.
type SubnetConfig struct {
    // Prefix is the subnet CIDR (e.g., "10.224.0.0/16").
    Prefix netip.Prefix

    // Gateway is the default gateway for pods in this subnet.
    Gateway netip.Addr
}

// DNSConfig contains DNS configuration for an endpoint or network.
type DNSConfig struct {
    Servers    []string // DNS server IPs
    SearchList []string // DNS search domains
    Domain     string   // Primary DNS domain
}

// NetworkState holds platform-specific state resulting from network creation.
// This is opaque to the common layer — only the platform implementation
// interprets it.
type NetworkState struct {
    // NetworkID as assigned by the platform.
    NetworkID string

    // HostAdapterMAC is the MAC address of the host adapter used by this network.
    HostAdapterMAC [6]byte

    // HostAdapterIndex is the OS interface index of the host adapter.
    HostAdapterIndex int

    // HostIPv4 is the host-side IPv4 address for this network.
    HostIPv4 netip.Addr

    // HostIPv6 is the host-side IPv6 address for this network (if available).
    HostIPv6 netip.Addr

    // PlatformData holds platform-specific state (e.g., adapter LUID on Windows,
    // cilium_host link index on Linux). Opaque to common code.
    PlatformData any
}

// PlatformNetwork manages node-level network resources.
type PlatformNetwork interface {
    // CreateNetwork initializes the node's pod networking infrastructure.
    //
    // Linux: Creates cilium_host/cilium_net veth pair, assigns router IPs,
    //        configures sysctl, loads base BPF programs.
    // Windows: Calls wcnagent CreateNetwork — validates subnets, selects
    //          host adapter, programs CNC node configuration and SNAT exclusions.
    //
    // This is called once during agent startup and idempotent on restart.
    CreateNetwork(ctx context.Context, cfg NetworkConfig) (*NetworkState, error)

    // DeleteNetwork tears down the node's pod networking infrastructure.
    //
    // Linux: Deletes cilium_host/cilium_net.
    // Windows: Calls wcnagent DeleteNetwork.
    DeleteNetwork(ctx context.Context, networkID string) error

    // GetNetworkState returns the current state of the network.
    // Returns nil if no network exists.
    GetNetworkState(ctx context.Context, networkID string) (*NetworkState, error)
}
```

### 5.2 PlatformEndpoint Interface

```go
// pkg/datapath/types/platform_endpoint.go

package types

import (
    "context"
    "net/netip"
)

// EndpointNetworkConfig contains all information needed to create and configure
// a pod's network interface.
type EndpointNetworkConfig struct {
    // EndpointID is the Cilium-assigned endpoint ID (1-65535).
    EndpointID uint16

    // ContainerID is the container runtime's container identifier.
    ContainerID string

    // NetnsPath is the path to the container's network namespace.
    // Linux: e.g., "/var/run/netns/cni-xxxxx"
    // Windows: Ignored (compartment is created by the platform).
    NetnsPath string

    // IfName is the desired interface name inside the container.
    // Linux: typically "eth0"
    // Windows: platform-managed (FL virtual interface)
    IfName string

    // NetworkID identifies the parent network (from CreateNetwork).
    NetworkID string

    // SandboxID identifies the pod sandbox (from CreatePodSandbox).
    // Links the endpoint to its isolation boundary.
    SandboxID string

    // IPv4Address is the allocated IPv4 address for this endpoint.
    IPv4Address netip.Prefix

    // IPv6Address is the allocated IPv6 address for this endpoint (optional).
    IPv6Address netip.Prefix

    // IPv4Gateway is the default gateway for IPv4 traffic.
    IPv4Gateway netip.Addr

    // IPv6Gateway is the default gateway for IPv6 traffic.
    IPv6Gateway netip.Addr

    // Routes are additional routes to install for this endpoint.
    Routes []RouteConfig

    // DNS is the DNS configuration for this endpoint.
    DNS *DNSConfig

    // MTU is the desired interface MTU.
    MTU int

    // IsRemote indicates this endpoint represents a pod on another node.
    // Remote endpoints don't get a local interface; instead, the platform
    // programs forwarding entries (Linux: node routes; Windows: CNC neighbors).
    IsRemote bool

    // RemoteNodeIP is the IP of the remote node (only for remote endpoints).
    RemoteNodeIP netip.Addr

    // PodName is the Kubernetes pod name (for logging/telemetry).
    PodName string

    // PodNamespace is the Kubernetes pod namespace.
    PodNamespace string
}

// RouteConfig defines a route to be installed for an endpoint.
type RouteConfig struct {
    // Destination is the route destination CIDR.
    Destination netip.Prefix

    // Gateway is the next-hop address (empty for on-link routes).
    Gateway netip.Addr

    // MTU overrides the interface MTU for this route (0 = use interface MTU).
    MTU int
}

// EndpointState holds the result of endpoint creation.
type EndpointState struct {
    // EndpointID as used by the platform.
    EndpointID uint16

    // HostInterfaceName is the name of the host-side interface.
    // Linux: "lxc<hash>"
    // Windows: empty (no host-side peer)
    HostInterfaceName string

    // HostInterfaceIndex is the OS interface index of the host-side interface.
    HostInterfaceIndex int

    // ContainerInterfaceName is the name of the container-side interface.
    // Linux: "eth0"
    // Windows: FL virtual interface name
    ContainerInterfaceName string

    // ContainerInterfaceIndex is the OS interface index of the container interface.
    ContainerInterfaceIndex int

    // HostMAC is the MAC address of the host-side interface.
    HostMAC [6]byte

    // ContainerMAC is the MAC address of the container-side interface.
    ContainerMAC [6]byte

    // PlatformData holds platform-specific endpoint state.
    PlatformData any
}

// PlatformEndpoint manages pod network interface lifecycle.
type PlatformEndpoint interface {
    // CreateEndpoint creates the pod's network interface and associates it
    // with the network and sandbox.
    //
    // Linux: Creates veth/netkit pair, moves peer to container netns,
    //        configures IP/routes inside container, disables rp_filter.
    // Windows: Calls wcnagent CreateEndpoint (creates endpoint object with
    //          IP, MAC, network association). Does NOT yet create the
    //          virtual interface — that happens in AttachEndpoint.
    //
    // For remote endpoints (IsRemote=true):
    //   Linux: Installs node routes (netlink.RouteReplace).
    //   Windows: Programs CNC neighbors (CncAddOrUpdateNeighbor).
    CreateEndpoint(ctx context.Context, cfg EndpointNetworkConfig) (*EndpointState, error)

    // AttachEndpoint wires the endpoint's interface into the pod's sandbox
    // and programs the datapath.
    //
    // Linux: Attaches BPF programs to TC hooks on host-side veth,
    //        creates per-endpoint routes if needed, updates lxcmap.
    // Windows: Calls wcnagent ModifyNamespace (attach_endpoint_to_namespace)
    //          — creates FL virtual interface, assigns IPs, creates routes,
    //          configures DNS, programs CNC endpoint and ACL policies.
    //
    // This is called after CreateEndpoint and after the daemon has resolved
    // the endpoint's identity and policy.
    AttachEndpoint(ctx context.Context, endpointID uint16, sandboxID string) error

    // DetachEndpoint removes the endpoint from its sandbox and deprograms
    // the datapath.
    //
    // Linux: Detaches BPF programs from TC hooks, removes endpoint routes.
    // Windows: Calls wcnagent ModifyNamespace (detach) — deletes FL virtual
    //          interface, CNC endpoint, routes, DNS.
    DetachEndpoint(ctx context.Context, endpointID uint16, sandboxID string) error

    // DeleteEndpoint destroys the endpoint's network interface and cleans up
    // all associated resources.
    //
    // Linux: Deletes veth pair (host side deletion removes both).
    // Windows: Calls wcnagent DeleteEndpoint — removes CNC neighbors (if remote),
    //          LB backends, registry state.
    DeleteEndpoint(ctx context.Context, endpointID uint16) error

    // GetEndpointState returns the current platform state for an endpoint.
    // Returns nil if endpoint doesn't exist.
    GetEndpointState(ctx context.Context, endpointID uint16) (*EndpointState, error)

    // ValidateEndpoint checks if the endpoint's network plumbing is healthy.
    //
    // Linux: Verifies veth pair exists, links are up, BPF attached.
    // Windows: Verifies HCN endpoint exists, FL virtual interface active.
    ValidateEndpoint(ctx context.Context, endpointID uint16) error

    // ListEndpoints returns all endpoints known to the platform.
    // Used during agent restart for endpoint restoration.
    ListEndpoints(ctx context.Context) ([]EndpointState, error)
}
```

### 5.3 PlatformNode Interface

```go
// pkg/datapath/types/platform_node.go

package types

import (
    "context"
    "net/netip"
)

// NodeConfig contains the node-level configuration for the platform.
type NodeConfig struct {
    // NodeName is the Kubernetes node name.
    NodeName string

    // NodeIPv4 is the node's primary IPv4 address.
    NodeIPv4 netip.Addr

    // NodeIPv6 is the node's primary IPv6 address (optional).
    NodeIPv6 netip.Addr

    // PodCIDRv4 is the IPv4 CIDR allocated to this node for pods.
    PodCIDRv4 netip.Prefix

    // PodCIDRv6 is the IPv6 CIDR allocated to this node for pods (optional).
    PodCIDRv6 netip.Prefix

    // MTU is the desired MTU for pod interfaces.
    MTU int

    // EnableIPv4 indicates whether IPv4 is enabled.
    EnableIPv4 bool

    // EnableIPv6 indicates whether IPv6 is enabled.
    EnableIPv6 bool
}

// NodeState holds the result of node initialization.
type NodeState struct {
    // HostInterfaceName is the name of the node's host-side interface.
    // Linux: "cilium_host"
    // Windows: physical adapter name
    HostInterfaceName string

    // HostInterfaceIndex is the OS interface index of the host interface.
    HostInterfaceIndex int

    // HostMAC is the MAC address of the host interface.
    HostMAC [6]byte

    // InternalIPv4 is the internal IPv4 address used for Cilium operations
    // (router IP on Linux, management IP on Windows).
    InternalIPv4 netip.Addr

    // InternalIPv6 is the internal IPv6 address.
    InternalIPv6 netip.Addr
}

// PlatformNode manages node-level networking setup.
type PlatformNode interface {
    // InitializeNode performs one-time node-level networking setup.
    //
    // Linux: Creates cilium_host/cilium_net veth pair, configures sysctl,
    //        loads base BPF programs (socket LB, XDP, host programs),
    //        sets up tunnel devices.
    // Windows: Calls wcnagent Initialize and CreateNetwork (which selects
    //          the host adapter, programs CNC node config, creates SNAT
    //          exclusions, and creates L4 proxy rules).
    InitializeNode(ctx context.Context, cfg NodeConfig) (*NodeState, error)

    // ConfigureNodeRouting sets up node-level routing after initialization.
    //
    // Linux: Adds IPs to cilium_host, creates service loopback IPs,
    //        configures iptables masquerade rules.
    // Windows: Configured during CreateNetwork — management IPs from adapter.
    ConfigureNodeRouting(ctx context.Context, state *NodeState) error

    // HandleRemoteNode programs forwarding entries for a remote node.
    //
    // Linux: Installs routes via netlink for the remote node's PodCIDR.
    // Windows: Programs CNC neighbor entries for remote node endpoints.
    HandleRemoteNode(ctx context.Context, node RemoteNodeInfo) error

    // RemoveRemoteNode removes forwarding entries for a remote node.
    RemoveRemoteNode(ctx context.Context, node RemoteNodeInfo) error

    // CleanupNode tears down all node-level networking.
    CleanupNode(ctx context.Context) error
}

// RemoteNodeInfo contains information about a remote node in the cluster.
type RemoteNodeInfo struct {
    NodeName string
    NodeIP   netip.Addr
    PodCIDRs []netip.Prefix
}
```

### 5.4 PlatformNamespace Interface

```go
// pkg/datapath/types/platform_ns.go

package types

import "context"

// SandboxConfig contains configuration for creating a pod sandbox
// (isolation boundary).
type SandboxConfig struct {
    // SandboxID is a unique identifier for this sandbox.
    // Typically derived from the container ID or pod UID.
    SandboxID string

    // NetnsPath is the network namespace path (Linux only).
    // Windows ignores this — compartments are created by the platform.
    NetnsPath string

    // ExcludedUDPPorts lists UDP ports to reserve/exclude in this sandbox.
    // Windows: Reserved via CreatePersistentUdpPortReservation.
    // Linux: Not applicable (pods don't have port reservations).
    ExcludedUDPPorts []uint16
}

// SandboxState holds the result of sandbox creation.
type SandboxState struct {
    // SandboxID as assigned.
    SandboxID string

    // CompartmentID is the Windows network compartment ID.
    // Linux: 0 (not used).
    CompartmentID uint32

    // PlatformData holds platform-specific sandbox state.
    PlatformData any
}

// PlatformNamespace manages pod sandbox (isolation boundary) lifecycle.
type PlatformNamespace interface {
    // CreatePodSandbox creates an isolation boundary for a pod.
    //
    // Linux: No-op or thin wrapper — the container runtime creates the
    //        network namespace before calling CNI. This method may just
    //        record the netns path.
    // Windows: Calls wcnagent CreateNamespace — creates a Windows kernel
    //          network compartment (isolated routing table, interface list).
    //          Also reserves excluded UDP ports in the compartment.
    CreatePodSandbox(ctx context.Context, cfg SandboxConfig) (*SandboxState, error)

    // DeletePodSandbox destroys the pod's isolation boundary.
    //
    // Linux: No-op — the container runtime cleans up the netns.
    // Windows: Calls wcnagent DeleteNamespace — deletes the compartment.
    DeletePodSandbox(ctx context.Context, sandboxID string) error

    // GetSandboxState returns the current state of a sandbox.
    GetSandboxState(ctx context.Context, sandboxID string) (*SandboxState, error)
}
```

### 5.5 Aggregate Interface

```go
// pkg/datapath/types/platform.go

package types

// PlatformDatapath is the aggregate interface for all platform-specific
// networking operations. Each platform provides a single implementation
// that satisfies this interface.
//
// The Cilium agent creates a PlatformDatapath during initialization via
// Hive dependency injection, selecting the implementation based on GOOS.
type PlatformDatapath interface {
    PlatformNode
    PlatformNetwork
    PlatformNamespace
    PlatformEndpoint

    // Name returns the platform name ("linux" or "windows").
    Name() string
}
```

---

## 6. Linux Platform Implementation

The Linux implementation wraps the existing Cilium code behind the new shim interfaces. **No behavioral changes are made** — only the call paths are re-routed through the interfaces.

### Package: `pkg/datapath/linux/platform_linux.go`

```go
package linux

// linuxPlatform implements PlatformDatapath for Linux.
type linuxPlatform struct {
    logger     *slog.Logger
    sysctl     sysctl.Sysctl
    connector  datapath.ConnectorConfig  // Existing connector (veth/netkit)
    loader     datapath.Loader           // Existing BPF loader
    nodeHandler *linuxNodeHandler        // Existing node handler
    routeMgr   *route.Manager
    mtu        int
}

func (p *linuxPlatform) Name() string { return "linux" }
```

#### PlatformNode — Linux

| Method | Implementation |
|--------|---------------|
| `InitializeNode` | Calls existing `setupBaseDevice()` (creates cilium_host/cilium_net), `enableForwarding()`, `loader.Reinitialize()` (loads base BPF programs). Returns NodeState with cilium_host info. |
| `ConfigureNodeRouting` | Calls existing `addHostDeviceAddr()`, sysctl tuning, iptables setup. Wraps code from `infra_ip_allocation.go`. |
| `HandleRemoteNode` | Calls existing `linuxNodeHandler.NodeAdd()` / `NodeUpdate()` → `netlink.RouteReplace()`. |
| `RemoveRemoteNode` | Calls existing `linuxNodeHandler.NodeDelete()` → `netlink.RouteDel()`. |
| `CleanupNode` | Deletes cilium_host/cilium_net veth pair. |

#### PlatformNamespace — Linux

| Method | Implementation |
|--------|---------------|
| `CreatePodSandbox` | **No-op.** Records the netns path. The container runtime creates the namespace. Returns SandboxState with CompartmentID=0. |
| `DeletePodSandbox` | **No-op.** The container runtime cleans up the namespace. |
| `GetSandboxState` | Returns the recorded netns path if it exists. |

#### PlatformNetwork — Linux

| Method | Implementation |
|--------|---------------|
| `CreateNetwork` | **Thin wrapper.** On Linux, the "network" is implicit — it's the node's PodCIDR. Records the subnet config and returns NetworkState with cilium_host info. Most of the actual work is in `InitializeNode`. |
| `DeleteNetwork` | **No-op** (network cleanup is part of `CleanupNode`). |
| `GetNetworkState` | Returns the recorded network state. |

#### PlatformEndpoint — Linux

| Method | Implementation |
|--------|---------------|
| `CreateEndpoint` | Wraps existing `connector.NewLinkPair()` (creates veth/netkit pair), `configureIface()` (IP/routes inside container netns). This is the code currently in the CNI plugin's `cmd_linux.go`. |
| `AttachEndpoint` | Wraps existing `loader.ReloadDatapath()` (compiles and loads BPF programs), `attachSKBProgram()` (attaches to TC hooks), `upsertEndpointRoute()`. |
| `DetachEndpoint` | Wraps existing `loader.Unload()` (detaches BPF programs), removes endpoint routes. |
| `DeleteEndpoint` | Wraps existing veth deletion via `netlink.LinkDel()`. |
| `ValidateEndpoint` | Wraps existing `checkLink()` / `ValidateConnectorPlumbing()` from `endpoint_restore.go`. |
| `ListEndpoints` | Wraps existing `listVethIfaces()` / `safenetlink.LinkList()`. |

### Refactoring Strategy for Linux

The refactoring is done in stages to minimize risk:

1. **Stage 1: Define interfaces** — Add the new interface files under `pkg/datapath/types/`. No functional changes.
2. **Stage 2: Create Linux implementation** — Move existing code into `linuxPlatform` methods. Each method wraps existing functions without changing behavior. 
3. **Stage 3: Wire into Hive** — Register `linuxPlatform` as the `PlatformDatapath` provider on Linux via build tags. Update callers to use the interface.
4. **Stage 4: Move CNI code** — Move veth creation and container configuration from the CNI plugin into the `PlatformEndpoint.CreateEndpoint()` implementation. The CNI plugin becomes a thin client that calls the agent, which calls the platform shim.

**Important:** In Stage 4, the CNI plugin on Linux can still do the veth creation directly (for performance), or it can delegate to the agent. This is a design choice:
- **Option A (Direct):** CNI creates veth, configures container, then tells agent. Agent compiles BPF. (Current model — fast.)
- **Option B (Delegated):** CNI tells agent, agent calls PlatformEndpoint.CreateEndpoint() + AttachEndpoint(). (Simpler, consistent with Windows, but adds latency.)

**Recommendation:** Keep Option A for Linux (CNI creates veth directly) and use Option B for Windows (CNI delegates to agent). The `CreateEndpoint` shim is still useful on Linux for endpoint restoration and validation, but the hot path (CNI ADD) can bypass it.

---

## 7. Windows Platform Implementation

### 7.1 Integration with WcnAgent

WcnAgent is a mature Windows networking library that already implements the heavy lifting for Windows pod networking. Rather than reimplementing HNS/HCS/FL-virtual-interface management in Go, the Windows platform implementation **loads wcnagent.dll and calls its APIs**.

```
Cilium Agent (Go)
    │
    ▼
pkg/datapath/windows/platform_windows.go
    │
    ▼
pkg/datapath/windows/wcnagent.go  ← Go wrapper around wcnagent DLL
    │ (LoadLibrary + GetProcAddress)
    ▼
wcnagent.dll (C++)
    │
    ├── CreateNamespace → CreateCompartment (kernel)
    ├── CreateNetwork → GetAdaptersAddresses, CncAddOrUpdateNodeConfiguration
    ├── CreateEndpoint → CncAddOrUpdateNeighbor (remote)
    └── ModifyNamespace → CreateFlVirtualInterface, CreateUnicastIpAddressEntry,
                          CncAddOrUpdateEndpoint, CncAddOrUpdateEndpointPolicies
```

#### WcnAgent DLL Loading

```go
// pkg/datapath/windows/wcnagent.go

package windows

import (
    "syscall"
    "unsafe"
)

// wcnAgentLib wraps the wcnagent.dll function table.
type wcnAgentLib struct {
    dll       *syscall.DLL
    apiTable  *WcnAgentAPITable

    // Function pointers from the API table
    initialize       uintptr
    uninitialize     uintptr
    createNetwork    uintptr
    deleteNetwork    uintptr
    createNamespace  uintptr
    deleteNamespace  uintptr
    modifyNamespace  uintptr
    createEndpoint   uintptr
    deleteEndpoint   uintptr
    // ... other functions as needed
}

func loadWcnAgent(dllPath string) (*wcnAgentLib, error) {
    dll, err := syscall.LoadDLL(dllPath)
    if err != nil {
        return nil, fmt.Errorf("failed to load wcnagent.dll: %w", err)
    }

    // Get WcnAgentFunctionTableOpen export
    proc, err := dll.FindProc("WcnAgentFunctionTableOpen")
    if err != nil {
        return nil, fmt.Errorf("WcnAgentFunctionTableOpen not found: %w", err)
    }

    var apiTable *WcnAgentAPITable
    ret, _, err := proc.Call(
        uintptr(WCN_AGENT_API_VERSION),
        uintptr(unsafe.Pointer(&apiTable)),
    )
    if ret != 0 {
        return nil, fmt.Errorf("WcnAgentFunctionTableOpen failed: HRESULT 0x%x", ret)
    }

    return &wcnAgentLib{
        dll:      dll,
        apiTable: apiTable,
        // Extract function pointers from table...
    }, nil
}
```

### 7.2 HNS/HCS Direct Integration

An alternative to loading wcnagent.dll is to call HNS/HCS APIs directly from Go using the `hcsshim` package. However, this would **duplicate significant logic** that wcnagent already implements:
- FL virtual interface creation and management
- CNC datapath programming (CncAddOrUpdateEndpoint, etc.)
- Host adapter selection and configuration
- Registry-based state persistence
- Port reservation and SNAT exclusion

### 7.3 Recommended Approach

**Use wcnagent as the Windows networking backend.** This provides:
1. **Proven, tested code** for all Windows networking operations.
2. **CNC datapath integration** already implemented.
3. **State persistence** (registry) for crash recovery.
4. **Port reservation**, SNAT, and L4 proxy support.

The Go wrapper adds minimal overhead and provides a clean Go API for the Cilium agent.

#### PlatformNode — Windows

| Method | Implementation |
|--------|---------------|
| `InitializeNode` | `wcnagent.Initialize()` → `wcnagent.CreateNetwork(networkConfig)`. Converts `NodeConfig` to HCN JSON (`HostComputeNetwork` schema). Returns NodeState with adapter info. |
| `ConfigureNodeRouting` | Handled during `CreateNetwork` — management IPs are from the selected adapter. May additionally configure host routes if needed. |
| `HandleRemoteNode` | For each remote pod CIDR: creates a remote endpoint via `wcnagent.CreateEndpoint()` with `RemoteEndpoint` flag → programs CNC neighbors. |
| `RemoveRemoteNode` | Deletes remote endpoints for the node. |
| `CleanupNode` | `wcnagent.DeleteNetwork()` → `wcnagent.Uninitialize()`. |

#### PlatformNamespace — Windows

| Method | Implementation |
|--------|---------------|
| `CreatePodSandbox` | `wcnagent.CreateNamespace(sandboxID, settings)`. Creates a Windows kernel network compartment with isolated routing table. Reserves excluded UDP ports. |
| `DeletePodSandbox` | `wcnagent.DeleteNamespace(sandboxID)`. Deletes the compartment and all associated state. |
| `GetSandboxState` | `wcnagent.QueryNamespaceProperties(sandboxID)`. Returns compartment ID and attached endpoints. |

#### PlatformNetwork — Windows

| Method | Implementation |
|--------|---------------|
| `CreateNetwork` | `wcnagent.CreateNetwork(networkID, settings)`. Creates the network with subnet definitions, selects host adapter, programs SNAT exclusions and CNC node config. |
| `DeleteNetwork` | `wcnagent.DeleteNetwork(networkID)`. Removes SNAT exclusions, resets node config, deletes registry state. |
| `GetNetworkState` | `wcnagent.QueryNetworkProperties(networkID)`. Returns adapter info, subnets, management IPs. |

#### PlatformEndpoint — Windows

| Method | Implementation |
|--------|---------------|
| `CreateEndpoint` | `wcnagent.CreateEndpoint(endpointID, settings)`. Creates endpoint object with IP/MAC/network association. For remote endpoints, immediately programs CNC neighbors. |
| `AttachEndpoint` | `wcnagent.ModifyNamespace(sandboxID, {Add, endpointID})`. This is the **critical step** that: (1) creates FL virtual interface in compartment, (2) assigns IPs, (3) configures DNS, (4) creates routes, (5) programs CNC endpoint, (6) applies ACL policies. |
| `DetachEndpoint` | `wcnagent.ModifyNamespace(sandboxID, {Remove, endpointID})`. Reverses the attachment: deletes FL virtual interface, CNC endpoint, routes, DNS. |
| `DeleteEndpoint` | `wcnagent.DeleteEndpoint(endpointID)`. Removes CNC neighbors (remote), LB backends, registry state. |
| `ValidateEndpoint` | `wcnagent.QueryEndpointProperties(endpointID)`. Verifies endpoint exists and FL virtual interface is active. |
| `ListEndpoints` | `wcnagent.EnumerateEndpoints("")`. Returns all known endpoints. |

---

## 8. Data Flow Diagrams

### 8.1 Pod Creation — Linux (After Refactoring)

```
Container Runtime (containerd)
    │
    │ CNI ADD (stdin: config, env: netns, ifname, container_id)
    ▼
┌─────────────────────────────────────────────────────────────┐
│  CNI Plugin (plugins/cilium-cni/)                           │
│                                                             │
│  1. Parse config, connect to agent                          │
│  2. Allocate IP: POST /ipam → agent                         │
│  3. Create veth pair (connector.NewLinkPair)          ◄─── Linux-specific
│  4. Configure container netns (configureIface)        ◄─── Linux-specific
│  5. Build EndpointChangeRequest                             │
│  6. PUT /endpoint/{id} → agent                              │
│  7. Return CNI result                                       │
└────────────────────┬────────────────────────────────────────┘
                     │ PUT /endpoint/{id}
                     ▼
┌─────────────────────────────────────────────────────────────┐
│  Cilium Agent (Daemon)                                      │
│                                                             │
│  1. EndpointCreator.NewEndpointFromChangeModel()            │ Common
│  2. EndpointManager.AddEndpoint()                           │ Common
│  3. Fetch K8s metadata, resolve identity                    │ Common
│  4. Trigger regeneration:                                   │
│     └─ PlatformEndpoint.AttachEndpoint()               ◄─── Via shim
│        └─ Linux impl:                                       │
│           - loader.ReloadDatapath() (compile + load BPF)    │
│           - attachSKBProgram() (TC hooks)                   │
│           - upsertEndpointRoute() (if needed)               │
│  5. Update lxcmap                                           │ Linux-specific
│  6. Sync CiliumEndpoint CRD                                 │ Common
└─────────────────────────────────────────────────────────────┘
```

### 8.2 Pod Creation — Windows (After Refactoring)

```
Container Runtime (containerd on Windows)
    │
    │ CNI ADD (stdin: config, env: container_id)
    ▼
┌─────────────────────────────────────────────────────────────┐
│  CNI Plugin (plugins/cilium-cni/)                           │
│                                                             │
│  1. Parse config, connect to agent                          │
│  2. Allocate IP: POST /ipam → agent                         │
│  3. Build EndpointChangeRequest                             │
│  4. PUT /endpoint/{id} → agent                              │
│     (No local network setup — agent handles everything)     │
│  5. Return CNI result                                       │
└────────────────────┬────────────────────────────────────────┘
                     │ PUT /endpoint/{id}
                     ▼
┌─────────────────────────────────────────────────────────────┐
│  Cilium Agent (Daemon)                                      │
│                                                             │
│  1. EndpointCreator.NewEndpointFromChangeModel()            │ Common
│  2. EndpointManager.AddEndpoint()                           │ Common
│  3. Fetch K8s metadata, resolve identity                    │ Common
│  4. Platform operations (via shim):                         │
│     a. PlatformNamespace.CreatePodSandbox()            ◄─── Via shim
│        └─ Windows impl:                                     │
│           wcnagent.CreateNamespace()                        │
│           └─ CreateCompartment() (kernel)                   │
│     b. PlatformEndpoint.CreateEndpoint()               ◄─── Via shim
│        └─ Windows impl:                                     │
│           wcnagent.CreateEndpoint()                         │
│           └─ Allocates wcn_id, sets MAC                     │
│     c. PlatformEndpoint.AttachEndpoint()               ◄─── Via shim
│        └─ Windows impl:                                     │
│           wcnagent.ModifyNamespace(Add, endpoint)           │
│           └─ CreateFlVirtualInterface()                     │
│           └─ CreateUnicastIpAddressEntry()                  │
│           └─ SetInterfaceDnsSettings()                      │
│           └─ CreateIpForwardEntry2()                        │
│           └─ CncAddOrUpdateEndpoint()                       │
│  5. Sync CiliumEndpoint CRD                                 │ Common
└─────────────────────────────────────────────────────────────┘
```

### 8.3 Agent Startup — Node Initialization

```
┌─────────────────────────────────────────────────────────────┐
│                 Agent Startup (Both Platforms)                │
│                                                              │
│  1. Parse config, connect to K8s                   Common    │
│  2. Initialize IPAM                                Common    │
│  3. PlatformNode.InitializeNode()             ◄── Via shim  │
│     ┌────────────────────────┬───────────────────────────┐   │
│     │ Linux:                 │ Windows:                  │   │
│     │ • setupBaseDevice()    │ • wcnagent.Initialize()   │   │
│     │   (cilium_host/net)    │ • wcnagent.CreateNetwork()│   │
│     │ • enableForwarding()   │   (selects adapter,       │   │
│     │ • loader.Reinitialize()│    programs CNC node,     │   │
│     │   (base BPF programs)  │    SNAT exclusions)       │   │
│     │ • setupTunnelDevice()  │                           │   │
│     └────────────────────────┴───────────────────────────┘   │
│  4. PlatformNode.ConfigureNodeRouting()        ◄── Via shim  │
│     ┌────────────────────────┬───────────────────────────┐   │
│     │ Linux:                 │ Windows:                  │   │
│     │ • addHostDeviceAddr()  │ • (done in CreateNetwork) │   │
│     │ • allocateRouterIPs()  │ • (mgmt IPs from adapter) │   │
│     │ • iptables rules       │                           │   │
│     └────────────────────────┴───────────────────────────┘   │
│  5. Restore endpoints from disk                    Common    │
│  6. Start K8s watchers                             Common    │
│  7. Start API server                               Common    │
└─────────────────────────────────────────────────────────────┘
```

---

## 9. Interface Contract Details

### 9.1 Ordering Constraints

The following ordering constraints must be maintained by callers:

```
InitializeNode()
    ↓
CreateNetwork()
    ↓ (for each pod)
CreatePodSandbox()  ← Can be called before or after CreateEndpoint
    ↓
CreateEndpoint()
    ↓
AttachEndpoint()    ← Requires both sandbox and endpoint to exist
    ↓ (teardown)
DetachEndpoint()
    ↓
DeleteEndpoint()
    ↓
DeletePodSandbox()
```

On **Linux**, `CreatePodSandbox()` is a no-op, so the effective order is `CreateEndpoint()` → `AttachEndpoint()`.

On **Windows**, `CreatePodSandbox()` must be called before `AttachEndpoint()` because the compartment must exist for the FL virtual interface to be created inside it.

### 9.2 Idempotency

All interface methods should be **idempotent**:
- `CreateNetwork` with the same ID should succeed if the network already exists with compatible config.
- `CreateEndpoint` with the same ID should succeed if the endpoint already exists.
- `Delete*` methods should succeed even if the object doesn't exist (no-op).
- This is critical for crash recovery: after a restart, the agent may re-issue create operations for objects that were partially created.

### 9.3 Error Handling

```go
// Platform-specific errors should be wrapped in standard error types:

var (
    ErrNetworkNotFound    = errors.New("network not found")
    ErrEndpointNotFound   = errors.New("endpoint not found")
    ErrSandboxNotFound    = errors.New("sandbox not found")
    ErrAlreadyExists      = errors.New("object already exists")
    ErrSubnetOverlap      = errors.New("subnet overlaps with existing network")
    ErrAdapterNotFound    = errors.New("host adapter not found")
    ErrInvalidConfig      = errors.New("invalid configuration")
)
```

### 9.4 Thread Safety

All interface methods must be **thread-safe**. The Cilium agent may call them from multiple goroutines concurrently (e.g., multiple CNI ADD requests arriving simultaneously).

- On Linux, the existing code uses `compilationLock` for BPF operations.
- On Windows, wcnagent uses a global `wcnagent_lock` that serializes all API calls.

### 9.5 JSON Schema Conversion

The Windows implementation must convert between Cilium's Go data structures and wcnagent's HCN JSON schema. This conversion happens in the platform implementation layer:

```go
// Example: Converting EndpointNetworkConfig to HCN JSON for wcnagent
func endpointConfigToHCNJSON(cfg EndpointNetworkConfig) (string, error) {
    hcnEndpoint := HCNEndpoint{
        SchemaVersion: SchemaVersion{Major: 2, Minor: 0},
        Name:          fmt.Sprintf("%s-eth0", cfg.PodName),
        HostComputeNetwork: cfg.NetworkID,
        IpConfigurations: []IpConfiguration{
            {
                IpAddress:    cfg.IPv4Address.Addr().String(),
                PrefixLength: cfg.IPv4Address.Bits(),
            },
        },
        Routes: convertRoutes(cfg.Routes),
        Dns:    convertDNS(cfg.DNS),
    }
    return json.Marshal(hcnEndpoint)
}
```

---

## 10. Open Questions & Decisions

### Q1: Where does veth creation happen on Linux after refactoring?

**Options:**
- **A) Keep in CNI plugin** (recommended for Phase 1): The CNI plugin continues to create veth pairs directly on Linux, as it does today. The `PlatformEndpoint.CreateEndpoint()` is only used for endpoint restoration and validation. This preserves the existing fast path.
- **B) Move to agent**: The CNI plugin delegates all networking to the agent via `PUT /endpoint/{id}`. The agent calls `PlatformEndpoint.CreateEndpoint()`. This is simpler but adds IPC latency.

**Recommendation:** Option A for Linux, Option B for Windows. The shim interfaces support both models.

### Q2: When is `CreatePodSandbox` called relative to CNI ADD?

On Windows, the compartment must exist before the endpoint can be attached. Two approaches:
- **A) CNI plugin calls a separate agent API for sandbox creation** before endpoint creation.
- **B) The agent automatically creates the sandbox during endpoint creation** if it doesn't exist.

**Recommendation:** Option B. The agent checks if a sandbox exists for the pod during `CreateEndpoint()`, and creates one if needed. This simplifies the CNI plugin.

### Q3: How does IPAM work on Windows?

IPAM is platform-agnostic — it runs in the Cilium agent regardless of platform. The agent allocates IPs from its pool (which is populated from Kubernetes PodCIDR or cloud IPAM). The allocated IP is passed to `CreateEndpoint()` in the `EndpointNetworkConfig`.

wcnagent does not manage IPAM — it receives pre-allocated IPs. This is consistent with how wcnagent works today (IPs come from HNS/CNI).

### Q4: What about BPF programs on Windows?

Phase 1 does not include BPF program loading on Windows. The datapath programming is done via CNC APIs (`CncAddOrUpdateEndpoint`, etc.) which are called by wcnagent. The `AttachEndpoint()` method on Windows does not compile or load BPF programs — it calls wcnagent's `ModifyNamespace` which programs the CNC datapath directly.

In the future (Phase 3 per the porting analysis), Windows eBPF may be used, and the Windows platform implementation could be extended to load BPF programs via eBPF-for-Windows APIs.

### Q5: How is wcnagent.dll deployed alongside the Cilium agent?

WcnAgent.dll needs to be co-located with the Cilium agent binary on Windows nodes. Options:
- **A) Bundle in the same container image** as the Cilium agent.
- **B) Install as a separate Windows service** and communicate via IPC.
- **C) Load as a shared library** from a well-known path.

**Recommendation:** Option A or C. Loading as a DLL (Option C) is the most natural fit since wcnagent is designed to be loaded via `WcnAgentFunctionTableOpen`. The DLL can be placed in the same directory as the Cilium agent binary or in a system path.

### Q6: State persistence on Windows — registry vs filesystem?

wcnagent persists state to the Windows registry. Cilium persists state to the filesystem (`/var/run/cilium/`). Options:
- **A) Let wcnagent continue using registry** and have Cilium use filesystem for its own state. Two sources of truth but each is authoritative for its domain.
- **B) Migrate wcnagent to filesystem-based persistence** to align with Cilium.

**Recommendation:** Option A for Phase 1. wcnagent's registry persistence is well-tested and enables crash recovery. Cilium can write its own state (endpoint metadata, identity cache) to filesystem.

---

## Appendix A: Existing Cilium Interfaces Relevant to Refactoring

These existing interfaces are already potential extension points. The new shim interfaces complement them:

```go
// pkg/datapath/types/loader.go — BPF program loading
type Loader interface {
    ReloadDatapath(ctx context.Context, ep Endpoint, cfg *LocalNodeConfiguration, 
                   stats *metrics.SpanStat) (string, error)
    Reinitialize(ctx context.Context, ...) error
    // ... more methods
}

// pkg/datapath/types/connector.go — Link pair creation
type ConnectorConfig interface {
    NewLinkPair(cfg LinkConfig, sysctl sysctl.Sysctl) (LinkPair, error)
    GetConfiguredMode() ConnectorMode
    // ... more methods
}

// pkg/datapath/types/node.go — Remote node management
type NodeHandler interface {
    NodeAdd(newNode nodeTypes.Node) error
    NodeUpdate(oldNode, newNode nodeTypes.Node) error
    NodeDelete(node nodeTypes.Node) error
    // ... more methods
}

// pkg/datapath/types/orchestrator.go — High-level datapath control
type Orchestrator interface {
    Reinitialize(ctx context.Context) error
    ReloadDatapath(ctx context.Context, ep Endpoint, stats *metrics.SpanStat) (string, error)
    // ... more methods
}

// pkg/endpoint/creator/creator.go — Endpoint object construction
type EndpointCreator interface {
    NewEndpointFromChangeModel(base *models.EndpointChangeRequest) (*endpoint.Endpoint, error)
    AddHostEndpoint(ctx context.Context) error
    AddIngressEndpoint(ctx context.Context) error
}
```

## Appendix B: WcnAgent API Mapping to Shim Interfaces

| WcnAgent API | Shim Interface | Shim Method |
|-------------|----------------|-------------|
| `Initialize()` | `PlatformNode` | `InitializeNode()` (part of) |
| `Uninitialize()` | `PlatformNode` | `CleanupNode()` (part of) |
| `CreateNetwork()` | `PlatformNetwork` | `CreateNetwork()` |
| `DeleteNetwork()` | `PlatformNetwork` | `DeleteNetwork()` |
| `QueryNetworkProperties()` | `PlatformNetwork` | `GetNetworkState()` |
| `CreateNamespace()` | `PlatformNamespace` | `CreatePodSandbox()` |
| `DeleteNamespace()` | `PlatformNamespace` | `DeletePodSandbox()` |
| `QueryNamespaceProperties()` | `PlatformNamespace` | `GetSandboxState()` |
| `CreateEndpoint()` | `PlatformEndpoint` | `CreateEndpoint()` |
| `DeleteEndpoint()` | `PlatformEndpoint` | `DeleteEndpoint()` |
| `QueryEndpointProperties()` | `PlatformEndpoint` | `GetEndpointState()` |
| `EnumerateEndpoints()` | `PlatformEndpoint` | `ListEndpoints()` |
| `ModifyNamespace(Add endpoint)` | `PlatformEndpoint` | `AttachEndpoint()` |
| `ModifyNamespace(Remove endpoint)` | `PlatformEndpoint` | `DetachEndpoint()` |

## Appendix C: Files Changed / Created

### New Files

| File | Purpose |
|------|---------|
| `pkg/datapath/types/platform.go` | `PlatformDatapath` aggregate interface |
| `pkg/datapath/types/platform_node.go` | `PlatformNode` interface + types |
| `pkg/datapath/types/platform_ns.go` | `PlatformNamespace` interface + types |
| `pkg/datapath/types/platform_endpoint.go` | `PlatformEndpoint` interface + types |
| `pkg/datapath/types/platform_network.go` | `PlatformNetwork` interface + types |
| `pkg/datapath/types/platform_types.go` | Shared data types (`DNSConfig`, `RouteConfig`, etc.) |
| `pkg/datapath/linux/platform_linux.go` | Linux `PlatformDatapath` implementation |
| `pkg/datapath/windows/platform_windows.go` | Windows `PlatformDatapath` implementation |
| `pkg/datapath/windows/wcnagent.go` | wcnagent DLL loading and Go wrapper |
| `pkg/datapath/windows/types.go` | Windows-specific types (HCN JSON schemas) |
| `pkg/datapath/windows/convert.go` | Cilium ↔ HCN JSON conversion functions |
| `plugins/cilium-cni/cmd/cmd_windows.go` | Windows CNI plugin (thin client) |
| `plugins/cilium-cni/cmd/endpoint_windows.go` | Windows endpoint listing (stub) |
| `plugins/cilium-cni/cmd/interface_windows.go` | Windows interface setup (no-op) |
| `daemon/cmd/daemon_main_linux.go` | Linux-specific daemon init (BPF, cgroups) |
| `daemon/cmd/daemon_main_windows.go` | Windows-specific daemon init (wcnagent) |
| `daemon/cmd/endpoint_restore_linux.go` | Linux endpoint restore (netlink) |
| `daemon/cmd/endpoint_restore_windows.go` | Windows endpoint restore (HCN) |
| `daemon/infraendpoints/netdev_windows.go` | Windows host IP management |
| `daemon/healthz/sockopt_linux.go` | Linux socket options (split from sockopt.go) |
| `daemon/healthz/sockopt_windows.go` | Windows socket options |

### Modified Files

| File | Change |
|------|--------|
| `daemon/cmd/daemon_main.go` | Move platform-specific init to `_linux.go` / `_windows.go` |
| `daemon/cmd/endpoint_restore.go` | Extract netlink calls to platform interface |
| `daemon/infraendpoints/infra_ip_allocation.go` | Extract netlink/routing calls to platform interface |
| `daemon/healthz/sockopt.go` | Split into platform files |
| `pkg/endpoint/bpf.go` | Route `realizeBPFState()` through platform shim (or keep as-is with Loader) |
| `pkg/datapath/orchestrator/orchestrator.go` | Add `PlatformDatapath` dependency |
| `plugins/cilium-cni/cmd/cmd.go` | Split platform-specific code to `_linux.go` / `_windows.go` |
