// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package defaults

import (
	"github.com/vishvananda/netlink"
)

const (
	// AddressScopeMax controls the maximum address scope for addresses to be
	// considered local ones with HOST_ID in the ipcache
	AddressScopeMax = int(netlink.SCOPE_HOST)
)

// Platform-specific filesystem paths for Linux.
const (
	// RuntimePath is the default path to the runtime directory
	RuntimePath = "/var/run/cilium"

	// LibraryPath is the default path to the cilium libraries directory
	LibraryPath = "/var/lib/cilium"

	// SockPath is the path to the UNIX domain socket exposing the API to clients locally
	SockPath = RuntimePath + "/cilium.sock"

	// ShellSockPath is the path to the UNIX domain socket exposing the debug shell
	ShellSockPath = RuntimePath + "/shell.sock"

	// MonitorSockPath1_2 is the path to the UNIX domain socket used to
	// distribute BPF and agent events to listeners (1.2 protocol version).
	MonitorSockPath1_2 = RuntimePath + "/monitor1_2.sock"

	// PidFilePath is the path to the pid file for the agent.
	PidFilePath = RuntimePath + "/cilium.pid"

	// DeleteQueueDir is the directory used for the CNI plugin to queue deletion requests
	// if the agent is down
	DeleteQueueDir = RuntimePath + "/deleteQueue"

	// DeleteQueueLockfile is the file used to synchronize access of the queue directory between
	// the agent and the CNI plugin processes
	DeleteQueueLockfile = DeleteQueueDir + "/lockfile"

	// BPFFSRoot is the default path where BPFFS should be mounted
	BPFFSRoot = "/sys/fs/bpf"

	// BPFFSRootFallback is the path which is used when /sys/fs/bpf has
	// a mount, but with the other filesystem than BPFFS.
	BPFFSRootFallback = "/run/cilium/bpffs"

	// DefaultCgroupRoot is the default path where cilium cgroup2 should be mounted
	DefaultCgroupRoot = "/run/cilium/cgroupv2"

	// NetNsPath is the default path to the mounted network namespaces directory
	NetNsPath = RuntimePath + "/netns"
)
