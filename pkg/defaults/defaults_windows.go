// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package defaults

const (
	// AddressScopeMax controls the maximum address scope for addresses to be
	// considered local ones with HOST_ID in the ipcache
	// Use the raw value instead of constant as netlink.SCOPE_HOST requires unix headers
	AddressScopeMax = 0xfe // netlink.SCOPE_HOST
)

// Platform-specific filesystem paths for Windows.
const (
	// RuntimePath is the default path to the runtime directory
	RuntimePath = `C:\var\run\cilium`

	// LibraryPath is the default path to the cilium libraries directory
	LibraryPath = `C:\var\lib\cilium`

	// SockPath is the path to the UNIX domain socket exposing the API to clients locally.
	// Windows supports AF_UNIX sockets since Windows 10 1803 / Windows Server 2019.
	SockPath = RuntimePath + `\cilium.sock`

	// ShellSockPath is the path to the UNIX domain socket exposing the debug shell
	ShellSockPath = RuntimePath + `\shell.sock`

	// MonitorSockPath1_2 is the path to the UNIX domain socket used to
	// distribute BPF and agent events to listeners (1.2 protocol version).
	MonitorSockPath1_2 = RuntimePath + `\monitor1_2.sock`

	// PidFilePath is the path to the pid file for the agent.
	PidFilePath = RuntimePath + `\cilium.pid`

	// DeleteQueueDir is the directory used for the CNI plugin to queue deletion requests
	// if the agent is down
	DeleteQueueDir = RuntimePath + `\deleteQueue`

	// DeleteQueueLockfile is the file used to synchronize access of the queue directory between
	// the agent and the CNI plugin processes
	DeleteQueueLockfile = DeleteQueueDir + `\lockfile`

	// BPFFSRoot is not applicable on Windows (BPFFS is Linux-specific).
	BPFFSRoot = ""

	// BPFFSRootFallback is not applicable on Windows.
	BPFFSRootFallback = ""

	// DefaultCgroupRoot is not applicable on Windows (cgroups are Linux-specific).
	DefaultCgroupRoot = ""

	// NetNsPath is not applicable on Windows in the same way as Linux;
	// Windows uses HCN namespace IDs rather than pinned mount paths.
	NetNsPath = ""
)
