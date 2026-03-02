// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux && !windows

package defaults

const (
	// AddressScopeMax controls the maximum address scope for addresses to be
	// considered local ones with HOST_ID in the ipcache
	// Use the raw value instead of constant as netlink.SCOPE_HOST is using unix.RT_SCOPE_HOST
	AddressScopeMax = 0xfe // netlink.SCOPE_HOST
)

// Fallback platform-specific filesystem paths for unsupported platforms.
const (
	RuntimePath         = "/var/run/cilium"
	LibraryPath         = "/var/lib/cilium"
	SockPath            = RuntimePath + "/cilium.sock"
	ShellSockPath       = RuntimePath + "/shell.sock"
	MonitorSockPath1_2  = RuntimePath + "/monitor1_2.sock"
	PidFilePath         = RuntimePath + "/cilium.pid"
	DeleteQueueDir      = RuntimePath + "/deleteQueue"
	DeleteQueueLockfile = DeleteQueueDir + "/lockfile"
	BPFFSRoot           = "/sys/fs/bpf"
	BPFFSRootFallback   = "/run/cilium/bpffs"
	DefaultCgroupRoot   = "/run/cilium/cgroupv2"
	NetNsPath           = RuntimePath + "/netns"
)
