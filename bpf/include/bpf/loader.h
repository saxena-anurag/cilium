/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2016-2020 Authors of Cilium */

#ifndef __BPF_LOADER__
#define __BPF_LOADER__

#include <linux/types.h>

#define PIN_NONE		0
#define PIN_OBJECT_NS		1
#define PIN_GLOBAL_NS		2

#ifndef EBPF_FOR_WINDOWS
struct bpf_elf_map {
	__u32 type;
	__u32 size_key;
	__u32 size_value;
	__u32 max_elem;
	__u32 flags;
	__u32 id;
	__u32 pinning;
	__u32 inner_id;
	__u32 inner_idx;
};
#else
// EBPF_FOR_WINDOWS: This is a copy of ebpf_map_definition_in_file_t with
// field names adjusted to match what is expected by XDP progra,.
struct bpf_elf_map
{
    __u32 size;        ///< Size in bytes of the ebpf_map_definition_t structure.
    __u32 type; ///< Type of map.
    __u32 size_key;    ///< Size in bytes of a map key.
    __u32 size_value;  ///< Size in bytes of a map value.
    __u32 max_elem; ///< Maximum number of entries allowed in the map.

    /** When a map definition is hard coded in an eBPF program, inner_map_idx
     * indicates the 0-based index of which map in the maps section of the ELF
     * file is the inner map template.
     */
    uint32_t inner_map_idx;
    uint32_t pinning;
    uint32_t id;
    uint32_t inner_id;
};

#endif

#define NO_PREPOPULATE		-1

#endif /* __BPF_LOADER__ */
