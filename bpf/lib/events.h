/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2016-2020 Authors of Cilium */

#ifndef __LIB_EVENTS_H_
#define __LIB_EVENTS_H_

#include <bpf/api.h>

#ifndef EBPF_FOR_WINDOWS
struct bpf_elf_map __section_maps EVENTS_MAP = {
	.type		= BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.size_key	= sizeof(__u32),
	.size_value	= sizeof(__u32),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= __NR_CPUS__,
};
#endif

#endif /* __LIB_EVENTS_H_ */
