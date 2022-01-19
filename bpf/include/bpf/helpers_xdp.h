/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2016-2020 Authors of Cilium */

#ifndef __BPF_HELPERS_XDP__
#define __BPF_HELPERS_XDP__

#ifndef EBPF_FOR_WINDOWS
#include <linux/bpf.h>
#endif

#include "compiler.h"
#include "helpers.h"
#include "features_xdp.h"

/* Only used helpers in Cilium go below. */

/* Packet misc meta data & encapsulation helper */
#ifndef EBPF_FOR_WINDOWS
static int BPF_FUNC(xdp_adjust_meta, struct xdp_md *xdp, int delta);
#endif
static int BPF_FUNC(xdp_adjust_head, struct xdp_md *xdp, int delta);
#ifndef EBPF_FOR_WINDOWS
static int BPF_FUNC(xdp_adjust_tail, struct xdp_md *xdp, int delta);
#endif

/* Packet redirection */
static int BPF_STUB(redirect, int ifindex, __u32 flags);

/* Packet manipulation */
static int BPF_STUB(xdp_load_bytes, struct xdp_md *xdp, __u32 off,
		    void *to, __u32 len);
static int BPF_STUB(xdp_store_bytes, struct xdp_md *xdp, __u32 off,
		    const void *from, __u32 len, __u32 flags);

static int BPF_STUB(l3_csum_replace, struct xdp_md *xdp, __u32 off,
		    __u32 from, __u32 to, __u32 flags);
static int BPF_STUB(l4_csum_replace, struct xdp_md *xdp, __u32 off,
		    __u32 from, __u32 to, __u32 flags);

static int BPF_STUB(xdp_adjust_room, struct xdp_md *xdp, __s32 len_diff,
		    __u32 mode, __u64 flags);

static int BPF_STUB(xdp_change_type, struct xdp_md *xdp, __u32 type);
static int BPF_STUB(xdp_change_proto, struct xdp_md *xdp, __u32 proto,
		    __u32 flags);
static int BPF_STUB(xdp_change_tail, struct xdp_md *xdp, __u32 nlen,
		    __u32 flags);

#ifndef EBPF_FOR_WINDOWS
/* Packet tunnel encap/decap */
static int BPF_STUB(xdp_get_tunnel_key, struct xdp_md *xdp,
		    struct bpf_tunnel_key *to, __u32 size, __u32 flags);
static int BPF_STUB(xdp_set_tunnel_key, struct xdp_md *xdp,
		    const struct bpf_tunnel_key *from, __u32 size,
		    __u32 flags);
#endif

#ifndef EBPF_FOR_WINDOWS
/* Events for user space */
static int BPF_FUNC_REMAP(xdp_event_output, struct xdp_md *xdp, void *map,
			  __u64 index, const void *data, __u32 size) =
			 (void *)BPF_FUNC_perf_event_output;
#endif

#endif /* __BPF_HELPERS_XDP__ */
