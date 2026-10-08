/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BPF_NETNS_H
#define _BPF_NETNS_H

#include <linux/mutex.h>
#include <uapi/linux/bpf.h>

struct bpf_prog;
struct bpf_prog_array;

enum netns_bpf_attach_type {
	NETNS_BPF_INVALID = -1,
	NETNS_BPF_FLOW_DISSECTOR = 0,
	NETNS_BPF_SK_LOOKUP,
	MAX_NETNS_BPF_ATTACH_TYPE
};

static inline enum netns_bpf_attach_type
to_netns_bpf_attach_type(enum bpf_attach_type attach_type)
{
	switch (attach_type) {
	case BPF_FLOW_DISSECTOR:
		return NETNS_BPF_FLOW_DISSECTOR;
	case BPF_SK_LOOKUP:
		return NETNS_BPF_SK_LOOKUP;
	default:
		return NETNS_BPF_INVALID;
	}
}

extern struct mutex netns_bpf_mutex;

#endif /* _BPF_NETNS_H */
