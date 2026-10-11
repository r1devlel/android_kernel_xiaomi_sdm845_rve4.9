/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM xdp

#if !defined(_TRACE_XDP_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_XDP_H

#include <linux/netdevice.h>
#include <linux/filter.h>
#include <linux/tracepoint.h>

#ifndef __DEVMAP_OBJ_TYPE
#define __DEVMAP_OBJ_TYPE
struct _bpf_dtab_netdev {
	struct net_device *dev;
};
#endif /* __DEVMAP_OBJ_TYPE */

TRACE_EVENT(xdp_exception,

	TP_PROTO(const struct net_device *dev,
		 const struct bpf_prog *xdp, u32 act),

	TP_ARGS(dev, xdp, act),

	TP_STRUCT__entry(
		__field(int, prog_id)
		__field(u32, act)
		__field(int, ifindex)
	),

	TP_fast_assign(
		__entry->prog_id = xdp->aux->id;
		__entry->act = act;
		__entry->ifindex = dev->ifindex;
	),

	TP_printk("prog_id=%d action=%u ifindex=%d",
		  __entry->prog_id, __entry->act, __entry->ifindex)
);

TRACE_EVENT(xdp_devmap_xmit,

	TP_PROTO(const struct net_device *from_dev,
		 const struct net_device *to_dev,
		 int sent, int drops, int err),

	TP_ARGS(from_dev, to_dev, sent, drops, err),

	TP_STRUCT__entry(
		__field(int, from_ifindex)
		__field(u32, act)
		__field(int, to_ifindex)
		__field(int, drops)
		__field(int, sent)
		__field(int, err)
	),

	TP_fast_assign(
		__entry->from_ifindex = from_dev->ifindex;
		__entry->act = 4; /* XDP_REDIRECT */
		__entry->to_ifindex = to_dev->ifindex;
		__entry->drops = drops;
		__entry->sent = sent;
		__entry->err = err;
	),

	TP_printk("from_ifindex=%d to_ifindex=%d action=%u sent=%d drops=%d err=%d",
		  __entry->from_ifindex, __entry->to_ifindex, __entry->act,
		  __entry->sent, __entry->drops, __entry->err)
);

#endif /* _TRACE_XDP_H */

#include <trace/define_trace.h>
