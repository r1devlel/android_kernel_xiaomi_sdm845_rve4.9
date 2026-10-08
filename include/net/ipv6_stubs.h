#ifndef _IPV6_STUBS_H
#define _IPV6_STUBS_H

#include <linux/in6.h>
#include <linux/types.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <net/udp.h>

/*
 * BPF IPv6 socket helper interface.
 *
 * The 4.9 tree already defines struct ipv6_stub in addrconf.h,
 * so this header only carries the BPF-specific stub introduced by mido.
 */
struct ipv6_bpf_stub {
	int (*inet6_bind)(struct sock *sk, struct sockaddr *uaddr, int addr_len,
			  u32 flags);
	struct sock *(*udp6_lib_lookup)(struct net *net,
					const struct in6_addr *saddr, __be16 sport,
					const struct in6_addr *daddr, __be16 dport,
					int dif, int sdif, struct udp_table *tbl,
					struct sk_buff *skb);
};

extern const struct ipv6_bpf_stub *ipv6_bpf_stub __read_mostly;

#endif
