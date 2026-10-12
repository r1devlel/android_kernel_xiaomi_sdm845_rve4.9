#ifndef BPF_BACKPORT_H
#define BPF_BACKPORT_H

#include <linux/version.h>
#include <linux/skbuff.h>
#include <net/neighbour.h>

/* ===== SKB CHECKSUM FUNCTIONS ===== */

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0)

/**
 * __skb_reset_checksum_unnecessary - Reset checksum state
 * Used to mark skb as having unnecessary checksum validation
 */
static inline void __skb_reset_checksum_unnecessary(struct sk_buff *skb)
{
	skb->ip_summed = CHECKSUM_UNNECESSARY;
}

#endif /* KERNEL_VERSION < 5.0.0 */

/* ===== SKB MAC HEADER FUNCTIONS ===== */

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0)

/**
 * skb_unset_mac_header - Unset the mac_header pointer
 * Marks the mac_header as invalid
 */
static inline void skb_unset_mac_header(struct sk_buff *skb)
{
	skb->mac_header = (typeof(skb->mac_header))~0U;
}

#endif /* KERNEL_VERSION < 5.0.0 */

/* ===== DEVICE FUNCTIONS ===== */

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 1, 0)

/**
 * dev_is_mac_header_xmit - Check if device uses mac header for transmission
 * Fallback implementation for older kernels
 */
static inline int dev_is_mac_header_xmit(const struct net_device *dev)
{
	/* Most devices use MAC header transmission in 4.9 era */
	return 1;
}

#endif /* KERNEL_VERSION < 5.1.0 */

/* ===== GSO (Generic Segmentation Offload) CONSTANTS ===== */

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 1, 0)

/* SKB_GSO_UDP_L4 introduced in 5.1 for UDP segmentation offload */
#ifndef SKB_GSO_UDP_L4
#define SKB_GSO_UDP_L4 (1 << 6)
#endif

#endif /* KERNEL_VERSION < 5.1.0 */

/* ===== GSO FUNCTIONS ===== */

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 1, 0)

/**
 * skb_is_gso_tcp - Check if skb is TCP GSO
 * Returns true if GSO is enabled and it's not UDP-based GSO
 */
static inline bool skb_is_gso_tcp(const struct sk_buff *skb)
{
	return skb_is_gso(skb) && !(skb_shinfo(skb)->gso_type & SKB_GSO_UDP);
}

/**
 * skb_decrease_gso_size - Decrease the GSO segment size
 * Adjusts gso_size after modifications to packet length
 */
static inline void skb_decrease_gso_size(struct skb_shared_info *shinfo,
					 u32 len_diff)
{
	/* Safely reduce the GSO size if needed */
	if (shinfo->gso_size > len_diff)
		shinfo->gso_size -= len_diff;
}

#endif /* KERNEL_VERSION < 5.1.0 */

/* ===== NEIGHBOR FUNCTIONS ===== */

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0)

/**
 * sock_confirm_neigh - Confirm neighbor for socket
 * Minimal stub that calls neigh_confirm if available
 */
static inline void sock_confirm_neigh(struct sk_buff *skb,
				       struct neighbour *neigh)
{
	/* In 4.9, just confirm the neighbor directly if it exists */
	if (neigh && neigh->confirmed < jiffies - 1) {
		neigh->confirmed = jiffies;
	}
}

/**
 * neigh_output - Output packet to neighbor
 * Wrapper around the older neigh->output() callback
 */
static inline int neigh_output(struct neighbour *neigh,
			        struct sk_buff *skb,
			        bool is_v6)
{
	/* Call the neighbor's output function directly in 4.9 */
	if (neigh && neigh->output)
		return neigh->output(neigh, skb);
	
	/* Fallback: consume the skb */
	kfree_skb(skb);
	return -EINVAL;
}

#endif /* KERNEL_VERSION < 5.0.0 */

/* ===== DATA POINTER FUNCTIONS ===== */

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 2, 0)

/**
 * bpf_compute_data_end_sk_skb - Compute data end pointer for SK_SKB
 * Fallback to generic data pointers computation
 */
static inline void bpf_compute_data_end_sk_skb(struct sk_buff *skb)
{
	/* In 4.9, use the generic data pointers function */
	bpf_compute_data_pointers(skb);
}

#endif /* KERNEL_VERSION < 5.2.0 */

/* ===== DEVICE OPERATIONS COMPATIBILITY ===== */

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0)

/**
 * Macro to safely check for ndo_get_peer_dev operation
 * Returns false/NULL in older kernels that don't have it
 */
#ifndef CONFIG_HAVE_NDO_GET_PEER_DEV
#define __ndo_get_peer_dev_available 0
#else
#define __ndo_get_peer_dev_available 1
#endif

#endif /* KERNEL_VERSION < 5.0.0 */

#endif /* BPF_BACKPORT_H */
