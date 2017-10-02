/*
 * ChromeOS backport definitions
 * Copyright (C) 2015-2017 Intel Deutschland GmbH
 */
#include <linux/if_ether.h>
#include <linux/errqueue.h>
#include <generated/utsrelease.h>
/* ipv6_addr_is_multicast moved - include old header */
#include <net/addrconf.h>
#include <net/ieee80211_radiotap.h>

/* make sure we include iw_handler.h to get wireless_nlevent_flush() */
#include <net/iw_handler.h>

/* common backward compat code */

#define BACKPORTS_GIT_TRACKED "chromium:" UTS_RELEASE
#define BACKPORTS_BUILD_TSTAMP __DATE__ " " __TIME__

#ifndef netdev_alloc_pcpu_stats
#define netdev_alloc_pcpu_stats(type)				\
({								\
	typeof(type) __percpu *pcpu_stats = alloc_percpu(type); \
	if (pcpu_stats)	{					\
		int i;						\
		for_each_possible_cpu(i) {			\
			typeof(type) *stat;			\
			stat = per_cpu_ptr(pcpu_stats, i);	\
			u64_stats_init(&stat->syncp);		\
		}						\
	}							\
	pcpu_stats;						\
})
#endif /* netdev_alloc_pcpu_stats */

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0)
/* consider properly backporting this? */
static inline int crypto_memneq(const void *a, const void *b, size_t size)
{
	unsigned long neq = 0;

#if defined(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS)
	while (size >= sizeof(unsigned long)) {
		neq |= *(unsigned long *)a ^ *(unsigned long *)b;
		/* OPTIMIZER_HIDE_VAR(neq); */
		barrier();
		a += sizeof(unsigned long);
		b += sizeof(unsigned long);
		size -= sizeof(unsigned long);
	}
#endif /* CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS */
	while (size > 0) {
		neq |= *(unsigned char *)a ^ *(unsigned char *)b;
		/* OPTIMIZER_HIDE_VAR(neq); */
		barrier();
		a += 1;
		b += 1;
		size -= 1;
	}
	return neq != 0UL ? 1 : 0;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,14,0)
#include "u64_stats_sync.h"

struct pcpu_sw_netstats {
	u64     rx_packets;
	u64     rx_bytes;
	u64     tx_packets;
	u64     tx_bytes;
	struct u64_stats_sync   syncp;
};

#define netdev_tstats(dev)	((struct pcpu_sw_netstats *)dev->ml_priv)
#define netdev_assign_tstats(dev, e)	dev->ml_priv = (e);
#else
#define netdev_tstats(dev)	dev->tstats
#define netdev_assign_tstats(dev, e)	dev->tstats = (e);
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(3,14,0) */

#ifndef BIT_ULL
#define BIT_ULL(nr) (1ULL << (nr))
#endif

#ifndef GENMASK
#define GENMASK(h, l)		(((U32_C(1) << ((h) - (l) + 1)) - 1) << (l))
#define GENMASK_ULL(h, l)	(((U64_C(1) << ((h) - (l) + 1)) - 1) << (l))
#endif

static inline void netdev_attach_ops(struct net_device *dev,
				     const struct net_device_ops *ops)
{
	dev->netdev_ops = ops;
}

#define mc_addr(ha)	(ha)->addr

#ifndef U16_MAX
#define U16_MAX         ((u16)~0U)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,19,0)
static inline long ktime_get_seconds(void)
{
	struct timespec uptime;

	ktime_get_ts(&uptime);
	return uptime.tv_sec;
}
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(3,19,0) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
#define thermal_notify_framework notify_thermal_framework
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0) */

#ifndef S16_MAX
#define S16_MAX		((s16)(U16_MAX>>1))
#endif

#ifndef S16_MIN
#define S16_MIN		((s16)(-S16_MAX - 1))
#endif

#if LINUX_VERSION_IS_LESS(4,5,0)
void *memdup_user_nul(const void __user *src, size_t len);
#endif /* LINUX_VERSION_IS_LESS(4,5,0) */

/* this was added in v3.2.79, v3.18.30, v4.1.21, v4.4.6 and 4.5 */
#if !(LINUX_VERSION_IS_GEQ(4,4,6) || \
      (LINUX_VERSION_IS_GEQ(4,1,21) && \
       LINUX_VERSION_IS_LESS(4,2,0)) || \
      (LINUX_VERSION_IS_GEQ(3,18,30) && \
       LINUX_VERSION_IS_LESS(3,19,0)) || \
      (LINUX_VERSION_IS_GEQ(3,2,79) && \
       LINUX_VERSION_IS_LESS(3,3,0)))
/* we don't have wext */
static inline void wireless_nlevent_flush(void) {}
#endif

#ifndef SHASH_DESC_ON_STACK
#define SHASH_DESC_ON_STACK(shash, ctx)				 \
	char __##shash##_desc[sizeof(struct shash_desc) +	 \
	       crypto_shash_descsize(ctx)] CRYPTO_MINALIGN_ATTR; \
	struct shash_desc *shash = (struct shash_desc *)__##shash##_desc

static inline void *backport_idr_remove(struct idr *idr, int id)
{
	void *item = idr_find(idr, id);
	idr_remove(idr, id);
	return item;
}
#define idr_remove     backport_idr_remove
#endif

#ifndef setup_deferrable_timer
#define setup_deferrable_timer(timer, fn, data)                         \
        __setup_timer((timer), (fn), (data), TIMER_DEFERRABLE)
#endif

#if LINUX_VERSION_IS_LESS(4,1,0)
typedef struct {
#ifdef CONFIG_NET_NS
	struct net *net;
#endif
} possible_net_t;

static inline void possible_write_pnet(possible_net_t *pnet, struct net *net)
{
#ifdef CONFIG_NET_NS
	pnet->net = net;
#endif
}

static inline struct net *possible_read_pnet(const possible_net_t *pnet)
{
#ifdef CONFIG_NET_NS
	return pnet->net;
#else
	return &init_net;
#endif
}
#else
#define possible_write_pnet(pnet, net) write_pnet(pnet, net)
#define possible_read_pnet(pnet) read_pnet(pnet)
#endif /* LINUX_VERSION_IS_LESS(4,1,0) */

#if LINUX_VERSION_IS_LESS(4,12,0) &&		\
	!LINUX_VERSION_IN_RANGE(4,11,9, 4,12,0)
#define netdev_set_priv_destructor(_dev, _destructor) \
	(_dev)->destructor = __ ## _destructor
#define netdev_set_def_destructor(_dev) \
	(_dev)->destructor = free_netdev
#else
#define netdev_set_priv_destructor(_dev, _destructor) \
	(_dev)->needs_free_netdev = true; \
	(_dev)->priv_destructor = (_destructor);
#define netdev_set_def_destructor(_dev) \
	(_dev)->needs_free_netdev = true;
#endif

#if LINUX_VERSION_IS_LESS(4,9,0) &&			\
	!LINUX_VERSION_IN_RANGE(3,12,69, 3,13,0) &&	\
	!LINUX_VERSION_IN_RANGE(4,4,37, 4,5,0) &&	\
	!LINUX_VERSION_IN_RANGE(4,8,13, 4,9,0)

#define pcie_find_root_port iwl7000_pcie_find_root_port
static inline struct pci_dev *pcie_find_root_port(struct pci_dev *dev)
{
	while (1) {
		if (!pci_is_pcie(dev))
			break;
		if (pci_pcie_type(dev) == PCI_EXP_TYPE_ROOT_PORT)
			return dev;
		if (!dev->bus->self)
			break;
		dev = dev->bus->self;
	}
	return NULL;
}

#endif/* <4.9.0 but not >= 3.12.69, 4.4.37, 4.8.13 */
