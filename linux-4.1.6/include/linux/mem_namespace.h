#ifndef _LINUX_MEM_NS_H
#define _LINUX_MEM_NS_H

#include <linux/sched.h>
#include <linux/bug.h>
#include <linux/mm.h>
#include <linux/gfp.h>
#include <linux/nsproxy.h>
#include <linux/kref.h>
#include <linux/ns_common.h>

#ifdef CONFIG_AZKABAN_NS

struct kmem_cache;
struct kmem_cache_node;

struct mem_namespace {
	struct list_head	slab_caches;
	struct kmem_cache *	kmem_cache;
	struct kmem_cache *	kmalloc_caches[KMALLOC_SHIFT_HIGH + 1];
#ifdef CONFIG_ZONE_DMA
	struct kmem_cache *	kmalloc_dma_caches[KMALLOC_SHIFT_HIGH + 1];
#endif
	struct kmem_cache *	nsproxy_cachep;
#ifdef CONFIG_AZKABAN_PID_NS
	struct kmem_cache *	pid_ns_cachep;
#endif
#ifdef CONFIG_AZKABAN_MNT_NS
	struct kmem_cache *	mnt_cache;
#endif
#ifdef CONFIG_AZKABAN_NET_NS
	struct kmem_cache *	net_cachep;
#endif
	struct kmem_cache 	*task_struct_cachep;
	struct kmem_cache	*task_xstate_cachep;
	struct kmem_cache	*cred_jar;
	struct kmem_cache	*signal_cachep;
	struct kmem_cache	*sighand_cachep;
	struct kmem_cache	*files_cachep;
	struct kmem_cache	*fs_cachep;
	struct kmem_cache	*vm_area_cachep;
	struct kmem_cache	*mm_cachep;
	struct kmem_cache	*delayacct_cache;

	struct kmem_cache	*pgd_cache;

#if USE_SPLIT_PTE_PTLOCKS && ALLOC_SPLIT_PTLOCKS
	struct kmem_cache	*page_ptl_cachep;
#endif
};

int copy_mem_namespace(unsigned long clone_flags);
struct mem_namespace *create_mem_ns(int flags);

#define __GFP_NS		((__force gfp_t)0x10000000u)

#define SLAB_NS			0x00100000UL

static inline struct mem_namespace *current_mem_ns(void)
{
	struct task_struct *tsk = current;
	if (unlikely(tsk->clone_mem_ns))
		return tsk->clone_mem_ns;
	return tsk->mem_ns;
}

#define KMEM_CACHE_NS(name)					\
	({								\
		struct mem_namespace *ns = current_mem_ns();		\
		(ns) ? ns->name : name;					\
	})

struct kmem_cache *ns_copy_kmem_cache(struct kmem_cache *root);

void test_mem_ns(struct mem_namespace *mem_ns);

#endif /* AZKABAN_NS */

#endif /* _LINUX_MEM_NS_H */
