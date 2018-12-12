#ifndef _LINUX_LOW_MEM_NOTIFY_H
#define _LINUX_LOW_MEM_NOTIFY_H

#include <linux/mm.h>
#include <linux/ratelimit.h>
#include <linux/stddef.h>
#include <linux/swap.h>

extern unsigned low_mem_margin_percent;
extern unsigned long low_mem_minfree;
void low_mem_notify(void);
extern const struct file_operations low_mem_notify_fops;
extern bool low_mem_margin_enabled;
extern unsigned int low_mem_ram_vs_swap_weight;
extern struct ratelimit_state low_mem_logging_ratelimit;

/*
 * Compute available memory used by files that can be reclaimed quickly.
 */
static inline unsigned long get_available_file_mem(void)
{
	unsigned long file_mem =
			global_node_page_state(NR_ACTIVE_FILE) +
			global_node_page_state(NR_INACTIVE_FILE);
	unsigned long dirty_mem = global_node_page_state(NR_FILE_DIRTY);
	unsigned long min_file_mem = min_filelist_kbytes >> (PAGE_SHIFT - 10);
	unsigned long clean_file_mem = file_mem - dirty_mem;
	/* Conservatively estimate the amount of available_file_mem */
	unsigned long available_file_mem = (clean_file_mem > min_file_mem) ?
			(clean_file_mem - min_file_mem) : 0;
	return available_file_mem;
}

/*
 * Available anonymous memory.
 */
static inline unsigned long get_available_anon_mem(void)
{
	return global_node_page_state(NR_ACTIVE_ANON) +
		global_node_page_state(NR_INACTIVE_ANON);
}

/*
 * Compute "available" memory, that is either free memory or memory that can be
 * reclaimed quickly, adjusted for the presence of swap.
 */
static inline unsigned long get_available_mem_adj(void)
{
	/* min_free_kbytes is reserved for emergency allocation like when
	 * PF_MEMALLOC is set. In general it's not usable in normal page
	 * allocation process.
	 */
	unsigned long min_free_pages = min_free_kbytes >> (PAGE_SHIFT - 10);
	/* free_mem is completely unallocated; clean file-backed memory
	 * (file_mem - dirty_mem) is easy to reclaim, except for the last
	 * min_filelist_kbytes.
	 */
	unsigned long free_mem =
			global_zone_page_state(NR_FREE_PAGES) - min_free_pages;
	unsigned long available_mem = free_mem +
			get_available_file_mem();
	unsigned long swappable_pages = min_t(unsigned long,
			get_nr_swap_pages(), get_available_anon_mem());
	/*
	 * The contribution of swap is reduced by a factor of
	 * low_mem_ram_vs_swap_weight.
	 */
	return available_mem + swappable_pages / low_mem_ram_vs_swap_weight;
}

/*
 * Returns TRUE if we are in a low memory state.
 */
static inline bool _is_low_mem_situation(void)
{
	static bool was_low_mem;	/* = false, as per style guide */
	/* We declare a low-memory condition when a combination of RAM and swap
	 * space is low.
	 */
	unsigned long available_mem = get_available_mem_adj();
	bool is_low_mem = available_mem < low_mem_minfree;

	if (unlikely(is_low_mem && !was_low_mem) &&
	    __ratelimit(&low_mem_logging_ratelimit)) {
		pr_info("entering low_mem (avail RAM = %lu kB, avail swap %lu kB, avail file %lu kB, anon mem: %lu kB)\n",
			available_mem * PAGE_SIZE / 1024,
			get_nr_swap_pages() * PAGE_SIZE / 1024,
			get_available_file_mem() * PAGE_SIZE / 1024,
			get_available_anon_mem() * PAGE_SIZE / 1024);
	}
	was_low_mem = is_low_mem;

	return is_low_mem;
}

static inline bool is_low_mem_situation(void)
{
	return low_mem_margin_enabled ? _is_low_mem_situation() : false;
}

#endif
