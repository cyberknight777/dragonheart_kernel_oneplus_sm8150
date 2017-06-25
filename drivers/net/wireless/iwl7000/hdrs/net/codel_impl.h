#ifndef __NET_SCHED_CODEL_IMPL_H
#define __NET_SCHED_CODEL_IMPL_H

#define codel_params_init(params) WARN_ON_ONCE(1)
#define codel_vars_init(vars) WARN_ON_ONCE(1)
#define codel_stats_init(stats) WARN_ON_ONCE(1)
static inline void *codel_dequeue(void *a, void *b, void *c, void *d, void *e, void *f, void *g, void *h, void *j)
{
	WARN_ON(1);
	return NULL;
}

#endif
