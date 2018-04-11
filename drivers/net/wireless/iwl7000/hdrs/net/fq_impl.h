#ifndef __NET_SCHED_FQ_IMPL_H
#define __NET_SCHED_FQ_IMPL_H

#include <net/fq.h>

static inline struct sk_buff *fq_flow_dequeue(struct fq *fq,
					      struct fq_flow *flow)
{
	WARN_ON(1);
	return NULL;
}

static inline struct sk_buff *fq_tin_dequeue(struct fq *fq,
					     struct fq_tin *tin,
					     fq_tin_dequeue_t dequeue_func)
{
	WARN_ON(1);
	return NULL;
}

static inline struct fq_flow *fq_flow_classify(struct fq *fq,
					struct fq_tin *tin,
					struct sk_buff *skb,
					fq_flow_get_default_t get_default_func)
{
	WARN_ON(1);
	return NULL;
}

static inline void fq_recalc_backlog(struct fq *fq,
				     struct fq_tin *tin,
				     struct fq_flow *flow)
{
	WARN_ON(1);
}

static inline void fq_tin_enqueue(struct fq *fq,
				  struct fq_tin *tin,
				  struct sk_buff *skb,
				  fq_skb_free_t free_func,
				  fq_flow_get_default_t get_default_func)
{
	WARN_ON(1);
}

static inline void fq_tin_filter(struct fq *fq,
				 struct fq_tin *tin,
				 fq_skb_filter_t filter_func,
				 void *filter_data,
				 fq_skb_free_t free_func)
{
	WARN_ON(1);
}

static inline void fq_flow_reset(struct fq *fq,
				 struct fq_flow *flow,
				 fq_skb_free_t free_func)
{
	WARN_ON(1);
}

static inline void fq_tin_reset(struct fq *fq,
				struct fq_tin *tin,
				fq_skb_free_t free_func)
{
	WARN_ON(1);
}

static inline void fq_flow_init(struct fq_flow *flow)
{
	WARN_ON(1);
}

static inline void fq_tin_init(struct fq_tin *tin)
{
	WARN_ON(1);
}

static inline int fq_init(struct fq *fq, int flows_cnt)
{
	WARN_ON(1);
	return -EOPNOTSUPP;
}

static inline void fq_reset(struct fq *fq,
			    fq_skb_free_t free_func)
{
	WARN_ON(1);
}
#endif
