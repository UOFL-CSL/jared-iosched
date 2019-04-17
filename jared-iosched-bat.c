/*
 * EDIT: Adding batching.
 * The Jared I/O scheduler.
 *
 * Copyright (C) 2019 UofL Computer Systems Lab
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License v2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
#include <linux/kernel.h>
#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/elevator.h>
#include <linux/module.h>
#include <linux/sbitmap.h>

#include "blk.h"
#include "blk-mq.h"
#include "blk-mq-sched.h"
#include "blk-mq-tag.h"

/* Scheduling domains. */
enum {
	JARED_READ,
	JARED_SYNC_WRITE,
	JARED_OTHER, /* Async writes, discard, etc. */
	JARED_NUM_DOMAINS,
};

/*
 * Scheduling domain batch sizes. We favor reads.
 */
static const unsigned int jared_batch_size[] = {
	[JARED_READ] = 16,
	[JARED_SYNC_WRITE] = 8,
	[JARED_OTHER] = 8,
};

struct jared_ctx_queue { // Software context
	spinlock_t lock;
	struct list_head rq_list[JARED_NUM_DOMAINS]; // Requests ready to be sent to HW dispatch queue
} ____cacheline_aligned_in_smp;


struct jared_hctx_data { // Hardware context
	spinlock_t lock;
	struct list_head rqs[JARED_NUM_DOMAINS]; // Requests ready to be sent to driver
	unsigned int cur_domain;
	unsigned int batching;
	struct jared_ctx_queue *jcqs; // Software context queues (could be > 1)
	struct sbitmap jcq_map[JARED_NUM_DOMAINS]; // Software contexts with requests ready to be sent
};

static unsigned int jared_sched_domain(unsigned int op)
{
	if ((op & REQ_OP_MASK) == REQ_OP_READ)
		return JARED_READ;
	else if ((op & REQ_OP_MASK) == REQ_OP_WRITE && op_is_sync(op))
		return JARED_SYNC_WRITE;
	else
		return JARED_OTHER;
}
	 
static int jared_init_sched(struct request_queue *q, struct elevator_type *e)
{
	struct elevator_queue *eq;

	eq = elevator_alloc(q, e);
	if (!eq)
		return -ENOMEM;

	q->elevator = eq;
	
	return 0;
}

static void jared_ctx_queue_init(struct jared_ctx_queue *jcq)
{
	unsigned int i;
	
	spin_lock_init(&jcq->lock);
	for (i = 0; i < JARED_NUM_DOMAINS; i++)
		INIT_LIST_HEAD(&jcq->rq_list[i]);
}

static int jared_init_hctx(struct blk_mq_hw_ctx *hctx, unsigned int hctx_idx)
{
	struct jared_hctx_data *jhd;
	int i;

	jhd = kmalloc_node(sizeof(*jhd), GFP_KERNEL, hctx->numa_node);
	if (!jhd)
		return -ENOMEM;

	jhd->jcqs = kmalloc_array_node(hctx->nr_ctx,
				       sizeof(struct jared_ctx_queue),
				       GFP_KERNEL, hctx->numa_node);
	if (!jhd->jcqs)
		goto err_jhd;

	for (i = 0; i < hctx->nr_ctx; i++)
		jared_ctx_queue_init(&jhd->jcqs[i]);

	for (i = 0; i < JARED_NUM_DOMAINS; i++) {
		if (sbitmap_init_node(&jhd->jcq_map[i], hctx->nr_ctx,
					  ilog2(8), GFP_KERNEL, hctx->numa_node)) {
			while (--i >= 0)
				sbitmap_free(&jhd->jcq_map[i]);
			goto err_jcqs;
		}
	}

	spin_lock_init(&jhd->lock);
	
	for (i = 0; i < JARED_NUM_DOMAINS; i++) {
		INIT_LIST_HEAD(&jhd->rqs[i]);
	}
	

	jhd->cur_domain = 0;
	jhd->batching = 0;
	
	hctx->sched_data = jhd;
	
	return 0;

err_jcqs:
	kfree(jhd->jcqs);
err_jhd:
	kfree(jhd);
	return -ENOMEM;
}

static void jared_exit_hctx(struct blk_mq_hw_ctx *hctx, unsigned int hctx_idx)
{
	struct jared_hctx_data *jhd = hctx->sched_data;
	int i;
	
	for (i = 0; i < JARED_NUM_DOMAINS; i++)
		sbitmap_free(&jhd->jcq_map[i]);
	kfree(jhd->jcqs);
	kfree(hctx->sched_data);
}

static bool jared_bio_merge(struct blk_mq_hw_ctx *hctx, struct bio *bio)
{
	struct jared_hctx_data *jhd = hctx->sched_data;
	struct blk_mq_ctx *ctx = blk_mq_get_ctx(hctx->queue);
	struct jared_ctx_queue *jcq = &jhd->jcqs[ctx->index_hw];
	unsigned int sched_domain = jared_sched_domain(bio->bi_opf);
	struct list_head *rq_list = &jcq->rq_list[sched_domain];
	bool merged;

	spin_lock(&jcq->lock);
	merged = blk_mq_bio_list_merge(hctx->queue, rq_list, bio);
	spin_unlock(&jcq->lock);
	blk_mq_put_ctx(ctx);

	return merged;
}

static void jared_insert_requests(struct blk_mq_hw_ctx *hctx,
				struct list_head *rqs, bool at_head)
{
	struct jared_hctx_data *jhd = hctx->sched_data;
	struct request *rq, *next;

	list_for_each_entry_safe(rq, next, rqs, queuelist) {
		unsigned int sched_domain = jared_sched_domain(rq->cmd_flags);
		struct jared_ctx_queue *jcq = &jhd->jcqs[rq->mq_ctx->index_hw];
		struct list_head *head = &jcq->rq_list[sched_domain];

		spin_lock(&jcq->lock);
		if (at_head)
			list_move(&rq->queuelist, head);
		else
			list_move_tail(&rq->queuelist, head);
		sbitmap_set_bit(&jhd->jcq_map[sched_domain], 
				rq->mq_ctx->index_hw);
		blk_mq_sched_request_inserted(rq);
		spin_unlock(&jcq->lock);
	}
}

struct flush_jcq_data {
	struct jared_hctx_data *jhd;
	unsigned int sched_domain;
	struct list_head *list;
};

static bool flush_busy_jcq(struct sbitmap *sb, unsigned int bitnr, void *data)
{
	struct flush_jcq_data *flush_data = data;
	struct jared_ctx_queue *jcq = &flush_data->jhd->jcqs[bitnr];

	spin_lock(&jcq->lock);
	list_splice_tail_init(&jcq->rq_list[flush_data->sched_domain], 
				  flush_data->list);
	sbitmap_clear_bit(sb, bitnr);
	spin_unlock(&jcq->lock);

	return true;
}

static void jared_flush_busy_jcqs(struct jared_hctx_data *jhd,
				  unsigned int sched_domain,
				  struct list_head *list)
{
    // For each SW queue with pending requests, add to HW dispatch.
	struct flush_jcq_data data = {
		.jhd = jhd,
		.sched_domain = sched_domain,
		.list = list,
	};

	sbitmap_for_each_set(&jhd->jcq_map[sched_domain], 
				 flush_busy_jcq, &data);
}

static struct request *
jared_dispatch_cur_domain(struct jared_hctx_data *jhd,
			  struct blk_mq_hw_ctx *hctx)
{
	struct list_head *rqs;
	struct request *rq;

	rqs = &jhd->rqs[jhd->cur_domain];

	/*
	 * If we already have a flushed request, then we send it. 
	 * Otherwise, if there are pending requests in the jcqs,
	 * flush the jcqs. If not, we should leave the requests in the jcqs 
	 * so that they can be merged. Note that jhd->lock serializes the 
	 * flushes, so if we observed any bit set in the kcq_map, we will 
	 * always get a request.
	 */
	rq = list_first_entry_or_null(rqs, struct request, queuelist);
	if (rq) {
		jhd->batching++;
		list_del_init(&rq->queuelist);
		return rq;
	} else if (sbitmap_any_bit_set(&jhd->jcq_map[jhd->cur_domain])) {
		jared_flush_busy_jcqs(jhd, jhd->cur_domain, rqs);
		rq = list_first_entry(rqs, struct request, queuelist);
		jhd->batching++;
		list_del_init(&rq->queuelist);
		return rq;
	}

	/* There were either no pending requests or no tokens. */
	return NULL;
}

static struct request *jared_dispatch_request(struct blk_mq_hw_ctx *hctx)
{
	struct jared_hctx_data *jhd = hctx->sched_data;
	struct request *rq;
	int i;

	spin_lock(&jhd->lock);

	/*
	 * First, if we are still entitled to batch, try to dispatch a request
	 * from the batch.
	 */
	if (jhd->batching < jared_batch_size[jhd->cur_domain]) {
		rq = jared_dispatch_cur_domain(jhd, hctx);
		if (rq)
			goto out;
	}

	/*
	 * Either,
	 * 1. We were no longer entitled to a batch.
	 * 2. The domain we were batching didn't have any requests.
	 *
	 * Start another batch. Note that this wraps back around to the original
	 * domain if no other domains have requests.
	 */
	jhd->batching = 0;
	for (i = 0; i < JARED_NUM_DOMAINS; i++) {
		if (jhd->cur_domain == JARED_NUM_DOMAINS - 1)
			jhd->cur_domain = 0;
		else
			jhd->cur_domain++;

		rq = jared_dispatch_cur_domain(jhd, hctx);
		if (rq)
			goto out;
	}

	rq = NULL;
out:
	spin_unlock(&jhd->lock);
	return rq;
}

static bool jared_has_work(struct blk_mq_hw_ctx *hctx)
{
	struct jared_hctx_data *jhd = hctx->sched_data;
	int i;
	
	for (i = 0; i < JARED_NUM_DOMAINS; i++) {
		if (!list_empty_careful(&jhd->rqs[i]) ||
			sbitmap_any_bit_set(&jhd->jcq_map[i]))
			return true;
	}
	
	return false;
}

static struct elevator_type jared_sched = {
	.ops.mq = {
		.init_sched = jared_init_sched,
		.init_hctx = jared_init_hctx,
		.exit_hctx = jared_exit_hctx,
		.bio_merge = jared_bio_merge,
		.insert_requests = jared_insert_requests,
		.dispatch_request = jared_dispatch_request,
		.has_work = jared_has_work,
	},
	.uses_mq = true,
	.elevator_name = "jared_bat",
	.elevator_owner = THIS_MODULE,
};

static int __init jared_init(void)
{
	return elv_register(&jared_sched);
}

static void __exit jared_exit(void)
{
	elv_unregister(&jared_sched);
}

module_init(jared_init);
module_exit(jared_exit);

MODULE_AUTHOR("Jared Gillespie");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Jared Batch I/O scheduler");