/*
 * EDIT: Added limit_queue_depth to balance sync / async.
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

struct jared_ctx_queue { // Software context
	spinlock_t lock;
	struct list_head rqs; // Requests ready to be sent to HW dispatch queue
} ____cacheline_aligned_in_smp;

struct jared_hctx_data { // Hardware context
	spinlock_t lock;
	struct list_head rqs; // Requests ready to be sent to driver
	struct jared_ctx_queue *jcqs; // Software context queues (could be > 1)
	struct sbitmap jcq_map; // Software contexts with requests ready to be sent
};

struct jared_queue_data {
	/*
	 * Async request percentage, converted to per-word depth for
	 * sbitmap_get_shallow().
	 */
	unsigned int async_depth;
};

static struct jared_queue_data *jared_queue_data_alloc(struct request_queue *q)
{
	struct jared_queue_data *jqd;
	unsigned int shift;
	int ret = -ENOMEM;
	int async_percent;

	jqd = kmalloc_node(sizeof(*jqd), GFP_KERNEL, q->node);
	if (!jqd)
		return ERR_PTR(ret);

	/*
	 * In order to prevent starvation of synchronous requests by a flood of
	 * asynchronous requests, we reserve 25% of requests for synchronous
	 * operations.
	 */
	async_percent = 75;
	
	shift = q->queue_hw_ctx[0]->sched_tags->bitmap_tags.sb.shift;
	jqd->async_depth = (1U << shift) * async_percent / 100U;


	return jqd;
}

static int jared_init_sched(struct request_queue *q, struct elevator_type *e)
{
	struct jared_queue_data *jqd;
	struct elevator_queue *eq;

	eq = elevator_alloc(q, e);
	if (!eq)
		return -ENOMEM;

	jqd = jared_queue_data_alloc(q);
	if (IS_ERR(jqd)) {
		kobject_put(&eq->kobj);
		return PTR_ERR(jqd);
	}
	
	eq->elevator_data = jqd;
	q->elevator = eq;
	
	return 0;
}


static void jared_ctx_queue_init(struct jared_ctx_queue *jcq)
{
	spin_lock_init(&jcq->lock);
	INIT_LIST_HEAD(&jcq->rqs);
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

	if (sbitmap_init_node(&jhd->jcq_map, hctx->nr_ctx,
				  ilog2(8), GFP_KERNEL, hctx->numa_node)) {
		sbitmap_free(&jhd->jcq_map);
		goto err_jcqs;
	}

	spin_lock_init(&jhd->lock);
	INIT_LIST_HEAD(&jhd->rqs);
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

	sbitmap_free(&jhd->jcq_map);
	kfree(jhd->jcqs);
	kfree(hctx->sched_data);
}

static bool jared_bio_merge(struct blk_mq_hw_ctx *hctx, struct bio *bio)
{
	struct jared_hctx_data *jhd = hctx->sched_data;
	struct blk_mq_ctx *ctx = blk_mq_get_ctx(hctx->queue);
	struct jared_ctx_queue *jcq = &jhd->jcqs[ctx->index_hw];
	struct list_head *rqs = &jcq->rqs;
	bool merged;
	
	spin_lock(&jcq->lock);
	merged = blk_mq_bio_list_merge(hctx->queue, rqs, bio);
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
		struct jared_ctx_queue *jcq = &jhd->jcqs[rq->mq_ctx->index_hw];
		struct list_head *head = &jcq->rqs;

		spin_lock(&jcq->lock);
		if (at_head)
			list_move(&rq->queuelist, head);
		else
			list_move_tail(&rq->queuelist, head);
		sbitmap_set_bit(&jhd->jcq_map, rq->mq_ctx->index_hw);
		blk_mq_sched_request_inserted(rq);
		spin_unlock(&jcq->lock);
	}
}

struct flush_jcq_data {
	struct jared_hctx_data *jhd;
	struct list_head *list;
};

static bool flush_busy_jcq(struct sbitmap *sb, unsigned int bitnr, void *data)
{
	struct flush_jcq_data *flush_data = data;
	struct jared_ctx_queue *jcq = &flush_data->jhd->jcqs[bitnr];

	spin_lock(&jcq->lock);
	list_splice_tail_init(&jcq->rqs, flush_data->list);
	sbitmap_clear_bit(sb, bitnr);
	spin_unlock(&jcq->lock);

	return true;
}

static void jared_flush_busy_jcqs(struct jared_hctx_data *jhd, 
				struct list_head *list)
{
    // For each SW queue with pending requests, add to HW dispatch.
	struct flush_jcq_data data = {
		.jhd = jhd,
		.list = list,
	};

	sbitmap_for_each_set(&jhd->jcq_map, flush_busy_jcq, &data);
}

static struct request *jared_dispatch_request(struct blk_mq_hw_ctx *hctx)
{
	struct jared_hctx_data *jhd = hctx->sched_data;
	struct list_head *rqs;
	struct request *rq;
	
	spin_lock(&jhd->lock);
	rqs = &jhd->rqs;

	rq = list_first_entry_or_null(rqs, struct request, queuelist);
	
	// If we already have a flushed request, we submit it.
	if (rq) {
		list_del_init(&rq->queuelist);
		
	// Otherwise, if there are pending requests in the jcqs, flush the jcqs
	} else if (sbitmap_any_bit_set(&jhd->jcq_map)) {
		jared_flush_busy_jcqs(jhd, rqs);
		rq = list_first_entry(rqs, struct request, queuelist);
		list_del_init(&rq->queuelist);;
	}
	
	spin_unlock(&jhd->lock);
	return rq;
}

static bool jared_has_work(struct blk_mq_hw_ctx *hctx)
{
	struct jared_hctx_data *jhd = hctx->sched_data;
	return (!list_empty_careful(&jhd->rqs) || sbitmap_any_bit_set(&jhd->jcq_map));
}

static void jared_limit_depth(unsigned int op, struct blk_mq_alloc_data *data)
{
	/*
	 * We use the scheduler tags as per-hardware queue queueing tokens.
	 * Async requests can be limited at this stage.
	 */
	if (!op_is_sync(op)) {
		struct jared_queue_data *jqd = data->q->elevator->elevator_data;

		data->shallow_depth = jqd->async_depth;
	}
}

static struct elevator_type jared_sched = {
	.ops.mq = {
		.init_sched = jared_init_sched,
		.init_hctx = jared_init_hctx,
		.exit_hctx = jared_exit_hctx,
		.limit_depth = jared_limit_depth,
		.bio_merge = jared_bio_merge,
		.insert_requests = jared_insert_requests,
		.dispatch_request = jared_dispatch_request,
		.has_work = jared_has_work,
	},
	.uses_mq = true,
	.elevator_name = "jared_lqd",
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
MODULE_DESCRIPTION("Jared LQD I/O scheduler");