// SPDX-License-Identifier: GPL-2.0
/*
 * io_uring registered IO slots
 *
 * A slot is a registered (buf, file) tuple bound to a single bio.
 * Submission becomes "fill bi_sector + bi_size, hand to the block layer";
 * everything else (page pinning, queue limit checks, blkcg attach,
 * integrity setup, segment counting) is validated once at registration
 * time and skipped per-IO.
 *
 * Restricted to direct-to-device IO: the registered file must resolve to
 * a raw block_device with no stacking driver in the path (no dm/md, no
 * filesystem). Stacking layers want to clone/remap/split bios and are
 * fundamentally incompatible with a pre-built one.
 */
#include <linux/kernel.h>
#include <linux/file.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/nospec.h>

#include <uapi/linux/io_uring.h>

#include "io_uring.h"
#include "rsrc.h"
#include "filetable.h"
#include "slot.h"

struct io_slot {
	/* The associated buf_node and file_node are pinned by the slot */
	struct io_rsrc_node	*buf_node;
	struct io_rsrc_node	*file_node;

	struct block_device	*bdev;

	/* Set to a valid request when the slot is currently undergoing IO */
	struct io_kiocb		*req;
	u32			id;

	struct bio		bio;
};

struct io_slot_rw {
	struct file	*file;
	u32		slot_id;
	u32		nbytes;
	u64		offset;
	u64		buf_off;
	struct io_slot	*slot;
	struct bio	*bio;
	u8		op;
};

static struct io_slot *io_slot_lookup(struct io_ring_ctx *ctx, unsigned int id)
{
	struct io_slot_table *t = &ctx->slot_table;

	if (id < t->nr_slots) {
		id = array_index_nospec(id, t->nr_slots);
		return t->slots[id];
	}
	return NULL;
}

static bool io_slot_busy(struct io_slot *slot)
{
	return READ_ONCE(slot->req);
}

static void io_free_io_slot(struct io_ring_ctx *ctx, struct io_slot *slot)
{
	WARN_ON_ONCE(io_slot_busy(slot));

	bio_uninit(&slot->bio);
	io_put_rsrc_node(ctx, slot->buf_node);
	io_put_rsrc_node(ctx, slot->file_node);
	kfree(slot);
}

void io_free_io_slots(struct io_ring_ctx *ctx)
{
	struct io_slot_table *t = &ctx->slot_table;
	unsigned int i;

	lockdep_assert_held(&ctx->uring_lock);

	for (i = 0; i < t->nr_slots; i++) {
		struct io_slot *slot = t->slots[i];

		if (!slot)
			continue;
		t->slots[i] = NULL;
		io_free_io_slot(ctx, slot);
	}

	kvfree(t->slots);
	t->slots = NULL;
	t->nr_slots = 0;
}

static int io_slot_submit(struct io_ring_ctx *ctx, struct io_kiocb *req,
			  struct io_slot_rw *rw, unsigned int issue_flags)
{
	struct io_mapped_ubuf *imu;
	struct io_slot *slot;
	struct bio *bio;
	blk_opf_t opf;
	const struct bio_vec *bvec;
	size_t walk;

	io_ring_submit_lock(ctx, issue_flags);

	slot = io_slot_lookup(ctx, rw->slot_id);
	if (!slot)
		goto err;

	imu = slot->buf_node->buf;
	if (rw->buf_off + rw->nbytes > imu->len)
		goto err;

	walk = rw->buf_off;
	bvec = io_imu_offset_to_bvec(imu, &walk);

	if (smp_load_acquire(&slot->req)) {
		io_ring_submit_unlock(ctx, issue_flags);
		req_set_fail(req);
		return -EBUSY;
	}

	smp_store_release(&slot->req, req);
	io_ring_submit_unlock(ctx, issue_flags);

	bio = &slot->bio;

	opf = (__force blk_opf_t) rw->op;
	if (req->flags & REQ_F_IOPOLL)
		opf |= REQ_POLLED;
	bio->bi_opf = opf | REQ_NOMERGE;

	bio->bi_iter.bi_sector = rw->offset >> SECTOR_SHIFT;
	bio->bi_iter.bi_size = rw->nbytes;
	bio->bi_iter.bi_idx = bvec - imu->bvec;
	bio->bi_iter.bi_bvec_done = walk;
	bio->bi_private = NULL;

	rw->slot = slot;
	rw->bio = bio;

	submit_bio_noacct_fast(bio);
	return 0;
err:
	io_ring_submit_unlock(ctx, issue_flags);
	req_set_fail(req);
	return -EINVAL;
}

int io_slot_rw_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_slot_rw *rw = io_kiocb_to_cmd(req, struct io_slot_rw);
	u32 rw_flags;

	/*
	 * Using slot read/write with IOSQE_ASYNC is inefficient and hence a
	 * terrible idea, better make that explicit.
	 */
	if (req->flags & REQ_F_FORCE_ASYNC)
		return -EINVAL;

	if (sqe->file_index || sqe->addr3)
		return -EINVAL;

	rw_flags = READ_ONCE(sqe->rw_flags);
	if (rw_flags & ~IORING_SLOT_RW_WRITE)
		return -EINVAL;

	rw->offset = READ_ONCE(sqe->off);
	if (rw->offset & ((1ULL << SECTOR_SHIFT) - 1))
		return -EINVAL;
	rw->buf_off = READ_ONCE(sqe->addr);
	if (rw->buf_off & ((1ULL << SECTOR_SHIFT) - 1))
		return -EINVAL;

	rw->slot_id = READ_ONCE(sqe->buf_index);
	rw->nbytes = READ_ONCE(sqe->len);
	if (!rw->nbytes)
		return -EINVAL;

	if (rw_flags & IORING_SLOT_RW_WRITE)
		rw->op = REQ_OP_WRITE;
	else
		rw->op = REQ_OP_READ;
	return 0;
}

int io_slot_rw(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_slot_rw *rw = io_kiocb_to_cmd(req, struct io_slot_rw);
	struct io_ring_ctx *ctx = req->ctx;
	int ret;

	ret = io_slot_submit(ctx, req, rw, issue_flags);
	if (ret < 0)
		return ret;

	return IOU_ISSUE_SKIP_COMPLETE;
}

int io_slot_iopoll(struct io_kiocb *req, struct io_comp_batch *iob,
		   unsigned int flags)
{
	struct io_slot_rw *rw = io_kiocb_to_cmd(req, struct io_slot_rw);
	struct io_slot *slot = rw->slot;
	struct kiocb kiocb;
	struct file *file;

	if (unlikely(!slot || !rw->bio))
		return 0;

	file = io_slot_file(slot->file_node);
	kiocb = (struct kiocb){
		.ki_filp	= file,
		.private	= rw->bio,
	};
	return file->f_op->iopoll(&kiocb, iob, flags);
}
