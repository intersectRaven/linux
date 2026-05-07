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
#include <linux/overflow.h>

#include <uapi/linux/io_uring.h>

#include "io_uring.h"
#include "rsrc.h"
#include "filetable.h"
#include "slot.h"

struct io_slot {
	/* The associated buf_node and file_node are pinned by the slot */
	struct io_rsrc_node	*buf_node;
	struct io_rsrc_node	*file_node;

	/* Whole-disk bdev; partition is folded into part_offset / part_size */
	struct block_device	*bdev;
	u64			part_offset;	/* bytes; 0 for whole-disk */
	u64			part_size;	/* bytes; bdev_nr_sectors at register */

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

#define IO_SLOT_TABLE_MAX	USHRT_MAX

static struct io_slot *io_slot_lookup(struct io_ring_ctx *ctx, unsigned int id)
{
	struct io_slot_table *t = &ctx->slot_table;

	if (id < t->nr_slots) {
		id = array_index_nospec(id, t->nr_slots);
		return t->slots[id];
	}
	return NULL;
}

/* Caller holds ctx->uring_lock. */
static int io_slot_table_alloc(struct io_ring_ctx *ctx, struct io_slot *slot,
			       u32 *id_out)
{
	struct io_slot_table *t = &ctx->slot_table;
	struct io_slot **new_slots;
	unsigned int i, new_nr;

	for (i = 0; i < t->nr_slots; i++)
		if (!t->slots[i])
			goto found;

	if (t->nr_slots >= IO_SLOT_TABLE_MAX)
		return -ENFILE;

	new_nr = t->nr_slots ? t->nr_slots * 2 : 8;
	if (new_nr >= IO_SLOT_TABLE_MAX)
		new_nr = IO_SLOT_TABLE_MAX;

	new_slots = kvmalloc_array(new_nr, sizeof(*new_slots),
				   GFP_KERNEL_ACCOUNT | __GFP_ZERO);
	if (!new_slots)
		return -ENOMEM;
	if (t->slots) {
		memcpy(new_slots, t->slots, t->nr_slots * sizeof(*new_slots));
		kvfree(t->slots);
	}
	t->slots = new_slots;
	t->nr_slots = new_nr;
	/* i still points at the first newly-grown entry */
found:
	t->slots[i] = slot;
	*id_out = i;
	return 0;
}

static void io_slot_table_remove(struct io_ring_ctx *ctx, unsigned int id)
{
	struct io_slot_table *t = &ctx->slot_table;

	if (WARN_ON_ONCE(id >= t->nr_slots))
		return;
	t->slots[id] = NULL;
}

static void io_slot_done_inline(struct io_kiocb *req)
{
	struct io_slot_rw *rw = io_kiocb_to_cmd(req, struct io_slot_rw);
	struct io_slot *slot = rw->slot;

	if (rw->bio == &slot->bio)
		WRITE_ONCE(slot->req, NULL);
}

void io_slot_iopoll_done(struct io_kiocb *req)
{
	io_slot_done_inline(req);
}

static void io_slot_task_complete(struct io_tw_req tw_req, io_tw_token_t tw)
{
	io_slot_done_inline(tw_req.req);
	io_req_complete_defer(tw_req.req);
}

static void io_slot_complete(struct io_kiocb *req, int res)
{
	if (req->flags & REQ_F_IOPOLL) {
		req->cqe.res = res;
		smp_store_release(&req->iopoll_completed, 1);
		return;
	}

	io_req_set_res(req, res, 0);
	req->io_task_work.func = io_slot_task_complete;
	io_req_task_work_add(req);
}

static void io_slot_bio_end_io(struct bio *bio)
{
	struct io_slot *slot = container_of(bio, struct io_slot, bio);
	struct io_kiocb *req = READ_ONCE(slot->req);
	struct io_slot_rw *rw = io_kiocb_to_cmd(req, struct io_slot_rw);
	int res = (int) rw->nbytes;

	if (bio->bi_status)
		res = blk_status_to_errno(bio->bi_status);

	/* reset the per-IO mutable bits */
	bio->bi_next = NULL;
	bio->bi_iter.bi_sector = 0;
	bio->bi_iter.bi_size = 0;
	bio->bi_status = 0;

	io_slot_complete(req, res);
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

static struct block_device *io_slot_validate_file(struct file *file)
{
	struct block_device *bdev;

	if (!S_ISBLK(file_inode(file)->i_mode))
		return ERR_PTR(-EINVAL);

	bdev = file_bdev(file);
	if (!bdev)
		return ERR_PTR(-EINVAL);

	if (bdev_test_flag(bdev_whole(bdev), BD_HAS_SUBMIT_BIO))
		return ERR_PTR(-EOPNOTSUPP);

	return bdev;
}

int io_register_io_slot(struct io_ring_ctx *ctx, void __user *arg)
{
	struct io_uring_slot_reg reg;
	struct io_rsrc_node *buf_node, *file_node;
	struct io_mapped_ubuf *imu;
	struct block_device *bdev;
	struct io_slot *slot;
	struct file *file;
	u32 slot_id;
	int ret;

	lockdep_assert_held(&ctx->uring_lock);

	if (copy_from_user(&reg, arg, sizeof(reg)))
		return -EFAULT;
	if (reg.resv)
		return -EINVAL;

	buf_node = io_rsrc_node_lookup(&ctx->buf_table, reg.buf_index);
	if (!buf_node)
		return -EINVAL;
	file_node = io_rsrc_node_lookup(&ctx->file_table.data, reg.file_index);
	if (!file_node)
		return -EINVAL;

	file = io_slot_file(file_node);
	bdev = io_slot_validate_file(file);
	if (IS_ERR(bdev))
		return PTR_ERR(bdev);

	if ((ctx->flags & IORING_SETUP_IOPOLL) &&
	    !(bdev_get_queue(bdev)->limits.features & BLK_FEAT_POLL))
		return -EOPNOTSUPP;

	imu = buf_node->buf;
	if (!imu)
		return -EINVAL;

	if (imu->flags & IO_REGBUF_F_KBUF)
		return -EINVAL;

	slot = kzalloc(sizeof(*slot), GFP_KERNEL_ACCOUNT);
	if (!slot)
		return -ENOMEM;

	/* Pin buf and file for the lifetime of the slot. */
	buf_node->refs++;
	file_node->refs++;

	slot->buf_node = buf_node;
	slot->file_node = file_node;

	slot->bdev = bdev_whole(bdev);
	slot->part_offset = bdev->bd_start_sect << SECTOR_SHIFT;
	slot->part_size = bdev_nr_sectors(bdev) << SECTOR_SHIFT;

	/* Upfront init of the bio */
	bio_init(&slot->bio, slot->bdev, imu->bvec, imu->nr_bvecs, REQ_OP_READ);
	slot->bio.bi_end_io = io_slot_bio_end_io;
	bio_set_flag(&slot->bio, BIO_REGISTERED);

	ret = io_slot_table_alloc(ctx, slot, &slot_id);
	if (!ret) {
		slot->id = slot_id;
		return slot_id;
	}

	io_put_rsrc_node(ctx, file_node);
	io_put_rsrc_node(ctx, buf_node);
	bio_uninit(&slot->bio);
	kfree(slot);
	return ret;
}

int io_unregister_io_slot(struct io_ring_ctx *ctx, void __user *arg)
{
	struct io_slot *slot;
	u32 slot_id;

	lockdep_assert_held(&ctx->uring_lock);

	if (copy_from_user(&slot_id, arg, sizeof(slot_id)))
		return -EFAULT;

	slot = io_slot_lookup(ctx, slot_id);
	if (!slot)
		return -ENOENT;

	/* slot busy */
	if (io_slot_busy(slot))
		return -EBUSY;

	io_slot_table_remove(ctx, slot_id);
	io_free_io_slot(ctx, slot);
	return 0;
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
	u64 end;

	io_ring_submit_lock(ctx, issue_flags);

	slot = io_slot_lookup(ctx, rw->slot_id);
	if (!slot)
		goto err;

	imu = slot->buf_node->buf;
	/*
	 * Check both ends in u64 so a sector-aligned offset close to U64_MAX
	 * can't wrap rw->{buf_off,offset} + rw->nbytes back into a small
	 * value that passes the bounds test.
	 */
	if (check_add_overflow(rw->buf_off, (u64)rw->nbytes, &end) ||
	    end > imu->len)
		goto err;
	if (check_add_overflow(rw->offset, (u64)rw->nbytes, &end) ||
	    end > slot->part_size)
		goto err;
	if (check_add_overflow(slot->part_offset, rw->offset, &end))
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

	bio->bi_iter.bi_sector = (slot->part_offset + rw->offset) >> SECTOR_SHIFT;
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
