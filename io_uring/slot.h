/* SPDX-License-Identifier: GPL-2.0 */
#ifndef IOU_SLOT_H
#define IOU_SLOT_H

#include <linux/io_uring_types.h>

#if defined(CONFIG_IO_URING_SLOT_RW)

int io_register_io_slot(struct io_ring_ctx *ctx, void __user *arg);
int io_unregister_io_slot(struct io_ring_ctx *ctx, void __user *arg);
void io_free_io_slots(struct io_ring_ctx *ctx);

int io_slot_rw_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
int io_slot_rw(struct io_kiocb *req, unsigned int issue_flags);
int io_slot_iopoll(struct io_kiocb *req, struct io_comp_batch *iob,
		   unsigned int flags);
void io_slot_iopoll_done(struct io_kiocb *req);

static inline bool io_is_slot_op(const struct io_kiocb *req)
{
	return req->opcode == IORING_OP_SLOT_RW;
}

#else

static inline int io_register_io_slot(struct io_ring_ctx *ctx, void __user *arg)
{
	return -EOPNOTSUPP;
}

static inline int io_unregister_io_slot(struct io_ring_ctx *ctx, void __user *arg)
{
	return -EOPNOTSUPP;
}

static inline void io_free_io_slots(struct io_ring_ctx *ctx)
{
}

static inline bool io_is_slot_op(const struct io_kiocb *req)
{
	return false;
}

static inline int io_slot_iopoll(struct io_kiocb *req, struct io_comp_batch *iob,
				 unsigned int flags)
{
	return -EOPNOTSUPP;
}

static inline void io_slot_iopoll_done(struct io_kiocb *req)
{
}

#endif /* CONFIG_IO_URING_SLOT_RW */

#endif /* IOU_SLOT_H */
