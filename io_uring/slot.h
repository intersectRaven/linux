/* SPDX-License-Identifier: GPL-2.0 */
#ifndef IOU_SLOT_H
#define IOU_SLOT_H

#include <linux/io_uring_types.h>

#if defined(CONFIG_IO_URING_SLOT_RW)

void io_free_io_slots(struct io_ring_ctx *ctx);

int io_slot_rw_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
int io_slot_rw(struct io_kiocb *req, unsigned int issue_flags);
int io_slot_iopoll(struct io_kiocb *req, struct io_comp_batch *iob,
		   unsigned int flags);

static inline bool io_is_slot_op(const struct io_kiocb *req)
{
	return req->opcode == IORING_OP_SLOT_RW;
}

#else

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

#endif /* CONFIG_IO_URING_SLOT_RW */

#endif /* IOU_SLOT_H */
