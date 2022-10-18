/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright 2020 RnD Center "ELVEES", JSC
 */
#ifndef _LINUX_RISC1_DMABUF_H
#define _LINUX_RISC1_DMABUF_H

#include <linux/dma-buf.h>
#include <linux/scatterlist.h>

#include "risc1-core.h"

struct risc1_buffer_priv {
	/* common part */
	struct risc1_buf buf_info;
	struct dma_buf dmabuf;
	struct risc1_priv *drv_priv;
	void *vaddr;

	/* noncached part */
	dma_addr_t paddr;

	/* cached part */
	unsigned int num_pages;
	struct page **pages;
	struct frame_vector *vec;
	struct sg_table *sgt;
	size_t size;
};

int risc1_create_buffer(struct risc1_priv *core, void __user *arg);

#endif
