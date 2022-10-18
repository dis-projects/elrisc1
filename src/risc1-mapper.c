// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright 2020 RnD Center "ELVEES", JSC
 */

#include <linux/anon_inodes.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include "risc1-trace.h"
#include "risc1-mapper.h"

const struct file_operations risc1_mapper_ops;

static int risc1_mapper_release(struct inode *inode, struct file *file)
{
	struct userptr_mapper *mapper = file->private_data;

	if (mapper->attach) {
		if (mapper->vaddr)
			dma_buf_vunmap(mapper->attach->dmabuf, mapper->vaddr);
		dma_buf_unmap_attachment(mapper->attach, mapper->sgt,
					 DMA_BIDIRECTIONAL);
		dma_buf_detach(mapper->dmabuf, mapper->attach);
		dma_buf_put(mapper->dmabuf);
	}

	kfree(mapper);
	return 0;
}

const struct file_operations risc1_mapper_ops = {
	.release = risc1_mapper_release,
	.owner = THIS_MODULE,
};

int sync_buffer(struct risc1_priv *core, size_t size, size_t buf_offset,
		struct userptr_mapper *mapper, enum risc1_buf_sync_dir dir)
{
	size_t first_sgl = 0, sgt_head_length = 0;
	size_t sgt_tail_length = 0, nents = 0;
	struct sg_table *sgt;
	struct scatterlist *sg_first, *sg_last;
	size_t remain_length, first_sgl_length, offset;
	dma_addr_t first_sgl_addr;

	if (size == 0) {
		WARN_ON(1);
		return 0;
	}

	if (buf_offset + size > mapper->size) {
		dev_warn(core->dev, "sync_buffer offset %ld size %ld msize %ld\n",
			buf_offset, size, mapper->size);
		WARN_ON(1);
		return -EINVAL;
	}

	trace_buffer_sync(size);

	sgt = mapper->sgt; offset = buf_offset;
	// Looking for start sgl
	for_each_sg(sgt->sgl, sg_first, sgt->orig_nents, first_sgl) {
		sgt_head_length += sg_dma_len(sg_first);
		if (sgt_head_length >= buf_offset)
			break;
		offset -= sg_dma_len(sg_first);
	}

	first_sgl_addr = sg_first->dma_address + offset;
	first_sgl_length = sg_first->length - offset;

	if (first_sgl_length < size) {
		for_each_sg(sg_next(sg_first), sg_last,
			    sgt->orig_nents - first_sgl - 1, nents) {
			sgt_tail_length += sg_dma_len(sg_last);
			if (sgt_tail_length + first_sgl_length >= size)
				break;
		}
		nents++;
	}

	if (nents == 0)
		first_sgl_length = size;
	else {
		remain_length = sg_dma_len(sg_last) + size - first_sgl_length -
					sgt_tail_length;
		WARN_ON(remain_length == 0);
	}

	switch (dir) {
	case RISC1_BUF_SYNC_DIR_TO_CPU:
		// Sync the first sgl
		dma_sync_single_for_cpu(core->dev, first_sgl_addr,
					first_sgl_length, DMA_FROM_DEVICE);
		if (nents == 0)
			break;
		// Sync the last sgl
		dma_sync_single_for_cpu(core->dev,
					sg_last->dma_address,
					remain_length, DMA_FROM_DEVICE);
		if (nents == 1)
			break;
		// Sync the intermediate sgls
		dma_sync_sg_for_cpu(core->dev,
				    sg_next(sg_first), nents - 1,
				    DMA_FROM_DEVICE);
		break;
	case RISC1_BUF_SYNC_DIR_TO_DEVICE:
		// Sync the first sgl
		dma_sync_single_for_device(core->dev, first_sgl_addr,
					   first_sgl_length, DMA_TO_DEVICE);
		if (nents == 0)
			break;
		// Sync the last sgl
		dma_sync_single_for_device(core->dev,
					   sg_last->dma_address,
					   remain_length, DMA_TO_DEVICE);
		if (nents == 1)
			break;
		// Sync the intermediate sgls
		dma_sync_sg_for_device(core->dev,
				       sg_next(sg_first), nents - 1,
				       DMA_TO_DEVICE);
		break;
	default:
		WARN_ON(1);
		break;
	}
	return 0;
}

int risc1_create_mapper(struct risc1_priv *core, void __user *arg)
{
	struct risc1_buf buf_info;
	struct dma_buf *dmabuf;
	struct userptr_mapper *mapper;
	int ret;

	ret = copy_from_user(&buf_info, arg, sizeof(struct risc1_buf));
	if (ret)
		return -EACCES;

	mapper = kzalloc(sizeof(struct userptr_mapper), GFP_KERNEL);
	if (!mapper) {
		printk(KERN_INFO "risc1_create_mapper failed 1\n");
		return -ENOMEM;
	}

	dmabuf = dma_buf_get(buf_info.dmabuf_fd);
	if (IS_ERR(dmabuf)) {
		ret = PTR_ERR(dmabuf);
		goto mapper_free;
	}
	mapper->dmabuf = dmabuf;
	mapper->vaddr = NULL;

	mapper->attach = dma_buf_attach(dmabuf, core->dev);
	if (IS_ERR(mapper->attach)) {
		ret = PTR_ERR(mapper->attach);
		goto dmabuf_put;
	}

	/* Cache flushing inside this function, since ops->map_dma_buf() will
	 * be called */
	mapper->sgt = dma_buf_map_attachment(mapper->attach,
					     DMA_BIDIRECTIONAL);
	if (IS_ERR(mapper->sgt)) {
		ret = PTR_ERR(mapper->sgt);
		goto dmabuf_detach;
	}

	mapper->size = dmabuf->size;
	mapper->offset = mapper->sgt->sgl[0].offset & RISC1_INPAGE_MASK;
	mapper->size_aligned = round_up(mapper->offset + mapper->size,
					RISC1_PAGE_SIZE);

	ret = anon_inode_getfd("risc1_buf_ops", &risc1_mapper_ops,
			       mapper, 0);
	if (ret < 0)
		goto dmabuf_unmap_attachment;
	/* Overriding dmabuf fd to new fd */
	buf_info.mapper_fd = ret;

	ret = copy_to_user(arg, &buf_info, sizeof(struct risc1_buf));
	if (ret) {
		ret = -EACCES;
		goto dmabuf_put_fd;
	}

	return 0;
dmabuf_put_fd:
	put_unused_fd(buf_info.mapper_fd);
dmabuf_unmap_attachment:
	dma_buf_unmap_attachment(mapper->attach, mapper->sgt,
				 DMA_BIDIRECTIONAL);
	mapper->sgt = NULL;
dmabuf_detach:
	dma_buf_detach(dmabuf, mapper->attach);
	mapper->attach = NULL;
dmabuf_put:
	dma_buf_put(dmabuf);
mapper_free:
	kfree(mapper);
	return ret;
}

int risc1_sync_buffer(struct risc1_priv *core, void __user *arg)
{
	struct risc1_buf_sync buf_sync;
	struct fd fd;
	int ret;

	ret = copy_from_user(&buf_sync, arg, sizeof(struct risc1_buf_sync));
	if (ret)
		return -EACCES;

	fd = fdget(buf_sync.mapper_fd);
	if (!fd.file || fd.file->f_op != &risc1_mapper_ops)
		return -EINVAL;

	if (buf_sync.size)
		ret = sync_buffer(core, buf_sync.size, buf_sync.offset,
				  fd.file->private_data, buf_sync.dir);

	fdput(fd);
	return ret;
}
