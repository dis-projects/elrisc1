// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright 2020 RnD Center "ELVEES", JSC
 */

#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#include "risc1-dmabuf.h"
#include "risc1-trace.h"

/* Both frame vector manipulation functions are copied from videobuf2-memops.
 * The reason they are copied is that we didn't want to introduce a dependency
 * on v4l2 and videobuf2 */

static struct frame_vector *create_framevec(unsigned long start,
					    unsigned long length, bool write)
{
	int ret;
	unsigned long first, last;
	unsigned long nr;
	struct frame_vector *vec;
	unsigned int flags = FOLL_FORCE;

	if (write)
		flags |= FOLL_WRITE;

	first = start >> PAGE_SHIFT;
	last = (start + length - 1) >> PAGE_SHIFT;
	nr = last - first + 1;
	vec = frame_vector_create(nr);
	if (!vec) {
		printk(KERN_INFO "create_framevec can't use frame_vector_create\n");
		return ERR_PTR(-ENOMEM);
	}
	ret = get_vaddr_frames(start & PAGE_MASK, nr, flags, vec);
	if (ret < 0) {
		printk(KERN_INFO "create_framevec can't use get_vaddr_frames\n");
		goto out_destroy;
	}
	/* We accept only complete set of PFNs */
	if (ret != nr) {
		ret = -EFAULT;
		goto out_release;
	}
	return vec;
out_release:
	put_vaddr_frames(vec);
out_destroy:
	frame_vector_destroy(vec);
	return ERR_PTR(ret);
}

static void destroy_framevec(struct frame_vector *vec)
{
	put_vaddr_frames(vec);
	frame_vector_destroy(vec);
}

static int risc1_allocate_coherent_memory(struct risc1_buffer_priv *priv)
{
	int rc;

	priv->buf_info.size = ALIGN(priv->buf_info.size, PAGE_SIZE);
	priv->vaddr = dma_alloc_coherent(priv->drv_priv->dev,
					 priv->buf_info.size,
					 &priv->paddr, GFP_KERNEL);
	if (!priv->vaddr) {
		printk(KERN_INFO "risc1_allocate_coherent_memory failed 1\n");
		return -ENOMEM;
	}

	priv->sgt = kmalloc(sizeof(struct sg_table), GFP_KERNEL);
	if (!priv->sgt) {
		printk(KERN_INFO "risc1_allocate_coherent_memory failed 2\n");
		rc = -ENOMEM;
		goto free_coherent;
	}

	rc = sg_alloc_table(priv->sgt, 1, GFP_KERNEL);
	if (rc)
		goto free_sg;
	priv->sgt->sgl[0].length = priv->buf_info.size;
	sg_dma_len(priv->sgt->sgl) = priv->buf_info.size;
	priv->sgt->sgl[0].dma_address = priv->paddr;

	return 0;
free_sg:
	kfree(priv->sgt);
free_coherent:
	dma_free_coherent(priv->drv_priv->dev, priv->buf_info.size,
			  priv->vaddr, priv->paddr);
	return rc;
}

static int risc1_get_sg_from_uptr(struct risc1_buffer_priv *priv)
{
	int ret;

	priv->size = priv->buf_info.size;
	priv->vec = create_framevec(priv->buf_info.p, priv->size, 1);
	if (IS_ERR(priv->vec))
		return PTR_ERR(priv->vec);

	priv->pages = frame_vector_pages(priv->vec);
	if (IS_ERR(priv->pages)) {
		ret = PTR_ERR(priv->pages);
		goto err_pfnvec;
	}
	priv->num_pages = frame_vector_count(priv->vec);

	priv->sgt = kmalloc(sizeof(struct sg_table), GFP_KERNEL);
	if (!priv->sgt) {
		printk(KERN_INFO "risc1_get_sg_from_uptr failed 1\n");
		ret = -ENOMEM;
		goto err_pfnvec;
	}

	ret = sg_alloc_table_from_pages(priv->sgt, priv->pages,
					priv->num_pages,
					offset_in_page(priv->buf_info.p),
					priv->buf_info.size, GFP_KERNEL);
	if (ret)
		goto err_kmalloc;

	return 0;
err_kmalloc:
	kfree(priv->sgt);
err_pfnvec:
	destroy_framevec(priv->vec);
	return ret;
}

static void risc1_put_sg_from_uptr(struct risc1_buffer_priv *priv)
{
	int i = priv->num_pages;

	sg_free_table(priv->sgt);
	while (--i >= 0)
		set_page_dirty_lock(priv->pages[i]);
	destroy_framevec(priv->vec);
}

static void risc1_free_coherent_memory(struct risc1_buffer_priv *priv)
{
	dma_free_coherent(priv->drv_priv->dev, priv->buf_info.size, priv->vaddr,
			  priv->paddr);
	sg_free_table(priv->sgt);
}

static int risc1_allocate_buffer(struct risc1_buffer_priv *priv)
{
	switch (priv->buf_info.type) {
	case RISC1_CACHED_BUFFER_FROM_UPTR:
		return risc1_get_sg_from_uptr(priv);
	case RISC1_NONCACHED_BUFFER:
		return risc1_allocate_coherent_memory(priv);
	default:
		return -EINVAL;
	}
}

void risc1_free_buffer(struct risc1_buffer_priv *priv)
{
	switch (priv->buf_info.type) {
	case RISC1_CACHED_BUFFER_FROM_UPTR:
		return risc1_put_sg_from_uptr(priv);
	case RISC1_NONCACHED_BUFFER:
		return risc1_free_coherent_memory(priv);
	default:
		return;
	}
}

static struct sg_table *
risc1_map_dmabuf(struct dma_buf_attachment *attach,
		    enum dma_data_direction dir)
{
	struct risc1_buffer_priv *priv = attach->dmabuf->priv;
	struct mutex *lock = &attach->dmabuf->lock;
	int rc;

	mutex_lock(lock);
	switch (priv->buf_info.type) {
	case RISC1_CACHED_BUFFER_FROM_UPTR:
		rc = dma_map_sg(attach->dev, priv->sgt->sgl,
				priv->sgt->orig_nents, dir);
		if (rc <= 0)
			goto free_sgt;
		break;
	case RISC1_NONCACHED_BUFFER:
		break;
	default:
		rc = -EINVAL;
		goto free_sgt;
	}

	mutex_unlock(lock);
	return priv->sgt;
free_sgt:
	mutex_unlock(lock);
	return ERR_PTR(rc);
}

static void risc1_unmap_dmabuf(struct dma_buf_attachment *attach,
				  struct sg_table *sgt,
				  enum dma_data_direction dir)
{
	struct risc1_buffer_priv *priv = attach->dmabuf->priv;

	if (priv->buf_info.type == RISC1_CACHED_BUFFER_FROM_UPTR)
		dma_unmap_sg_attrs(attach->dev, sgt->sgl, sgt->orig_nents, dir,
				   DMA_ATTR_SKIP_CPU_SYNC);
}

static void *risc1_dmabuf_map(struct dma_buf *dmabuf,
				 unsigned long page_num)
{
	struct risc1_buffer_priv *priv = dmabuf->priv;

	if (!priv->vaddr)
		priv->vaddr = vm_map_ram(priv->pages, priv->num_pages, -1,
					 PAGE_KERNEL);

	return priv->vaddr ? priv->vaddr + page_num * PAGE_SIZE : NULL;
}

static void risc1_dmabuf_unmap(struct dma_buf *dmabuf,
				  unsigned long page_num,
				  void *vaddr)
{
	(void)dmabuf;
	(void)page_num;
	(void)vaddr;
}

static int risc1_dmabuf_mmap(struct dma_buf *dmabuf,
				struct vm_area_struct *vma)
{
	struct risc1_buffer_priv *priv = dmabuf->priv;
	unsigned long uaddr;
	unsigned long usize;
	int ret, i = 0;

	WARN_ON(vma->vm_pgoff != 0);

	switch (priv->buf_info.type) {
	case RISC1_CACHED_BUFFER_FROM_UPTR:
		do {
			uaddr = vma->vm_start;
			usize = vma->vm_end - vma->vm_start;

			ret = vm_insert_page(vma, uaddr, priv->pages[i++]);
			if (ret) {
				dev_err(priv->drv_priv->dev,
					"Remapping memory, error: %d\n", ret);
				return ret;
			}

			uaddr += PAGE_SIZE;
			usize -= PAGE_SIZE;
		} while (usize > 0);
		break;
	case RISC1_NONCACHED_BUFFER:
		vma->vm_pgoff = 0;
		ret = dma_mmap_coherent(priv->drv_priv->dev, vma, priv->vaddr,
					priv->paddr, priv->buf_info.size);
		if (ret) {
			pr_err("Remapping memory failed, error: %d\n", ret);
			return ret;
		}
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static void risc1_dmabuf_release(struct dma_buf *dmabuf)
{
	struct risc1_buffer_priv *priv = dmabuf->priv;

	switch (priv->buf_info.type) {
	case RISC1_CACHED_BUFFER_FROM_UPTR:
		trace_buffer_release("cached", priv->buf_info.size);
		break;
	case RISC1_NONCACHED_BUFFER:
		trace_buffer_release("noncached", priv->buf_info.size);
		break;
	}

	risc1_free_buffer(priv);
	kfree(priv);
}

static void *risc1_dmabuf_vmap(struct dma_buf *dmabuf)
{
	struct risc1_buffer_priv *priv = dmabuf->priv;
	size_t offset;

	if (!priv->sgt)
		return NULL;
	offset = priv->sgt->sgl[0].offset;

	return risc1_dmabuf_map(dmabuf, 0) + offset;
}

static void risc1_dmabuf_vunmap(struct dma_buf *dmabuf, void *vaddr)
{
	struct risc1_buffer_priv *priv = dmabuf->priv;

	if (priv->buf_info.type == RISC1_NONCACHED_BUFFER)
		return;

	WARN_ON(((unsigned long)vaddr & PAGE_MASK) !=
			(unsigned long)priv->vaddr);

	vm_unmap_ram(priv->vaddr, priv->num_pages);
}

const struct dma_buf_ops risc1_dmabuf_ops = {
	.map_dma_buf = risc1_map_dmabuf,
	.unmap_dma_buf = risc1_unmap_dmabuf,
	.release = risc1_dmabuf_release,
	.map = risc1_dmabuf_map,
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4, 18, 20)
	.map_atomic = risc1_dmabuf_map,
#endif
	.unmap = risc1_dmabuf_unmap,
	.mmap = risc1_dmabuf_mmap,
	.vmap = risc1_dmabuf_vmap,
	.vunmap = risc1_dmabuf_vunmap
};

int risc1_create_buffer(struct risc1_priv *core, void __user *arg)
{
	struct risc1_buf buf_info;
	struct risc1_buffer_priv *priv;
	struct dma_buf *dmabuf;
	int ret;
	DEFINE_DMA_BUF_EXPORT_INFO(exp_info);

	priv = kzalloc(sizeof(struct risc1_buffer_priv), GFP_KERNEL);
	if (!priv) {
		printk(KERN_INFO "risc1_create_buffer failed 1\n");
		return -ENOMEM;
	}

	ret = copy_from_user(&buf_info, arg, sizeof(struct risc1_buf));
	if (ret) {
		ret = -EACCES;
		goto err_bufpriv;
	}
	priv->buf_info = buf_info;
	priv->drv_priv = core; //->drv_priv;

	switch (buf_info.type) {
	case RISC1_CACHED_BUFFER_FROM_UPTR:
		trace_buffer_create("cached", buf_info.size);
		break;
	case RISC1_NONCACHED_BUFFER:
		trace_buffer_create("noncached", buf_info.size);
		break;
	}

	ret = risc1_allocate_buffer(priv);
	if (ret)
		goto err_bufpriv;

	exp_info.ops = &risc1_dmabuf_ops;
	exp_info.size = priv->buf_info.size;
	exp_info.flags = O_RDWR;
	exp_info.priv = priv;

	dmabuf = dma_buf_export(&exp_info);
	if (IS_ERR(dmabuf)) {
		ret = PTR_ERR(dmabuf);
		risc1_free_buffer(priv);
		goto err_bufpriv;
	}
	dmabuf->owner = THIS_MODULE;

	priv->buf_info.dmabuf_fd = dma_buf_fd(dmabuf, 0);
	if (!priv->buf_info.dmabuf_fd) {
		ret = -EINVAL;
		goto dmabuf_put;
	}

	ret = copy_to_user(arg, &priv->buf_info,
			   sizeof(struct risc1_buf));
	if (ret)
		goto dmabuf_put;

	return 0;
dmabuf_put:
	dma_buf_put(dmabuf);
err_bufpriv:
	kfree(priv);
	return ret;
}
