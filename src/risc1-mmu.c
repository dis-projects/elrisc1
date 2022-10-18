// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright 2020 RnD Center "ELVEES", JSC
 */

#include <linux/slab.h>

#include "risc1-job.h"
#include "risc1-mmu.h"
#include "risc1-trace.h"

extern u32 job_debug;

struct risc1_protected_region {
	u32 base_addr;
	u32 size;
	u32 paddr;
};

static struct risc1_protected_region protected_regions[] = {
{ 0x01900000, 0x2700000, 0x01900000}, // 0x0190_0000,0x03FF_FFFF Registers + CRAM
{ 0x10000000, 0x8000, 0x03b00000 }, // CRAM
{ 0x1efd0000, 0x9000, 0x1efd0000},
};

static size_t MMU_PAGE_SIZES[] = {SZ_4K, SZ_2M, SZ_1G, 512 * SZ_1G};

static inline unsigned long risc1_mmu_alloc_fixed(struct mmu_pool *pool,
						     size_t size,
						     unsigned long address)
{
	struct mmupool_data_fixed data;

	data.offset = address - RISC1_VADDR_START;
	return mmu_pool_alloc_algo(pool, size, mmu_pool_fixed_alloc, &data);
}

static inline void write_pte_entry(uint64_t *pte, dma_addr_t paddr,
				   enum pte_type type)
{
	uint64_t tmp;

	tmp = RISC1_PTE_V_MASK;
	tmp |= (paddr >> RISC1_PAGE_SHIFT) << RISC1_PTE_PADDR_SHIFT;
	tmp |= (type << RISC1_PTE_TYPE_SHIFT) & RISC1_PTE_TYPE_MASK;
	/* FIXME: this is a hack - rf#10482 */
	if (type > PTE_NEXTGL)
		tmp |= RISC1_PTE_D_MASK | RISC1_PTE_R_MASK;
	*pte = tmp;
	pr_debug("pte %px paddr %llx type=%i res=%llx", pte, paddr, type, tmp);
}

static struct page_entry *get_page_entry(struct risc1_priv *core,
					 struct page_entry *p_top,
					 uint64_t vaddr_mmu_risc1,
					 enum risc1_page_size ps,
					 bool is_48bit)
{
	int i, j;
	dma_addr_t paddr;
	struct page *page;
	struct page_entry *p = p_top, *p_cur;
	struct risc1_priv *drv_priv = core;
	uint64_t *pte;
	uint64_t index;
	/* 48-bit addresses don't work with risc1 */
	if (vaddr_mmu_risc1 >> (is_48bit ? 48 : 32)) {
		dev_err(core->dev, "Virtual address 0x%llx out of bounds\n",
			vaddr_mmu_risc1);
		return NULL;
	}
	for (j = VMMU_PAGE_MAX_LEVEL; j > ps; j--) {
		index = (vaddr_mmu_risc1 >> (RISC1_PAGE_SHIFT + j * 9))
				& GENMASK(8, 0);

		p_cur = p + index;
		if (p_cur->next_lvl) {
			p->num_non_zero_ptes += 1;
			p = p_cur->next_lvl;
		}
		else {
			p_cur->next_lvl = kcalloc(RISC1_PTE_ENTRIES,
					      sizeof(struct page_entry),
					      GFP_KERNEL);
			if (!p_cur->next_lvl)
				return NULL;

			page = alloc_pages(GFP_KERNEL | __GFP_ZERO,
					   get_order(RISC1_PAGE_SIZE));
			if (!page)
				goto clean_next_lvl;
			pte = page_address(page);
			paddr = dma_map_single_attrs(drv_priv->dev, pte,
						     RISC1_PAGE_SIZE,
						     DMA_TO_DEVICE,
						     DMA_ATTR_SKIP_CPU_SYNC);
			if (!paddr)
				goto clean_page;
			p_cur->dma_addr = paddr;
			write_pte_entry(p_cur->pte, paddr, PTE_NEXT);
			p->num_non_zero_ptes += 1;
			p = p_cur->next_lvl;

			for (i = 0; i < RISC1_PTE_ENTRIES; i++)
				p[i].pte = &pte[i];
			continue;
clean_page:
			free_pages((unsigned long)pte,
				   get_order(RISC1_PAGE_SIZE));
clean_next_lvl:
			kfree(p_cur->next_lvl);
			p_cur->next_lvl = NULL;
			return NULL;
		}
	}
	/* Increment ptes counter for leaf node. write_pte_entry() will be
	 * called in write_buffer_pages()
	 */
	p->num_non_zero_ptes += 1;
	/* move the pointer to the leaf node rather than leaf page start */
	index = (vaddr_mmu_risc1 >> (RISC1_PAGE_SHIFT + j * 9)) & GENMASK(8, 0);
	p_cur = p + index;
	return p_cur;
}

static int write_fixed_pages(struct risc1_priv *core, int hugepages,
				  struct page_entry *p_top,
				  uint64_t buf_vaddr_mmu_risc1, enum pte_type type,
				  size_t buf_size, dma_addr_t buf_paddr)
{
	size_t page_size;
	enum risc1_page_size ps;
	struct page_entry *p;
	uint64_t vaddr_start_mmu_risc1 = buf_vaddr_mmu_risc1;

	while (buf_size > 0) {
		if (hugepages) {
			if (!(buf_vaddr_mmu_risc1 & (SZ_1G - 1)) &&
					buf_size >= SZ_1G) {
				page_size = SZ_1G;
				ps = RISC1_PAGE_1G;
			} else if (!(buf_vaddr_mmu_risc1 & (SZ_2M - 1)) &&
					buf_size >= SZ_2M) {
				page_size = SZ_2M;
				ps = RISC1_PAGE_2M;
			} else {
				page_size = SZ_4K;
				ps = RISC1_PAGE_4K;
			}
		} else {
			page_size = SZ_4K;
			ps = RISC1_PAGE_4K;
		}
		p = get_page_entry(core, p_top, buf_vaddr_mmu_risc1, ps, 0);
		if (!p) {
			printk(KERN_INFO "write_fixed_pages failed 1\n");
			return -ENOMEM;
		}
		p->offset = buf_vaddr_mmu_risc1 - vaddr_start_mmu_risc1;

		write_pte_entry(p->pte, buf_paddr, type);
		buf_vaddr_mmu_risc1 += page_size;
		buf_paddr += page_size;
		buf_size -= page_size;
	}

	return 0;
}

static int write_buffer_pages(struct risc1_priv *core, int hugepages,
			      struct page_entry *p_top,
			      uint64_t buf_vaddr_mmu_risc1, enum pte_type type,
			      dma_addr_t buf_paddr, size_t buf_size,
			      bool is_48bit, struct userptr_mapper *mapper,
			      uint64_t vaddr_start_mmu_risc1)
{
	size_t page_size;
	enum risc1_page_size ps;
	struct page_entry *p;

	pr_debug("buf_paddr=%llx, vaddr=%llx, size=%lx\n",
		 buf_paddr, buf_vaddr_mmu_risc1, buf_size);
	WARN_ON(buf_paddr & RISC1_INPAGE_MASK);
	WARN_ON(buf_vaddr_mmu_risc1 & RISC1_INPAGE_MASK);
	WARN_ON(buf_size & RISC1_INPAGE_MASK);
	while (buf_size > 0) {
		if (hugepages) {
			if (!(buf_vaddr_mmu_risc1 & (SZ_1G - 1)) &&
					buf_size >= SZ_1G) {
				page_size = SZ_1G;
				ps = RISC1_PAGE_1G;
			} else if (!(buf_vaddr_mmu_risc1 & (SZ_2M - 1)) &&
					buf_size >= SZ_2M) {
				page_size = SZ_2M;
				ps = RISC1_PAGE_2M;
			} else {
				page_size = SZ_4K;
				ps = RISC1_PAGE_4K;
			}
		} else {
			page_size = SZ_4K;
			ps = RISC1_PAGE_4K;
		}
		p = get_page_entry(core, p_top, buf_vaddr_mmu_risc1, ps,
				   is_48bit);
		if (!p) {
			printk(KERN_INFO "write_buffer_pages failed 1\n");
			return -ENOMEM;
		}
		p->mapper = mapper;
		p->offset = buf_vaddr_mmu_risc1 - vaddr_start_mmu_risc1;

		write_pte_entry(p->pte, buf_paddr, type);
		buf_vaddr_mmu_risc1 += page_size;
		buf_paddr += page_size;
		buf_size -= page_size;
	}
	return 0;
}

void sync_elcore_pte_table_for_device(struct risc1_priv *core,
				      struct page_entry *p)
{
	int i;
	struct page_entry *p_cur;
	uint64_t *pte;

	for (i = 0; i < RISC1_PTE_ENTRIES; i++) {
		p_cur = p + i;
		if (p_cur->next_lvl) {
			pte = p_cur->next_lvl->pte;
			sync_elcore_pte_table_for_device(core,
							 p_cur->next_lvl);
			if (p_cur->dma_addr) {
				dma_sync_single_for_device(core->dev,
							   p_cur->dma_addr,
							   RISC1_PAGE_SIZE,
							   DMA_TO_DEVICE);
			}
		}
	}
}

static int mmu_map_buffer(struct risc1_priv *core,
			   struct page_entry *p_top, int hugepages,
			   uint64_t vaddr_mmu_risc1,
			   struct risc1_buf_desc *buf)
{
	/*
	 * the only userptr that specifies the vaddr is ELF, and addresses
	 * for it are reserved in the risc1_pool.
	 */
	/* TODO: sync the memory? create non-cacheable memory? */
	int rc = 0;
	enum pte_type type;
	uint64_t vaddr_start_mmu_risc1;
	int i;
	struct scatterlist *iter;
	struct userptr_mapper *mapper = buf->mapper;
	dma_addr_t dmastart;
	size_t dmalen, dma_offset;

	if (buf->wr_addr)
		*buf->wr_addr = vaddr_mmu_risc1 + mapper->offset;

	switch (buf->type) {
	case RISC1_ELF_SECTION_CODE:
		type = PTE_SVRWXURWX;
		break;
	case RISC1_ELF_SECTION_DATA:
		type = PTE_SVRWXURWX;
		break;
	case RISC1_ELF_SECTION_DATA_CONST:
		type = PTE_SVRWXURWX;
	}
	vaddr_start_mmu_risc1 = vaddr_mmu_risc1;
	for_each_sg(mapper->sgt->sgl, iter, mapper->sgt->nents, i) {
		dma_offset = sg_dma_address(iter) & RISC1_INPAGE_MASK;
		dmastart = sg_dma_address(iter) - dma_offset;
		dmalen = round_up(sg_dma_len(iter) + dma_offset,
				  RISC1_PAGE_SIZE);
		pr_debug("dmastart=%llx len=%lx ofst=%lx\n", dmastart, dmalen,
			 dma_offset);
		rc = write_buffer_pages(core, hugepages, p_top, vaddr_mmu_risc1,
					type, dmastart, dmalen,
					buf->arg_type ==
						RISC1_TYPE_DMA_MEMORY,
					mapper, vaddr_start_mmu_risc1);
		if (rc)
			return rc;
		vaddr_mmu_risc1 += dmalen;
	}
	return rc;
}

static int mmu_map_elf(struct risc1_job_desc *job_desc,
		       struct risc1_buf_desc *elf)
{
	uint64_t vaddr_mmu_risc1;

	if (job_debug)
		printk(KERN_INFO "size_aligned %lx vaddr_mmu_risc1 %llx\n",
			elf->mapper->size_aligned, elf->vaddr_mmu_risc1);

	vaddr_mmu_risc1 = risc1_mmu_alloc_fixed(job_desc->risc1_pool,
						 elf->mapper->size_aligned,
						 elf->vaddr_mmu_risc1);
	if (!vaddr_mmu_risc1) {
		printk(KERN_INFO "mmu_map_elf failed 1\n");
		return -ENOMEM;
	}
	elf->vaddr_mmu_risc1 = vaddr_mmu_risc1;
	elf->mmu_allocated = 1;
	trace_mmu_map(elf);
	return mmu_map_buffer(job_desc->core, job_desc->p_top,
			      job_desc->hugepages, vaddr_mmu_risc1, elf);
}

static int mmu_map_buf(struct risc1_job_inst_desc *job_inst,
		       struct risc1_buf_desc *buf)
{
	uint64_t vaddr_mmu_risc1;
	struct mmu_pool *pool;

	if (buf->arg_type == RISC1_TYPE_DMA_MEMORY)
		pool = job_inst->dma_pool;
	else
		pool = job_inst->risc1_pool;
	if (buf->arg_type == RISC1_TYPE_NC_GLOBAL_MEMORY) {
		vaddr_mmu_risc1 = risc1_mmu_alloc_fixed(
					pool, buf->mapper->size_aligned,
					job_inst->nc_mem_current);
		job_inst->nc_mem_current += buf->mapper->size_aligned;
	} else
		vaddr_mmu_risc1 =
			mmu_pool_alloc(pool, buf->mapper->size_aligned);
	buf->vaddr_mmu_risc1 = vaddr_mmu_risc1;
	if (!vaddr_mmu_risc1) {
		printk(KERN_INFO "mmu_map_buf failed 1\n");
		return -ENOMEM;
	}
	buf->mmu_allocated = 1;
	trace_mmu_map(buf);
	return mmu_map_buffer(job_inst->core, job_inst->job_desc->p_top,
			      job_inst->job_desc->hugepages, vaddr_mmu_risc1,
			      buf);
}

static void mmu_free_ptes_recursive(struct risc1_priv *core,
				    struct page_entry *p)
{
	int i;
	struct page_entry *p_cur;
	uint64_t *pte;

	for (i = 0; i < RISC1_PTE_ENTRIES; i++) {
		p_cur = p + i;
		if (p_cur->next_lvl) {
			pte = p_cur->next_lvl->pte;
			mmu_free_ptes_recursive(core, p_cur->next_lvl);
			if (pte) {
				dma_unmap_single_attrs(core->dev,
						       p_cur->dma_addr,
						       RISC1_PAGE_SIZE,
						       DMA_FROM_DEVICE,
						       DMA_ATTR_SKIP_CPU_SYNC);
				free_pages((unsigned long)pte,
					   get_order(RISC1_PAGE_SIZE));
			}
		}
	}
	kfree(p);
}

static void risc1_mmu_free_fixed(struct risc1_job_desc *job_desc)
{
	int i, size;
	unsigned long addr;

	size = sizeof(protected_regions) / sizeof(struct risc1_protected_region);

	for (i = size - 1; i >= 0; i--) {
		addr = protected_regions[i].base_addr;

		mmu_pool_free(job_desc->risc1_pool, addr,
			      protected_regions[i].size);
	}
}

static int risc1_mmu_fill_fixed(struct risc1_job_desc *job_desc)
{
	int i, size;
	unsigned long addr;

	size = sizeof(protected_regions) / sizeof(struct risc1_protected_region);

	for (i = 0; i < size; ++i) {
		addr = protected_regions[i].base_addr;

		addr = risc1_mmu_alloc_fixed(job_desc->risc1_pool,
						protected_regions[i].size,
						addr);
		if (!addr)
			goto fixed_alloc_err;

		write_fixed_pages(job_desc->core, job_desc->hugepages, job_desc->p_top,
						  protected_regions[i].base_addr, PTE_SVRWXURWX,
						  protected_regions[i].size, protected_regions[i].paddr);
	}
	return 0;

fixed_alloc_err:
	while (i) {
		addr = protected_regions[i - 1].base_addr;

		mmu_pool_free(job_desc->risc1_pool, addr,
			      protected_regions[i - 1].size);
		i--;
	}
	printk(KERN_INFO "risc1_mmu_fill_fixed failed 1\n");
	return -ENOMEM;
}

int risc1_is_addr_pram(struct risc1_job_desc *job_desc,
				 struct risc1_buf_desc *elf)
{
	unsigned long start, end;

	start = risc1_get_paddr(elf->vaddr_mmu_risc1);
	end = start + elf->mapper->size;

	if ((start >= PHYS_INTERNAL_RISC1) &&
		(end < (PHYS_INTERNAL_RISC1 + INTERNAL_RISC1_SIZE))) {
		return 1;
	}
	if ((start >= PHYS_EXTERNAL_RISC1) &&
		(end < (PHYS_EXTERNAL_RISC1 + INTERNAL_RISC1_SIZE))) {
		return 1;
	}
	return 0;
}

static void risc1_prepare_pram(struct risc1_job_desc *job_desc,
				  struct risc1_buf_desc *elf)
{
	struct userptr_mapper *mapper = elf->mapper;

	if (!mapper->vaddr)
		mapper->vaddr = dma_buf_vmap(mapper->attach->dmabuf);
}

void risc1_mmu_free(struct risc1_job_desc *job_desc)
{
	int i;
	struct risc1_buf_desc *elf;

	dma_unmap_single_attrs(job_desc->core->dev,
			       job_desc->pt4_dma_addr,
			       RISC1_PAGE_SIZE, DMA_TO_DEVICE,
			       DMA_ATTR_SKIP_CPU_SYNC);

	mmu_free_ptes_recursive(job_desc->core, job_desc->p_top);
	free_pages((unsigned long)job_desc->pt4, get_order(RISC1_PAGE_SIZE));

	for (i = 0; i < job_desc->num_elf_sections; i++) {
		elf = job_desc->elf[i];
		if (risc1_is_addr_pram(job_desc, elf))
			continue;
		mmu_pool_free(job_desc->risc1_pool, elf->vaddr_mmu_risc1,
			      elf->mapper->size_aligned);
	}
	risc1_mmu_free_fixed(job_desc);
	mmu_pool_free(job_desc->risc1_pool, job_desc->stack->vaddr_mmu_risc1,
		      job_desc->stack->mapper->size_aligned);
}

static int mmu_free_recursive_mapper(struct risc1_priv *core,
				      struct page_entry *p,
				      uint64_t vaddr_mmu_risc1,
				      uint32_t depth,
				      size_t *freed)
{
	struct page_entry *p_cur, *p_next;
	u64 index;
	int i, rc;

	WARN_ON(depth > VMMU_PAGE_MAX_LEVEL);

	index = (vaddr_mmu_risc1 >> (RISC1_PAGE_SHIFT + depth * 9)) & GENMASK(8, 0);
	p_cur = p + index;

	if (p_cur->next_lvl) {
		rc = mmu_free_recursive_mapper(core, p_cur->next_lvl,
					       vaddr_mmu_risc1, depth - 1,
					       freed);

		if (rc == 0) {
			p->num_non_zero_ptes -= 1;
			*p_cur->pte = 0;
			p_cur->next_lvl = NULL;
			p_cur->mapper = NULL;
		}
	} else {
		p->num_non_zero_ptes -= 1;
		*p_cur->pte = 0;
		*freed += MMU_PAGE_SIZES[depth];
		for (i = index + 1; i < RISC1_PTE_ENTRIES; ++i) {
			p_next = p + i;
			if (p_next->mapper != p_cur->mapper)
				break;
			*freed += MMU_PAGE_SIZES[depth];
			p->num_non_zero_ptes -= 1;
			*p_next->pte = 0;
			p_next->mapper = NULL;
		}
		p_cur->mapper = NULL;
	}

	if (p->num_non_zero_ptes == 0) {
		dma_unmap_single_attrs(core->dev, p_cur->dma_addr,
				       RISC1_PAGE_SIZE, DMA_FROM_DEVICE,
				       DMA_ATTR_SKIP_CPU_SYNC);
		free_pages((unsigned long)p->pte, get_order(RISC1_PAGE_SIZE));
		kfree(p);
		return 0;
	}
	return p->num_non_zero_ptes;
}

static void mmu_free_mappers(struct risc1_job_inst_desc *job_inst)
{
	struct page_entry *p_cur = job_inst->job_desc->p_top;
	uint64_t vaddr_mmu_risc1;
	struct risc1_priv *core = job_inst->core;
	struct risc1_buf_desc *buf;
	size_t buf_size, released;
	int i;

	for (i = 0; i < job_inst->argc; i++) {
		buf = job_inst->args[i];
		vaddr_mmu_risc1 = buf->vaddr_mmu_risc1;
		buf_size = buf->mapper->size_aligned;
		while (buf_size > 0) {
			released = 0;
			mmu_free_recursive_mapper(core, p_cur, vaddr_mmu_risc1,
						  VMMU_PAGE_MAX_LEVEL,
						  &released);
			if (!released) {
				WARN_ON(1);
				return;
			}
			vaddr_mmu_risc1 += released;
			buf_size -= released;
		}
	}
}

void risc1_mmu_free_args(struct risc1_job_inst_desc *job_inst)
{
	int i;
	struct risc1_buf_desc *buf;

	mmu_free_mappers(job_inst);

	for (i = 0; i < job_inst->argc; i++) {
		buf = job_inst->args[i];
		if (buf->arg_type == RISC1_TYPE_DMA_MEMORY)
			mmu_pool_free(job_inst->dma_pool,
				      buf->vaddr_mmu_risc1,
				      buf->mapper->size_aligned);
		else if (buf->arg_type == RISC1_TYPE_NC_GLOBAL_MEMORY)
			mmu_pool_free(job_inst->risc1_pool,
				      buf->vaddr_mmu_risc1,
				      buf->mapper->size_aligned);
		else
			mmu_pool_free(job_inst->risc1_pool,
				      buf->vaddr_mmu_risc1,
				      buf->mapper->size_aligned);
	}
}

static int mmu_map_stack(struct risc1_job_desc *job_desc)
{
	uint64_t vaddr_mmu_risc1;
	struct risc1_buf_desc *stack = job_desc->stack;
	struct userptr_mapper *stack_mapper = stack->mapper;

	vaddr_mmu_risc1 = mmu_pool_alloc(job_desc->risc1_pool,
				       stack_mapper->size_aligned);
	stack->vaddr_mmu_risc1 = vaddr_mmu_risc1;
	if (!vaddr_mmu_risc1) {
		printk(KERN_INFO "mmu_map_stack failed 1\n");
		return -ENOMEM;
	}
	stack->mmu_allocated = 1;
	trace_mmu_map(stack);
	return mmu_map_buffer(job_desc->core, job_desc->p_top,
			      job_desc->hugepages, vaddr_mmu_risc1, stack);
}

void risc1_mmu_sync(struct risc1_job_inst_desc *job_inst)
{
	dma_sync_single_for_device(job_inst->core->dev,
				   job_inst->job_desc->pt4_dma_addr,
				   RISC1_PAGE_SIZE, DMA_TO_DEVICE);
	sync_elcore_pte_table_for_device(job_inst->core,
					 job_inst->job_desc->p_top);
}

int risc1_mmu_fill(struct risc1_job_desc *job_desc)
{
	int i, rc = 0;
	uint64_t *pt4;
	struct page_entry *p_top;
	struct page *page;

	page = alloc_pages(GFP_KERNEL | __GFP_ZERO, get_order(RISC1_PAGE_SIZE));
	if (!page) {
		printk(KERN_INFO "risc1_mmu_fill failed 1\n");
		return -ENOMEM;
	}
	pt4 = page_address(page);
	job_desc->pt4 = pt4;
	job_desc->pt4_dma_addr = dma_map_single_attrs(
						job_desc->core->dev,
						pt4, RISC1_PAGE_SIZE,
						DMA_TO_DEVICE,
						DMA_ATTR_SKIP_CPU_SYNC);
	if (!job_desc->pt4_dma_addr) {
		free_pages((unsigned long)pt4, get_order(RISC1_PAGE_SIZE));
		printk(KERN_INFO "risc1_mmu_fill failed 2\n");
		return -ENOMEM;
	}

	p_top = kcalloc(RISC1_PTE_ENTRIES, sizeof(struct page_entry),
			GFP_KERNEL);
	if (!p_top) {
		printk(KERN_INFO "risc1_mmu_fill failed 3\n");
		rc = -ENOMEM;
		goto clean_pt4;
	}
	job_desc->p_top = p_top;
	for (i = 0; i < RISC1_PTE_ENTRIES; i++)
		p_top[i].pte = &pt4[i];

	rc = risc1_mmu_fill_fixed(job_desc);
	if (rc) {
		kfree(p_top);
		goto clean_pt4;
	}

	for (i = 0; i < job_desc->num_elf_sections; i++) {
		if (risc1_is_addr_pram(job_desc, job_desc->elf[i])) {
			risc1_prepare_pram(job_desc, job_desc->elf[i]);
			continue;
		}
		rc = mmu_map_elf(job_desc, job_desc->elf[i]);
		if (rc != 0)
			goto clean_elf;
	}

	rc = mmu_map_stack(job_desc);
	if (rc)
		goto clean_stack;

	return 0;
clean_stack:
	if (job_desc->stack->vaddr_mmu_risc1)
		mmu_pool_free(job_desc->risc1_pool,
			      job_desc->stack->vaddr_mmu_risc1,
			      job_desc->stack->mapper->size_aligned);
clean_elf:
	for (i = 0; i < job_desc->num_elf_sections; i++) {
		if (job_desc->elf[i]->mmu_allocated)
			mmu_pool_free(job_desc->risc1_pool,
				      job_desc->elf[i]->vaddr_mmu_risc1,
				      job_desc->elf[i]->mapper->size_aligned);
	}
	mmu_free_ptes_recursive(job_desc->core, job_desc->p_top);
	risc1_mmu_free_fixed(job_desc);
clean_pt4:
		dma_unmap_single_attrs(job_desc->core->dev,
				       (unsigned long)pt4, RISC1_PAGE_SIZE,
				       DMA_TO_DEVICE, DMA_ATTR_SKIP_CPU_SYNC);
		free_pages((unsigned long)pt4, get_order(RISC1_PAGE_SIZE));
	return rc;
}

int risc1_mmu_fill_args(struct risc1_job_inst_desc *job_inst)
{
	int i, rc = 0;
	struct risc1_buf_desc *arg;
	struct userptr_mapper *mapper;
	uint64_t vaddr_mmu_risc1 = 0;

	for (i = 0; i < job_inst->argc; i++) {
		arg = job_inst->args[i];
		if (arg->arg_type != RISC1_TYPE_NC_GLOBAL_MEMORY)
			continue;
		rc = mmu_map_buf(job_inst, arg);
		if (rc != 0)
			goto clean_args;
	}
	if (job_inst->nc_mem_current) {
		vaddr_mmu_risc1 = risc1_mmu_alloc_fixed(
				job_inst->risc1_pool,
				(1UL << 32) - job_inst->nc_mem_current,
				job_inst->nc_mem_current);
		if (!vaddr_mmu_risc1) {
			printk(KERN_INFO "risc1_mmu_fill_args failed 1\n");
			rc = -ENOMEM;
			goto clean_args;
		}
	}

	for (i = 0; i < job_inst->argc; i++) {
		arg = job_inst->args[i];
		if (arg->arg_type == RISC1_TYPE_NC_GLOBAL_MEMORY)
			continue;
		rc = mmu_map_buf(job_inst, arg);
		if (rc != 0)
			goto clean_args;
	}

	if (job_inst->nc_mem_current && vaddr_mmu_risc1) {
		mmu_pool_free(job_inst->risc1_pool, vaddr_mmu_risc1,
			      (1UL << 32) - job_inst->nc_mem_current);
	}
	return 0;
clean_args:
	for (i = 0; i < job_inst->argc; i++) {
		if (job_inst->args[i]->mmu_allocated) {
			arg = job_inst->args[i];
			mapper = arg->mapper;
			if (arg->arg_type == RISC1_TYPE_DMA_MEMORY)
				mmu_pool_free(job_inst->dma_pool,
					      arg->vaddr_mmu_risc1,
					      mapper->size_aligned);
			else
				mmu_pool_free(job_inst->risc1_pool,
					      arg->vaddr_mmu_risc1,
					      mapper->size_aligned);
		}
	}
	if (job_inst->nc_mem_current && vaddr_mmu_risc1) {
		mmu_pool_free(job_inst->dma_pool, vaddr_mmu_risc1,
			      (1UL << 32) - job_inst->nc_mem_current);
	}
	return rc;
}

static void risc1_vmmulevelout(struct risc1_priv *core, int prefix, struct page_entry *pentry,
	uint64_t start, int shift, int outs)
{
	int i;
	uint64_t ppte = (pentry->pte == NULL) ? 0 : pentry->pte[0];

	if (!(ppte & 1))
		return;

	dev_warn(core->dev, "%*s %p 0x%16llx\n",
			prefix, "", pentry, ppte);

	for (i = 0; i < outs; i++) {
		uint64_t naddr = start + ((uint64_t)i << shift);
		struct page_entry *nentry = pentry + i;
		uint64_t pte;

		if (nentry->pte == NULL) continue;

		pte = nentry->pte[0];
		if (!(pte & 1)) continue;

		if (nentry->next_lvl) {
			risc1_vmmulevelout(core, prefix + 1, nentry->next_lvl,
				naddr, shift - 9, 512);
		} else {
			dev_warn(core->dev, "%*s pte 0x%16llx addr 0x%08x size 0x%08x\n",
				prefix, "", pte, (uint32_t)naddr, 1 << shift);
		}
	}
}

int risc1_mmu_dump(struct risc1_job_inst_desc *job_inst)
{
	struct risc1_priv *core = job_inst->core;
	struct risc1_job_desc *job_desc = job_inst->job_desc;
	struct page_entry *p_top = job_desc->p_top;

	dev_warn(core->dev, "p_top %p\n", p_top);
	risc1_vmmulevelout(core, 0, p_top, 0l, 12 + 3 * 9, 1);

	return 0;
}
