/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright 2020 RnD Center "ELVEES", JSC
 */
#ifndef _LINUX_RISC1_MMU_H
#define _LINUX_RISC1_MMU_H

#include "risc1-job-instance.h"
#include "mmu-alloc.h"

enum risc1_page_size {
	RISC1_PAGE_4K = 0,
	RISC1_PAGE_2M = 1,
	RISC1_PAGE_1G = 2,
	RISC1_PAGE_512G = 3
};

enum pte_type {
	PTE_NEXT = 0,
	PTE_NEXTGL = 1,
	PTE_SVROURX = 2,
	PTE_SVRWURWX = 3,
	PTE_SVROURO = 4,
	PTE_SVRWURW = 5,
	PTE_SVRXURX = 6,
	PTE_SVRWXURWX = 7,
	PTE_SVRO = 8,
	PTE_SVRW = 9,
	PTE_SVRX = 10,
	PTE_SVRWX = 11,
	PTE_SVROGL = 12,
	PTE_SVRWGL = 13,
	PTE_SVRXGL = 14,
	PTE_SVRWXGL = 15
};

struct page_entry {
	uint64_t *pte;
	struct page_entry *next_lvl;
	dma_addr_t dma_addr;
	struct userptr_mapper *mapper;
	size_t offset;
	size_t num_non_zero_ptes;
};

int risc1_mmu_fill(struct risc1_job_desc *job_desc);
void risc1_mmu_free(struct risc1_job_desc *job_desc);
int risc1_mmu_fill_args(struct risc1_job_inst_desc *job_inst);
void risc1_mmu_free_args(struct risc1_job_inst_desc *job_inst);
void risc1_mmu_sync(struct risc1_job_inst_desc *job_inst);
int risc1_is_addr_pram(struct risc1_job_desc *job_desc,
				 struct risc1_buf_desc *elf);
int risc1_mmu_dump(struct risc1_job_inst_desc *job_inst);

#endif
