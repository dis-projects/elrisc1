/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright 2020-2021 RnD Center "ELVEES", JSC
 */
#ifndef _LINUX_RISC1_JOB_H
#define _LINUX_RISC1_JOB_H

#include "risc1-mapper.h"

struct risc1_buf_desc {
	struct userptr_mapper *mapper;
	enum risc1_job_elf_section_type type;
	enum risc1_job_arg_type arg_type;
	uint64_t vaddr_mmu_risc1;
	int mmu_allocated;
	uint64_t *wr_addr;
};

/**
 * struct risc1_job_desc
 */
struct risc1_job_desc {
	struct risc1_priv *core;

	int num_elf_sections;
	struct risc1_buf_desc **elf;
	struct file **section_files;

	struct risc1_buf_desc *stack;
	struct file *stack_file;
	struct file *risc1_file;

	int hugepages;

	struct page_entry *p_top;
	uint64_t *pt4;
	dma_addr_t pt4_dma_addr;

	struct mmu_pool *risc1_pool;
};

int risc1_create_job(struct file *file, void __user *arg);

#endif
