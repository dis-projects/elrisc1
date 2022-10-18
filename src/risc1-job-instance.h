/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright 2021 RnD Center "ELVEES", JSC
 */
#ifndef _LINUX_RISC1_JOB_INSTANCE_H
#define _LINUX_RISC1_JOB_INSTANCE_H

#include "risc1-mapper.h"
#include "risc1-job.h"

#define E50_CACHE_TIMEOUT_USEC 10000

extern int mod_caches;
extern u32 irq_timeout_msec;
extern const struct file_operations risc1_mapper_ops;
extern const struct file_operations risc1_job_fops;
extern const struct dma_buf_ops risc1_dmabuf_ops;

enum risc1_l2_size {
	L2_CACHE_NONE = 0,
	L2_CACHE_128 = 1,
	L2_CACHE_256 = 2,
	L2_CACHE_512 = 3
};

enum risc1_debug_state {
	RISC1_DBG_RUN,
	RISC1_DBG_INTERRUPTED,
	RISC1_DBG_EXITED,
	RISC1_DBG_LAST,
};

enum risc1_debug_request {
	DBG_REQUEST_NONE,
	DBG_REQUEST_IOCTL,
	DBG_REQUEST_ATTACH,
	DBG_REQUEST_DETACH,
	DBG_READY_TO_PROCESS,
	DBG_PROCESSED,
};

/*
 * Internal job instance data structure
 */
struct risc1_job_inst_desc {
	struct risc1_priv *core;
	struct risc1_buf_desc **args;
	int argc;
	uint32_t *local_args_addr;
	enum risc1_job_instance_state state;
	enum risc1_job_instance_error error;
	uint32_t launcher_vaddr;
	uint32_t entry_point_vaddr;
	uint32_t noncached_regions;
	struct list_head queue_node;
	wait_queue_head_t poll_waitq;
	wait_queue_head_t poll_dbg_waitq;
	wait_queue_head_t irq_waitq;
	wait_queue_head_t syscall_waitq;
	wait_queue_head_t debug_waitq;
	struct work_struct worker;
	enum risc1_l2_size l2_size;
	uint32_t nc_mem_current;
	struct mmu_pool *risc1_pool;
	struct mmu_pool *dma_pool;
#ifndef RISC1_NO_IRQS
	int core_stopped;
#endif
	uint32_t catch_mode;
	int abort;
	int pc_wr;
	int no_ds;
	int do_step;
	int stopped_on_exc;
	int irq_state;
	size_t stack_start;
	void *stack_args;
	size_t stack_args_size;
	uint32_t arg_regs[RISC1_ARG_REGS];
	uint32_t arg_fregs[RISC1_FARG_REGS];
	spinlock_t state_lock;
	struct mutex debug_lock;

	struct file **arg_files;

	struct risc1_message message;
	int syscall_handled;

	int pid;
	char name[255];

	int self_fd;

	int attached;
	enum risc1_debug_state debug_state;
	enum risc1_stop_reason stop_reason;
	enum risc1_debug_request debug_request;
	int debug_result;
	int step_breakpoint;
	u32 bp_value;
	u32 bp_addr;
	u32 bpcnt_rest_plus_1;

	struct file *job_file;
	struct risc1_job_desc *job_desc;
};

int risc1_cancel_job_inst(struct risc1_job_inst_desc *instance);
int risc1_enqueue_job_inst(struct risc1_priv *core, void __user *arg);
int risc1_get_job_inst_count(struct risc1_priv *core, void __user *arg);
int risc1_get_job_inst_list(struct risc1_priv *core, void __user *arg);
void risc1_job_inst_run(struct work_struct *worker);
long risc1_get_job_inst_status(struct risc1_priv *core,
				  void __user *arg);
void *risc1_map_from_users(struct risc1_job_inst_desc *instance,
			      u64 vaddr, struct userptr_mapper **out_mapper,
			      size_t *offset, u64 *user_vaddr_cpu,
			      size_t size);
#endif
