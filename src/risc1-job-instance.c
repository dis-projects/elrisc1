// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright 2020-2022 RnD Center "ELVEES", JSC
 */

#include <linux/anon_inodes.h>
#include <linux/hash.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/sort.h>
#include <linux/uaccess.h>

#include "risc1-debug.h"
#include "risc1-job-instance.h"
#include "risc1-mmu.h"
#include "risc1-syscall.h"
#include "risc1-trace.h"

extern u32 event_handler_debug;
extern u32 core_debug;
extern u32 risc1_write_regs_debug;
extern u32 risc1_map_from_users_debug;
extern u32 risc1_syscall_debug;
extern u32 exception_debug;
extern u32 job_debug;

#define E50_CACHE_L1	BIT(0)
#define E50_CACHE_L2	BIT(1)

static int risc1_parse_args(struct risc1_job_inst_desc *desc,
			       struct risc1_job_instance *inst,
			       int argc)
{
	struct risc1_priv *core = desc->core;
	struct risc1_job_arg *earg;
	char *stack_cur = desc->stack_args;
	int reg = 0, i, j, ret, larg = 0;
	uint32_t local_addr;
	int buf_fd;
	struct fd fd;

	if (argc) {
		desc->args = kcalloc(argc, sizeof(struct userptr_mapper *),
				     GFP_KERNEL);
		if (!desc->args) {
			printk(KERN_INFO "risc1_parse_args failed 1\n");
			return -ENOMEM;
		}

		desc->arg_files = kcalloc(argc, sizeof(struct file *),
					  GFP_KERNEL);
		if (!desc->arg_files) {
			kfree(desc->args);
			printk(KERN_INFO "risc1_parse_args failed 2\n");
			return -ENOMEM;
		}
	}

	for (i = 0, j = 0; i < inst->argc; i++) {
		void *basic_dest;

		earg = &inst->args[i];
		switch (earg->type) {
		case RISC1_TYPE_BASIC:
			if (reg < RISC1_ARG_REGS && earg->basic.size <= 0x4) {
				basic_dest = &desc->arg_regs[reg];
				reg++;
			} else if (reg < (RISC1_ARG_REGS - 1) && earg->basic.size <= 0x8) {
				reg = (reg + 1) & -2; /* must be even ! */
				basic_dest = &desc->arg_regs[reg];
				reg += 2;
			} else {
				basic_dest = stack_cur;
				stack_cur += round_up(earg->basic.size, 0x4);
			}
			ret = copy_from_user(basic_dest,
					     (void __user *) earg->basic.p,
					     earg->basic.size);
			if (ret != 0) {
				dev_err(core->dev,
					"could not copy buffer, remaining: %x\n",
					ret);
				ret = -EFAULT;
				goto free_args;
			}
			break;
		case RISC1_TYPE_BASIC_FLOAT:
			break;
		case RISC1_TYPE_NC_GLOBAL_MEMORY:
		case RISC1_TYPE_GLOBAL_MEMORY:
		case RISC1_TYPE_DMA_MEMORY:
			if (earg->type == RISC1_TYPE_DMA_MEMORY)
				buf_fd = earg->dma_memory.mapper_fd;
			else
				buf_fd = earg->global_memory.mapper_fd;

			fd = fdget(buf_fd);
			if (!fd.file ||
				fd.file->f_op != &risc1_mapper_ops) {
				ret = -EINVAL;
				goto free_args;
			}

			desc->args[j] =
				kzalloc(sizeof(struct risc1_buf_desc),
					GFP_KERNEL);
			if (!desc->args[j]) {
				printk(KERN_INFO "risc1_parse_args failed 3\n");
				ret = -ENOMEM;
				goto free_args;
			}
			desc->arg_files[j] = get_file(fd.file);
			desc->args[j]->mapper = fd.file->private_data;
			desc->args[j]->type = earg->type;
			fdput(fd);

			/*
			 * Since the MMU is not yet initialized, and therefore
			 * the virtual addresses are unknown, this pointer is
			 * set up to be written once the MMU is filled.
			 */
			if (reg < RISC1_ARG_REGS) {
				desc->args[j]->wr_addr = (uint64_t *)
							&desc->arg_regs[reg];
				reg++;
			} else {
				desc->args[j]->wr_addr = (uint64_t *)stack_cur;
				stack_cur += 0x8;
			}
			desc->args[j]->arg_type = earg->type;
			j++;
			break;
		case RISC1_TYPE_LOCAL_MEMORY:
			local_addr = desc->local_args_addr[larg];
			if (reg < RISC1_ARG_REGS) {
				desc->arg_regs[reg] = local_addr;
				reg++;
			} else {
				*(uint32_t *)stack_cur = local_addr;
				stack_cur += 0x8;
			}
			larg++;
			break;
		}
	}
	return 0;
free_args:
	if (argc) {
		for (i = 0; i < desc->argc; ++i) {
			if (desc->arg_files[i])
				fput(desc->arg_files[i]);
		}
		kfree(desc->arg_files);
		for (i = 0; i < desc->argc; ++i)
			kfree(desc->args[i]);
		kfree(desc->args);
	}
	return ret;
}

struct risc1_job_arg_sort {
	struct risc1_job_arg arg;
	int origin_index;
};

static int local_mem_compare(const void *a, const void *b)
{
	const struct risc1_job_arg_sort *arg1 = a, *arg2 = b;

	return arg1->arg.local_memory.size - arg2->arg.local_memory.size;
}

static int find_args_by_closest_total_size(struct risc1_job_arg_sort *args,
					   const int argc,
					   const int contiguous_memsize,
					   int *are_args_in_lowbank)
{
	int curr_sum, max_sum = 0, start = 0, i = 0;
	int *are_args_in_lowbank_tmp;

	are_args_in_lowbank_tmp = kcalloc(argc, sizeof(int), GFP_KERNEL);
	if (!are_args_in_lowbank_tmp) {
		printk(KERN_INFO "find_args_by_closest_total_size failed 1\n");
		return -ENOMEM;
	}

	curr_sum = args[0].arg.local_memory.size;

	// To find max_sum less than contiguous_memsize
	for (i = 1; i < argc; i++) {

		// Update max_sum if it becomes greater than curr_sum
		if (max_sum < curr_sum && curr_sum <= contiguous_memsize) {
			max_sum = curr_sum;
			memcpy(are_args_in_lowbank, are_args_in_lowbank_tmp,
			       sizeof(int) * argc);
		}

		// If curr_sum becomes greater than
		// contiguous_memsize subtract starting elements of array
		while (curr_sum + args[i].arg.local_memory.size >
				contiguous_memsize && start < i) {
			curr_sum -= args[start].arg.local_memory.size;
			// Clear index of this element from bit array
			are_args_in_lowbank_tmp[args[start].origin_index] = 0;
			start++;
		}

		// Add elements to curr_sum
		curr_sum += args[i].arg.local_memory.size;
		// Set index of this element to bit array
		are_args_in_lowbank_tmp[args[i].origin_index] = 1;
	}

	//Adding an extra check for last subarray
	if (max_sum < curr_sum && curr_sum <= contiguous_memsize) {
		max_sum = curr_sum;
		memcpy(are_args_in_lowbank, are_args_in_lowbank_tmp,
		       sizeof(int) * argc);
	}

	kfree(are_args_in_lowbank_tmp);
	return max_sum;
}

static int try_arrange_local_args(struct risc1_job_inst_desc *desc,
				  struct risc1_job_instance *inst,
				  int largc, uint32_t args_size,
				  uint32_t localmem_required,
				  struct risc1_job_arg_sort *sort_earg)
{
#if 0 // TODO: fix it
	uint32_t localmem = PHYS_INTERNAL_INTERLEAVE_DSP;
	uint32_t localmem_high = PHYS_INTERNAL_INTERLEAVE_DSP + 0x40000;
	int i, ret, *are_args_in_lowbank = NULL;

	if (localmem_required == SZ_512K) {
		for (i = 0, largc = 0; i < inst->argc; ++i) {
			if (inst->args[i].type != RISC1_TYPE_LOCAL_MEMORY)
				continue;
			desc->local_args_addr[largc] = localmem;
			localmem += inst->args[i].local_memory.size;
			largc++;
		}
		return 0;
	}

	are_args_in_lowbank = kcalloc(largc, sizeof(int), GFP_KERNEL);
	if (!are_args_in_lowbank)
		return -ENOMEM;

	ret = find_args_by_closest_total_size(sort_earg, largc,
					      localmem_required / 2,
					      are_args_in_lowbank);
	if (ret < 0) {
		kfree(are_args_in_lowbank);
		return ret;
	}

	args_size = args_size - ret;
	if ((ret > localmem_required / 2) ||
			(args_size  > localmem_required / 2)) {
		kfree(are_args_in_lowbank);
		return -EINVAL;
	}

	for (i = 0, largc = 0; i < inst->argc; ++i) {
		if (inst->args[i].type != RISC1_TYPE_LOCAL_MEMORY)
			continue;
		if (are_args_in_lowbank[largc]) {
			desc->local_args_addr[largc] = localmem;
			localmem += inst->args[i].local_memory.size;
		} else {
			desc->local_args_addr[largc] = localmem_high;
			localmem_high += inst->args[i].local_memory.size;
		}
		largc++;
	}

	kfree(are_args_in_lowbank);
#endif
	return 0;
}

static int arrange_local_args(struct risc1_job_inst_desc *desc,
			      struct risc1_job_instance *inst,
			      int largc, uint32_t localmem_arg_size,
			      uint32_t localmem_required)
{
	int i, ret;
	struct risc1_job_arg_sort *sort_earg;

	// create copy of job local args for sorting
	sort_earg = kcalloc(largc, sizeof(struct risc1_job_arg_sort),
			     GFP_KERNEL);
	if (!sort_earg) {
		printk(KERN_INFO "arrange_local_args failed 1\n");
		return -ENOMEM;
	}

	for (i = 0, largc = 0; i < inst->argc; ++i) {
		if (inst->args[i].type != RISC1_TYPE_LOCAL_MEMORY)
			continue;
		memcpy(&sort_earg[largc].arg, &inst->args[i],
		       sizeof(struct risc1_job_arg));
		sort_earg[largc].origin_index = largc;
		largc++;
	}

	/* sort ascending arg size */
	sort(sort_earg, largc, sizeof(struct risc1_job_arg_sort),
	     &local_mem_compare, NULL);

	do {
		ret = try_arrange_local_args(desc, inst, largc,
					     localmem_arg_size,
					     localmem_required, sort_earg);
		if (ret == -ENOMEM)
			break;
		if (ret) {
			localmem_required += SZ_128K;
			desc->l2_size--;
		}
	} while (ret);

	kfree(sort_earg);
	return ret;
}

static int risc1_job_inst_release(struct inode *inode, struct file *file)
{
	int i;
	struct risc1_job_inst_desc *desc = file->private_data;

	risc1_cancel_job_inst(desc);
	for (i = 0; i < desc->argc; ++i)
		fput(desc->arg_files[i]);
	fput(desc->job_file);
	if (desc->dma_pool)
		mmu_pool_destroy(desc->dma_pool);
	kfree(desc->arg_files);
	kfree(desc->local_args_addr);
	for (i = 0; i < desc->argc; ++i)
		kfree(desc->args[i]);
	kfree(desc->args);
	kfree(desc->stack_args);
	kfree(desc);
	return 0;
}

static unsigned int risc1_job_inst_poll(struct file *file, poll_table *wait)
{
	struct risc1_job_inst_desc *desc = file->private_data;

	poll_wait(file, &desc->poll_waitq, wait);
	/* The spec doesn't suggest which events the job waits for, so
	 * we'll signal every IO event */
	if (desc->state > RISC1_JOB_STATUS_SYSCALL)
		return POLLIN | POLLRDNORM | POLLOUT | POLLWRNORM;

	// Send event if syscall data is ready
	if ((desc->state == RISC1_JOB_STATUS_SYSCALL) &&
	     (desc->message.type == RISC1_MESSAGE_SYSCALL))
		return POLLIN | POLLRDNORM | POLLOUT | POLLWRNORM;
	return 0;
}

static ssize_t risc1_job_inst_read(struct file *file, char __user *buf,
				      size_t size, loff_t *ppos)
{
	struct risc1_job_inst_desc *desc =
		(struct risc1_job_inst_desc *)file->private_data;

	WARN_ON(size != sizeof(struct risc1_message));

	if (desc->state != RISC1_JOB_STATUS_SYSCALL)
		return -EINVAL;

	return sizeof(struct risc1_message) -
			copy_to_user(buf, &desc->message,
				     sizeof(struct risc1_message));
}

static ssize_t risc1_job_inst_write(struct file *file,
				       const char __user *buf, size_t size,
				       loff_t *ppos)
{
	struct risc1_job_inst_desc *desc =
		(struct risc1_job_inst_desc *)file->private_data;
	struct risc1_message message;
	ssize_t ret;

	if (desc->state != RISC1_JOB_STATUS_SYSCALL)
		return -EINVAL;

	WARN_ON(size != sizeof(struct risc1_message));

	ret = copy_from_user(&message, buf, sizeof(struct risc1_message));
	if (ret)
		return ret;

	if (risc1_syscall_debug)
		dev_warn(desc->core->dev, "risc1_job_inst_write\n");

	if (message.type == RISC1_MESSAGE_SYSCALL_REPLY) {
		desc->syscall_handled = 1;
		memcpy(&desc->message, &message,
		       sizeof(struct risc1_message));
		wake_up(&desc->syscall_waitq);
	} else
		WARN_ON(1);

	return sizeof(struct risc1_message);
}

static const struct file_operations risc1_job_inst_fops = {
	.release = risc1_job_inst_release,
	.poll = risc1_job_inst_poll,
	.read = risc1_job_inst_read,
	.write = risc1_job_inst_write
};

int risc1_enqueue_job_inst(struct risc1_priv *core, void __user *arg)
{
	struct risc1_job_inst_desc *desc;
	struct risc1_job_arg *earg;
	struct risc1_job_instance *inst;
	struct risc1_job_inst_dbg_desc *dbg_desc;
	int ret, i, free_regs, free_fregs, argc = 0, largc = 0;
	size_t stack_args, local_mem, localmem_required, dma_mem, nc_mem;
	unsigned long flags;
	struct fd fd;

	if (job_debug)
		dev_warn(core->dev, "risc1_enqueue_job_inst\n");

	free_regs = RISC1_ARG_REGS;
	free_fregs = RISC1_FARG_REGS;
	stack_args = 0;
	local_mem = 0;
	largc = 0;
	nc_mem = 0;
	dma_mem = 0;

	desc = kzalloc(sizeof(struct risc1_job_inst_desc), GFP_KERNEL);
	inst = kzalloc(sizeof(struct risc1_job_instance), GFP_KERNEL);
	if (!desc || !inst) {
		printk(KERN_INFO "risc1_enqueue_job_inst failed 1\n");
		return -ENOMEM;
	}

	ret = copy_from_user(inst, arg, sizeof(struct risc1_job_instance));
	if (ret) {
		ret = -EACCES;
		goto clean_kfree;
	}
	fd = fdget(inst->job_fd);
	if (!fd.file || fd.file->f_op != &risc1_job_fops) {
		ret = -EBADFD;
		WARN_ON(1);
		goto job_fdput;
	}
	desc->job_file = get_file(fd.file);
	desc->job_desc = fd.file->private_data;
	desc->risc1_pool = desc->job_desc->risc1_pool;
	desc->core = core;
	desc->catch_mode = inst->catch_mode;
	fdput(fd);

	desc->pid = task_pid_nr(current);
	strcpy(desc->name, inst->name);

	spin_lock_init(&desc->state_lock);
	mutex_init(&desc->debug_lock);

	for (i = 0; i < inst->argc; i++) {
		earg = &inst->args[i];
		switch (earg->type) {
		case RISC1_TYPE_BASIC: // TODO: fix it
			if (free_regs > 0  && earg->basic.size <= 0x4)
				free_regs--;
			else
				stack_args += round_up(earg->basic.size, 4);
			break;
		case RISC1_TYPE_BASIC_FLOAT: // TODO: fix it
			if (free_fregs > 0  && earg->basic.size <= 0x4)
				free_fregs--;
			else
				stack_args += round_up(earg->basic.size, 4);
			break;
			break;
		case RISC1_TYPE_DMA_MEMORY:
		case RISC1_TYPE_GLOBAL_MEMORY:
		case RISC1_TYPE_NC_GLOBAL_MEMORY:
			argc++;
			if (free_regs > 0)
				free_regs--;
			else
				stack_args += 8;
			break;
		case RISC1_TYPE_LOCAL_MEMORY:
			local_mem += earg->local_memory.size;
			if (free_regs > 0)
				free_regs--;
			else
				stack_args += 8;
			largc++;
			break;
		}
	}

	/* TODO: users should be able to specify stack size */
	if (local_mem == 0) {
		desc->l2_size = L2_CACHE_512;
		localmem_required = 0;
	} else if (local_mem <= SZ_512K - SZ_256K) {
		desc->l2_size = L2_CACHE_256;
		localmem_required = SZ_256K;
	} else if (local_mem <= SZ_512K - SZ_128K) {
		desc->l2_size = L2_CACHE_128;
		localmem_required = SZ_512K - SZ_128K;
	} else if (local_mem <= SZ_512K) {
		desc->l2_size = L2_CACHE_NONE;
		localmem_required = SZ_512K;
	} else {
		dev_err(core->dev, "Not enough local memory for this job\n");
		ret = -ENOMEM;
		goto job_fdput;
	}

	desc->stack_start = desc->job_desc->stack->mapper->size - stack_args;
	desc->stack_args_size = stack_args;
	desc->argc = argc;

	if (stack_args > desc->job_desc->stack->mapper->size) {
		dev_err(core->dev, "Stack overflow: too many arguments\n");
		ret = -ENOMEM;
		goto job_fdput;
	}

	if (desc->stack_args_size) {
		desc->stack_args = kzalloc(desc->stack_args_size, GFP_KERNEL);
		if (!desc->stack_args) {
			dev_err(core->dev, "No stack_args\n");
			ret = -ENOMEM;
			goto job_fdput;
		}
	}

	if (largc) {
		desc->local_args_addr = kcalloc(largc, sizeof(uint32_t),
						GFP_KERNEL);
		if (!desc->local_args_addr)
			goto clean_stackargs;

		ret = arrange_local_args(desc, inst, largc, local_mem,
					 localmem_required);
		if (ret)
			goto clean_local_args;
	}

	ret = risc1_parse_args(desc, inst, argc);
	if (ret) {
		dev_err(core->dev, "Failed to parse arguments\n");
		goto clean_local_args;
	}

	for (i = 0; i < desc->argc; i++) {
		if (desc->args[i]->arg_type == RISC1_TYPE_DMA_MEMORY)
			dma_mem += desc->args[i]->mapper->size_aligned;
		else if (desc->args[i]->arg_type ==
				RISC1_TYPE_NC_GLOBAL_MEMORY)
			nc_mem += desc->args[i]->mapper->size_aligned;
	}

	if (nc_mem) {
		i = 31 - (nc_mem - 1) / (128 * SZ_1M);
		desc->noncached_regions = GENMASK(31, i);
		desc->nc_mem_current = (1UL << 32) - round_up(nc_mem, SZ_128M);
	}

	desc->launcher_vaddr = inst->launcher_virtual_address;
	desc->entry_point_vaddr = inst->entry_point_virtual_address;

	init_waitqueue_head(&desc->poll_waitq);
	init_waitqueue_head(&desc->poll_dbg_waitq);
	init_waitqueue_head(&desc->irq_waitq);
	init_waitqueue_head(&desc->syscall_waitq);
	init_waitqueue_head(&desc->debug_waitq);

	if (dma_mem) {
		desc->dma_pool = mmu_pool_create(ilog2(RISC1_PAGE_SIZE), -1);
		if (IS_ERR(desc->dma_pool)) {
			ret = PTR_ERR(desc->dma_pool);
			goto clean_args;
		}

		ret = mmu_pool_add(desc->dma_pool, (1ULL << 32), dma_mem, -1);
		if (ret) {
			dev_err(core->dev, "Failed to mmu_pool_add 0\n");
			goto clean_dmapool;
		}
	}

	ret = anon_inode_getfd("risc1jobinstance",
			       &risc1_job_inst_fops, desc, O_RDWR);
	if (ret < 0)
		goto clean_dmapool;
	desc->self_fd = inst->job_instance_fd = ret;

	if (inst->debug_enable) {
		dbg_desc = kzalloc(sizeof(struct risc1_job_inst_dbg_desc),
				   GFP_KERNEL);
		desc->debug_state = RISC1_DBG_INTERRUPTED;
		desc->stop_reason = RISC1_STOP_REASON_DBG_INTERRUPT;
		desc->attached = 1;
		ret = export_dbg_fd(dbg_desc);
		if (ret < 0) {
			kfree(dbg_desc);
			goto clean_fd;
		}
		inst->debug_fd = ret;
		dbg_desc->inst = desc;
		fd = fdget(desc->self_fd);
		dbg_desc->inst_file = get_file(fd.file);
		fdput(fd);
	}

	ret = copy_to_user(arg, inst, sizeof(struct risc1_job_instance));
	if (ret) {
		ret = -EACCES;
		goto clean_debug_fd;
	}

	INIT_WORK(&desc->worker, risc1_job_inst_run);
	spin_lock_irqsave(&core->queue_lock, flags);
	list_add_tail(&desc->queue_node, &core->job_queue);
	queue_work(core->work_q, &desc->worker);
	spin_unlock_irqrestore(&core->queue_lock, flags);
	kfree(inst);
	return 0;
clean_debug_fd:
	if (inst->debug_enable) {
		put_unused_fd(inst->debug_fd);
		kfree(dbg_desc);
	}
clean_fd:
	put_unused_fd(inst->job_instance_fd);
clean_dmapool:
	if (desc->dma_pool)
		mmu_pool_destroy(desc->dma_pool);
clean_args:
	for (i = 0; i < desc->argc; ++i)
		fput(desc->arg_files[i]);
	kfree(desc->arg_files);
	for (i = 0; i < desc->argc; ++i)
		kfree(desc->args[i]);
	kfree(desc->args);
clean_local_args:
	kfree(desc->local_args_addr);
clean_stackargs:
	kfree(desc->stack_args);
job_fdput:
	fput(desc->job_file);
clean_kfree:
	kfree(desc);
	kfree(inst);
	dev_err(core->dev, "queueing failed %d\n", ret);
	return ret;
}

int risc1_cancel_job_inst(struct risc1_job_inst_desc *desc)
{
	unsigned long flags;

	if (job_debug)
		dev_warn(desc->core->dev, "risc1_cancel_job_inst\n");

	desc->abort = 1;
#ifndef RISC1_NO_IRQS
	wake_up(&desc->irq_waitq);
#endif
	wake_up(&desc->syscall_waitq);
	if (cancel_work_sync(&desc->worker)) {
		spin_lock_irqsave(&desc->core->queue_lock, flags);
		list_del(&desc->queue_node);
		spin_unlock_irqrestore(&desc->core->queue_lock, flags);
		desc->debug_result = -EINVAL;
			desc->debug_state = RISC1_DBG_EXITED;
		wake_up(&desc->debug_waitq);
	}

	return 0;
}

static void get_job_inst_results(struct risc1_job_inst_desc *desc)
{
	unsigned long flags;
	struct risc1_priv *core = desc->core;

	if (job_debug)
		dev_warn(desc->core->dev, "get_job_inst_results\n");

	spin_lock_irqsave(&desc->state_lock, flags);
#if 1 /* TODO: fix it */
	desc->error = RISC1_JOB_STATUS_SUCCESS;
#else
	if (irq_status & DQSTR_ERRS) {
		desc->error = RISC1_JOB_STATUS_ERROR;
		dev_warn(core->dev, "Job failed with DQSTR: %x", irq_status);
		print_dump(core, RISC1_DUMP_MAIN);
	} else if ((irq_status & DQSTR_STP) == DQSTR_STP)
		desc->error = RISC1_JOB_STATUS_SUCCESS;
	else {
		print_dump(core, RISC1_DUMP_MAIN);
		WARN_ON(1);
	}
#endif
	spin_unlock_irqrestore(&desc->state_lock, flags);
	if (job_debug)
		print_dump(core, RISC1_DUMP_MAIN);
}

static unsigned int get_cache_prefetch_boundary(void)
{
	/* TODO: Fix for different pages */
	return L1_CTRL_PFB_4K;
}

static void caches_setup(struct risc1_job_inst_desc *desc)
{
	struct risc1_priv *core = desc->core;

	if(job_debug)
		dev_warn(core->dev, "caches_setup\n");
}

static void caches_inval(struct risc1_job_inst_desc *desc)
{
	if(job_debug)
		dev_warn(desc->core->dev, "caches_inval\n");

	iowrite32(1 | (1 << 1) | (1 << 12)| (1 << 14), desc->core->regs + (RISC1_CSR + 0 - RISC1_BASE));
}

static void caches_flush_after_run(struct risc1_job_inst_desc *desc)
{
	if(job_debug)
		dev_warn(desc->core->dev, "caches_flush_after_run\n");

#if 0 // TODO: fix it
	uint32_t i, reg_tmp;
	struct risc1_priv *core = desc->core;

	/* Stop prefetchers */
	reg_tmp = risc1_read(core, DSP_CTRL);
	reg_tmp &= ~(CTRL_PF | CTRL_DOPF);
	risc1_write(reg_tmp, core, DSP_CTRL);

	risc1_write(DSP_INVCTRL_FLUSH_ALL, core, DSP_INVCTRL);
	while (risc1_read(core, DSP_MBARREG) != 0) {
		for (i = 0; i < VMMU_TLBS; ++i) {
			reg_tmp = risc1_read(core, VMMU_TLB_CTRL +
							i * sizeof(u32));
			reg_tmp |= VMMU_TLB_CTRL_DUMMY;
			risc1_write(reg_tmp, core, VMMU_TLB_CTRL +
						i * sizeof(u32));
		}
	}
#endif
}

static void risc1_write_regs(struct risc1_job_inst_desc *desc)
{
	struct risc1_priv *core = desc->core;
	struct risc1_priv *drv_priv = core;
	struct risc1_buf_desc *stack = desc->job_desc->stack;
	struct risc1_job_desc *job_desc = desc->job_desc;
	int i;
	uint32_t stack_wr = stack->vaddr_mmu_risc1 + desc->stack_start;
	uint32_t entry;
	uint32_t value;

	if (risc1_write_regs_debug)
		dev_warn(core->dev, "risc1_write_regs 0\n");

	/* Clear NMI !!! */
	iowrite32(1, drv_priv->regs + (RISC1_URB + SDR_RISC1_SOFT_NMI_CLEAR - RISC1_BASE));

	for (i = 0; i < RISC1_ARG_REGS; i++) {
		/* a0-a3 - $4-$7 */
		risc1_write_reg(desc->arg_regs[i], drv_priv, RISC1_ONCD_GRFCPU, i + 4);
	}

	if (risc1_write_regs_debug)
		dev_warn(core->dev, "risc1_write_regs 1\n");

	for (i = 0; i < RISC1_FARG_REGS; i++) {
		/* $fp12 - $fp15 */
		risc1_write_reg(desc->arg_fregs[i], drv_priv, RISC1_ONCD_GRFFPU, i + 12);
	}

	if (risc1_write_regs_debug)
		dev_warn(core->dev, "risc1_write_regs 2\n");

	risc1_write_reg(stack_wr, drv_priv, RISC1_ONCD_GRFCPU, 29);

	if (risc1_write_regs_debug)
		dev_warn(core->dev, "risc1_write_regs 3\n");

	memcpy(stack->mapper->vaddr + desc->stack_start, desc->stack_args,
	       desc->stack_args_size);

	if (risc1_write_regs_debug)
		dev_warn(core->dev, "risc1_write_regs 4\n");

	if (desc->stack_args_size)
		sync_buffer(core, desc->stack_args_size, desc->stack_start,
			    stack->mapper, RISC1_BUF_SYNC_DIR_TO_DEVICE);

	// Clean BEV and ERL
	value = risc1_read_reg(drv_priv, RISC1_ONCD_GCP0, 12);
	value &= ~(( 1 << 22) | (1 << 2));
	risc1_write_reg(value, drv_priv, RISC1_ONCD_GCP0, 12);

	if (risc1_write_regs_debug)
		dev_warn(core->dev, "risc1_write_regs 5\n");

	entry = desc->launcher_vaddr ? desc->launcher_vaddr : desc->entry_point_vaddr;

	if (risc1_write_regs_debug)
		dev_warn(core->dev, "risc1_write_regs entry : %08x\n", entry);

	//iowrite32(entry + 0xa0000000, drv_priv->regs + (RISC1_OnCD + RISC1_ONCD_PC - RISC1_BASE));
	desc->pc_wr = 1;
	iowrite32((entry & 0x7fff) + 0xa3b00000, drv_priv->regs + (RISC1_OnCD + RISC1_ONCD_PC - RISC1_BASE));

	if (risc1_write_regs_debug)
		dev_warn(core->dev, "risc1_write_regs 6\n");

	risc1_write((u32)job_desc->pt4_dma_addr, core, VMMU_PTW_PBA_L);

	if (risc1_write_regs_debug)
		dev_warn(core->dev, "risc1_write_regs 7\n");

	risc1_write((u32)(job_desc->pt4_dma_addr >> 32), core,
		       VMMU_PTW_PBA_H);
// VP behaves differently, rf#12206
#ifdef RISC1_VP
	risc1_write(VMMU_PTW_CFG_41B, core, VMMU_PTW_CFG);
#else
	if (risc1_write_regs_debug)
		dev_warn(core->dev, "risc1_write_regs 8\n");

	risc1_write(VMMU_PTW_CFG_41B | VMMU_PTW_CFG_INV |
		       VMMU_PTW_CFG_A_CACHE(0xf) | VMMU_PTW_CFG_A_PROT(2) |
		       VMMU_PTW_CFG_PREFETCH, core, VMMU_PTW_CFG);
#endif
	if (risc1_write_regs_debug)
		dev_warn(core->dev, "risc1_write_regs 9\n");

	for (i = 0; i < VMMU_TLBS; i++)
		risc1_write(0, core, VMMU_TLB_CTRL + i * sizeof(u32));

	if (risc1_write_regs_debug)
		dev_warn(core->dev, "risc1_write_regs 10\n");
#if 0
	risc1_write(0xFFFFFFFF, core, DSP_MREGIONS);
	risc1_write(0xFFFFFFFF & ~desc->noncached_regions, core,
		       DSP_CREGIONS);
	risc1_write(0, core, DSP_IMASKR);
#endif
	value = ioread32(core->regs + (RISC1_OnCD + RISC1_ONCD_OSCR - RISC1_BASE));

	if (risc1_write_regs_debug)
		dev_warn(core->dev, "risc1_write_regs oscr 0x%08x\n", desc->catch_mode);

	iowrite32(desc->catch_mode, core->regs + (RISC1_OnCD + RISC1_ONCD_OSCR - RISC1_BASE));
}

int risc1_core_stopped(struct risc1_priv *core)
{
	uint32_t value;

	mutex_lock(&core->reg_lock);
	value = ioread32(core->regs + (RISC1_OnCD + RISC1_ONCD_OSCR - RISC1_BASE));
	mutex_unlock(&core->reg_lock);

	if (value & 0x200)
		return 1;

	return 0;
}

static void risc1_core_run(struct risc1_job_inst_desc *desc)
{
	unsigned long flags_state;
	struct risc1_priv *core = desc->core;
	uint32_t value;

	if (!risc1_core_stopped(core))
		return;

	if (core_debug)
		dev_warn(core->dev, "risc1_core_run\n");

	desc->core_stopped = 0;
	spin_lock_irqsave(&desc->state_lock, flags_state);
	desc->state = RISC1_JOB_STATUS_RUN;
	spin_unlock_irqrestore(&desc->state_lock, flags_state);

	// GO
	value = desc->do_step ? 0x8f : 0x2f;
	if (desc->pc_wr) {
		value |= 0x40;
		desc->pc_wr = 0;
	}
	mutex_lock(&core->reg_lock);
	iowrite32(value, core->regs + (RISC1_OnCD + RISC1_ONCD_GO - RISC1_BASE));
	desc->stopped_on_exc = 0;
	mutex_unlock(&core->reg_lock);
}

#ifndef RISC1_NO_IRQS
static int risc1_exception(struct risc1_job_inst_desc *desc, int ended)
{
	struct risc1_priv *core = desc->core;
	uint32_t cause;
	uint32_t exc_code;
	uint32_t pc, epc;
	uint32_t command;
	uint32_t value;
	uint32_t resume;

	static int cause_prev = -1, epc_prev = -1;

	cause = risc1_read_reg(core, RISC1_ONCD_GCP0, 13);
	epc = risc1_read_reg(core, RISC1_ONCD_GCP0, 14);
	mutex_lock(&core->reg_lock);
	value = ioread32(core->regs + (RISC1_OnCD + RISC1_ONCD_OSCR - RISC1_BASE));
	iowrite32(1, core->regs + (RISC1_OnCD + RISC1_ONCD_PCR - RISC1_BASE));
	pc = ioread32(core->regs + (RISC1_OnCD + RISC1_ONCD_PC - RISC1_BASE));
	mutex_unlock(&core->reg_lock);

	if (exception_debug && (cause_prev != cause || epc_prev != epc))
	{
		dev_warn(core->dev, "cause 0x%08x epc 0x%08x\n", cause, epc);
		cause_prev = cause;
		epc_prev = epc;
	}

	exc_code = (cause >> 2) & 0x1f;
	switch (exc_code)
	{
	case 8: // syscall
		command = risc1_read_mem(core, epc);

		if (risc1_syscall_debug)
			dev_warn(core->dev, "syscall 0x%08x oscr 0x%08x\n",
				command, value);

		if (!ended && syscall_handler(desc, command, 0))
		{
			ended = 1;
			desc->stop_reason = RISC1_STOP_REASON_APP_EXCEPTION;
		}
		break;
	default:
		ended = 1;
		desc->stop_reason = RISC1_STOP_REASON_APP_EXCEPTION;
		break;
	}

	return ended;
}

static int event_handler(struct risc1_job_inst_desc *desc, int ended)
{
	struct risc1_priv *core = desc->core;
	uint32_t reg_tmp;
	unsigned long flags_state;
	int debug_request, ret;
	int debug_stopped = 0;
	int min_msec = 0;
	uint32_t oscr, ir;

	static int irq_timeout_msec_prev = -1, abort_prev = -1;
	static int core_stopped_prev = -1, debug_request_prev = -1;
	static int ret_prev = -1;
	static uint32_t oscr_prev = -1, ir_prev = -1;
	static int debug_state_prev = -1;

	if (event_handler_debug
		&& (irq_timeout_msec_prev != irq_timeout_msec || abort_prev != desc->abort))
	{
		dev_warn(core->dev, "event_handler %d %d\n", irq_timeout_msec, desc->abort);
		irq_timeout_msec_prev = irq_timeout_msec;
		abort_prev = desc->abort;
	}

	if (event_handler_debug && (debug_state_prev != desc->debug_state)) {
		dev_warn(core->dev, "event_handler debug_state %d\n", desc->debug_state);
		debug_state_prev = desc->debug_state;
	}

	if (!desc->abort && desc->debug_state != RISC1_DBG_INTERRUPTED
		&& !ended && !desc->irq_state)
	{
			risc1_core_run(desc);
	}

	if (min_msec < irq_timeout_msec)
		min_msec = irq_timeout_msec;

	if (min_msec)
		ret = !wait_event_timeout(desc->irq_waitq,
			desc->core_stopped || desc->abort || desc->irq_state ||
				(desc->debug_request != DBG_REQUEST_NONE),
			msecs_to_jiffies(min_msec));
	else {
		wait_event(desc->irq_waitq,
			   desc->core_stopped || desc->abort || desc->irq_state ||
				(desc->debug_request != DBG_REQUEST_NONE));
		ret = 0;
	}

	if (desc->step_breakpoint)
		debug_request = DBG_REQUEST_NONE;
	else
		debug_request = desc->debug_request;

	desc->core_stopped = risc1_core_stopped(core);

	if (event_handler_debug
		&& (core_stopped_prev != desc->core_stopped || debug_request_prev != debug_request))
	{
		dev_warn(core->dev, "event_handler core_stopped %d %d\n", desc->core_stopped, debug_request);
		core_stopped_prev = desc->core_stopped;
		debug_request_prev = debug_request;
	}

	if (event_handler_debug && (ret_prev != ret || abort_prev != desc->abort)) {
		dev_warn(core->dev, "event_handler abort %d %d\n", ret, desc->abort);
		ret_prev = ret;
		abort_prev = desc->abort;
	}

	if (/*ret && */!desc->core_stopped && !desc->abort && !desc->irq_state
		&& (desc->debug_request == DBG_REQUEST_NONE))
			return ended;

	if (/*ret || */ desc->abort) {
		risc1_core_abort(core);
		ended = 1;
		desc->stop_reason = RISC1_STOP_REASON_APP_EXCEPTION;
	}

	mutex_lock(&core->reg_lock);
	/* Try to analyze ir, OSCR, Cause, R1 */
	ir = ioread32(core->regs + (RISC1_OnCD + RISC1_ONCD_IR - RISC1_BASE));
	if (ir & 0x04) { // stopped
		int processed = 0;

		desc->core_stopped = 1;
		oscr = ioread32(core->regs + (RISC1_OnCD + RISC1_ONCD_OSCR - RISC1_BASE));
		if (event_handler_debug && (ir_prev != ir || oscr_prev != oscr)) {
			dev_warn(core->dev, "ir 0x%08x oscr 0x%08x\n", ir, oscr);
			ir_prev = ir;
			oscr_prev = oscr;
		}

		if (desc->irq_state) {
			mutex_unlock(&core->reg_lock);
			desc->irq_state = 0;
			if (event_vcpu_handler(desc)) {
				ended = 1;
				desc->stop_reason = RISC1_STOP_REASON_APP_EXCEPTION;
			}
			processed = 1;
			mutex_lock(&core->reg_lock);
		}

		if (!desc->stopped_on_exc && (oscr & (1 << 12))) { // Exception vector
			uint32_t pc, status;

			iowrite32(1, core->regs + (RISC1_OnCD + RISC1_ONCD_PCR - RISC1_BASE));
			pc = ioread32(core->regs + (RISC1_OnCD + RISC1_ONCD_PC - RISC1_BASE));

			//oscr &= ~(1 << 12);
			//iowrite32(oscr, core->regs + (RISC1_OnCD + RISC1_ONCD_OSCR - RISC1_BASE));
			//oscr = ioread32(core->regs + (RISC1_OnCD + RISC1_ONCD_OSCR - RISC1_BASE));
			mutex_unlock(&core->reg_lock);

			status = risc1_read_reg(core, RISC1_ONCD_GCP0, 12);
			if (risc1_syscall_debug)
				dev_warn(core->dev,
					"new oscr 0x%08x pc 0x%08x status 0x%08x\n",
						oscr, pc, status);
			ended = risc1_exception(desc, ended);
			desc->stopped_on_exc = 1;

			mutex_lock(&core->reg_lock);
			processed = 1;
		}

		if (!ended && desc->attached) {
			desc->debug_state = RISC1_DBG_INTERRUPTED;
			desc->stop_reason = RISC1_STOP_REASON_DBG_INTERRUPT;
			if (oscr & (3 << 14)) { // OMLR0/OMLR1
				desc->stop_reason =
					RISC1_STOP_REASON_HW_BREAKPOINT;
			} else if (oscr & (1 << 7)) { // steps
				oscr &= ~(1 << 2); // TME
				iowrite32(oscr, core->regs + (RISC1_OnCD + RISC1_ONCD_OSCR - RISC1_BASE));
				desc->stop_reason = RISC1_STOP_REASON_STEP;
			} else if (oscr & (1 << 8)) {
				desc->stop_reason =
					RISC1_STOP_REASON_SW_BREAKPOINT;
			}
		} else if (!ended && desc->state == RISC1_JOB_STATUS_SYSCALL) {
			;
		} else if(!processed) {
			ended = 1;
			desc->stop_reason = RISC1_STOP_REASON_APP_EXCEPTION;
		}
	}
	mutex_unlock(&core->reg_lock);

#if 0 // TODO: fix it
	reg_tmp = risc1_read(core, DSP_DQSTR);
	if ((desc->debug_state != RISC1_DBG_INTERRUPTED) &&
	     desc->core_stopped && ((reg_tmp & (DQSTR_SC|DQSTR_DBG)) == 0)) {
		ended = 1;
		desc->stop_reason = RISC1_STOP_REASON_APP_EXCEPTION;
	}
	// In case of wrong syscall number DSP will be stopped
	if (!ended && (reg_tmp & DQSTR_SC) != 0 && syscall_handler(desc)) {
		ended = 1;
		desc->stop_reason = RISC1_STOP_REASON_APP_EXCEPTION;
	}
#endif
	reg_tmp = 0;
#if 0
	if (reg_tmp & DQSTR_DBG) {
		if (desc->attached) {
			desc->debug_state = RISC1_DBG_INTERRUPTED;
			debug_stopped = 1;
			// TODO: fix it
			// debug_id = risc1_read(core, DBG_INDEX) & DBG_ID;
			switch (debug_id) {
			case DBG_ID_DBSAR0:
			case DBG_ID_DBSAR1:
			case DBG_ID_DBSAR2:
			case DBG_ID_DBSAR3:
				desc->stop_reason =
					RISC1_STOP_REASON_HW_BREAKPOINT;
				break;
			case DBG_ID_DBCNTR:
				desc->stop_reason = RISC1_STOP_REASON_STEP;
				break;
			case DBG_ID_DBBREAK:
				desc->stop_reason =
					RISC1_STOP_REASON_SW_BREAKPOINT;
				break;
			case DBG_ID_QLIC:
				desc->stop_reason =
					RISC1_STOP_REASON_EXTERNAL_REQUEST;
				break;
			}
#if 0 // TODO: fix it
			risc1_write(
				risc1_read(core, DSP_IRQR) & (~IRQR_DBG),
				core, DSP_IRQR);
			risc1_write(
				risc1_read(core, DSP_DQSTR) & (~DQSTR_DBG),
				core, DSP_DQSTR);
#endif
		} else {
			ended = 1;
			desc->stop_reason = RISC1_STOP_REASON_APP_EXCEPTION;
		}
	}
#endif
#if 0 // TODO: fix it
	if (debug_stopped && desc->step_breakpoint &&
			(risc1_read(core, DSP_DBCNTR) != 0)) {
		risc1_write(desc->dbsar_value, core, desc->dbsar_addr);
		desc->step_breakpoint = 0;
		desc->dbcnt_rest_plus_1 = 0;
	}

	if (desc->step_breakpoint && (risc1_read(core, DSP_DBCNTR) == 0)) {
		if (desc->dbcnt_rest_plus_1 != 1)
			desc->debug_state = RISC1_DBG_RUN;
		if (desc->dbcnt_rest_plus_1)
			risc1_write(desc->dbcnt_rest_plus_1 - 1, core,
				       DSP_DBCNTR);
		risc1_write(desc->dbsar_value, core, desc->dbsar_addr);
		desc->step_breakpoint = 0;
		desc->dbcnt_rest_plus_1 = 0;
	}
#endif

	switch (debug_request) {
	case DBG_REQUEST_IOCTL:
		desc->debug_request = DBG_READY_TO_PROCESS;
		wake_up(&desc->debug_waitq);
		wait_event(desc->irq_waitq,
			   desc->debug_request == DBG_PROCESSED);
	break;
	case DBG_REQUEST_ATTACH:
		if (desc->attached)
			desc->debug_result = -EBUSY;
		else {
			desc->debug_state = RISC1_DBG_INTERRUPTED;
			desc->stop_reason = RISC1_STOP_REASON_DBG_INTERRUPT;
			desc->attached = 1;
			desc->debug_result = 0;
		}
		break;
	case DBG_REQUEST_DETACH:
		if (!desc->attached)
			desc->debug_result = -EINVAL;
		else {
			desc->debug_state = RISC1_DBG_RUN;
			desc->attached = 0;
			desc->debug_result = 0;
		}
		break;
	case DBG_REQUEST_NONE:
		break;
	}

	spin_lock_irqsave(&desc->state_lock, flags_state);
	if ((desc->step_breakpoint == 0) &&
			(desc->debug_state == RISC1_DBG_INTERRUPTED)) {
		desc->state = RISC1_JOB_STATUS_INTERRUPTED;
		wake_up(&desc->poll_dbg_waitq);
	} else if (desc->debug_state == RISC1_DBG_RUN) {
		desc->state = RISC1_JOB_STATUS_RUN;
	}
	spin_unlock_irqrestore(&desc->state_lock, flags_state);

	if (debug_request != DBG_REQUEST_NONE) {
		desc->debug_request = DBG_REQUEST_NONE;
		wake_up(&desc->debug_waitq);
	}
	return ended;
}
#else
//TODO: Implement for noninterrupt mode
#endif

void risc1_job_inst_run(struct work_struct *worker)
{
	unsigned long flags_state, flags_queue;
	int i, ret;
	int ended = 0;
#ifdef RISC1_NO_IRQS
	uint32_t irq_status;
	uint32_t reg_tmp;
#endif
	off_t offset;
	struct risc1_job_inst_desc *desc = container_of(worker,
					struct risc1_job_inst_desc,
					worker);
	struct risc1_priv *core = desc->core;
	struct risc1_job_desc *job_desc = desc->job_desc;

	if (job_debug)
		dev_warn(core->dev, "risc1_job_inst_run\n");

	risc1_core_reset(core);

	ret = risc1_mmu_fill_args(desc);
	if (ret) {
		dev_err(core->dev,
			"Failed to fill MMU for job arguments. The job will be skiped\n");
		spin_lock_irqsave(&desc->state_lock, flags_state);
		desc->error = RISC1_JOB_STATUS_ERROR;
		spin_unlock_irqrestore(&desc->state_lock, flags_state);
		goto done;
	}
	risc1_mmu_sync(desc);

	caches_setup(desc);
	caches_inval(desc);

	risc1_write_regs(desc);

	// Write code to CRAM
	for (i = 0; i < job_desc->num_elf_sections; i++) {
		struct risc1_buf_desc *elf = job_desc->elf[i];
		if (!risc1_is_addr_pram(job_desc, elf))
			continue;

		offset = elf->vaddr_mmu_risc1 & (INTERNAL_RISC1_SIZE - 1);

		if (job_debug)
			dev_warn(core->dev, "risc1 offset : 0x%08lx\n", offset);

		risc1_buf_cpy(core, core->mem + offset,
				 elf->mapper->vaddr,
				 elf->mapper->size);
		sync_buffer(core, elf->mapper->size, 0,
			    elf->mapper,
			    RISC1_BUF_SYNC_DIR_TO_DEVICE);
	}

	spin_lock_irqsave(&desc->state_lock, flags_state);
	if (desc->debug_state == RISC1_DBG_INTERRUPTED) {
		desc->state = RISC1_JOB_STATUS_INTERRUPTED;
		wake_up(&desc->poll_dbg_waitq);
	}
	spin_unlock_irqrestore(&desc->state_lock, flags_state);

#ifndef RISC1_NO_IRQS
	while (1) {
		ended = event_handler(desc, ended);
		if (ended) {
			desc->step_breakpoint = 0;
			if (!desc->attached)
				break;
			desc->debug_state = RISC1_DBG_INTERRUPTED;
			desc->stop_reason = RISC1_STOP_REASON_APP_EXCEPTION;
		}
	}
#else
#endif
	desc->debug_result = -EINVAL;
	desc->debug_state = RISC1_DBG_EXITED;
	wake_up(&desc->debug_waitq);
	trace_uptime(core, desc->name);

	caches_flush_after_run(desc);
	if (desc->abort || ret) {
		dev_err(core->dev, ret ? "job timed out\n" : "job aborted\n");
		spin_lock_irqsave(&desc->state_lock, flags_state);
		desc->error = RISC1_JOB_STATUS_ERROR;
		spin_unlock_irqrestore(&desc->state_lock, flags_state);
	} else
		get_job_inst_results(desc);
	//risc1_core_reset(core);
	risc1_mmu_free_args(desc);
done:
	spin_lock_irqsave(&core->queue_lock, flags_queue);
	list_del(&desc->queue_node);
	spin_lock_irqsave(&desc->state_lock, flags_state);
	desc->state = RISC1_JOB_STATUS_DONE;
	spin_unlock_irqrestore(&desc->state_lock, flags_state);
	spin_unlock_irqrestore(&core->queue_lock, flags_queue);
	wake_up(&desc->poll_waitq);
}

long risc1_get_job_inst_status(struct risc1_priv *core, void __user *arg)
{
	struct fd fd;
	struct risc1_job_inst_desc *desc;
	struct risc1_job_instance_status *status;
	int ret = 0;

	status = kzalloc(sizeof(struct risc1_job_instance_status),
			 GFP_KERNEL);
	if (!status) {
		dev_err(core->dev, "risc1_get_job_inst_status\n");
		return -ENOMEM;
	}

	ret = copy_from_user(status, arg,
			     sizeof(struct risc1_job_instance_status));
	if (ret) {
		ret = -EACCES;
		goto clean_status;
	}
	fd = fdget(status->job_instance_fd);
	if (!fd.file || fd.file->f_op != &risc1_job_inst_fops) {
		ret = -EBADFD;
		WARN_ON(1);
		goto clean_fd;
	}

	desc = fd.file->private_data;

	status->state = desc->state;
	status->error = desc->error;

	ret = copy_to_user(arg, status,
			   sizeof(struct risc1_job_instance_status));
clean_fd:
	fdput(fd);
clean_status:
	kfree(status);
	return ret;
}

/* Translate DSP virtual address to CPU virtual address */
void *risc1_map_from_users(struct risc1_job_inst_desc *desc,
			      u64 vaddr64_mmu_risc1,
			      struct userptr_mapper **out_mapper,
			      size_t *offset, u64 *user_vaddr_cpu,
			      size_t size)
{
	struct page_entry *p = desc->job_desc->p_top;
	u64 index, j, ret;
	int i;
	void *retval;
	u8 inpage_offset = 38;
	struct userptr_mapper *mapper;
	struct risc1_buffer_priv *buf_priv;
	struct risc1_priv *core = desc->core;
	u32 vaddr_mmu_risc1 = vaddr64_mmu_risc1;

	vaddr_mmu_risc1 = risc1_get_paddr(vaddr_mmu_risc1);

	if (risc1_map_from_users_debug)
		dev_warn(core->dev, "risc1_map_from_users 0x%08x\n", vaddr_mmu_risc1);

	// Get inpage offset
	for (j = 3; j >= 0; j--) {
		index = (j >= 3) ? 0 : ((vaddr_mmu_risc1 >> (RISC1_PAGE_SHIFT + j * 9)) &
								GENMASK(8, 0));
		p = p + index;

		if (risc1_map_from_users_debug) {
			dev_warn(core->dev, "risc1_map_from_users j %lld index %lld p 0x%p inpage_offset %d\n",
				j, index, p, inpage_offset);
			dev_warn(core->dev, "risc1_map_from_users next_lvl %p\n", p->next_lvl);
		}

		if (p->next_lvl == NULL)
			break;
		p = p->next_lvl;
		inpage_offset -= 9;
	}

	if (risc1_map_from_users_debug)
		dev_warn(core->dev, "risc1_map_from_users 2 p %p p->mapper %p\n", p, p->mapper);

	if ((p == NULL) || (p->mapper == NULL)) {
		/* Try to use elf structures */
		for (i = 0; i < desc->job_desc->num_elf_sections; i++) {
			struct risc1_buf_desc *elf = desc->job_desc->elf[i];
			u32 start = risc1_get_paddr(elf->vaddr_mmu_risc1);
			u32 end = start + elf->mapper->size;
			if (vaddr_mmu_risc1 >= start && vaddr_mmu_risc1 < end) {
				mapper = elf->mapper;
				break;
			}
		}
		if (mapper == NULL) {
			WARN_ON(1);
			return NULL;
		}
	} else {
		mapper = p->mapper;
	}

	if (risc1_map_from_users_debug)
		dev_warn(core->dev, "risc1_map_from_users 3\n");

	if (mapper->dmabuf->ops != &risc1_dmabuf_ops) {
		dev_err(core->dev, "Attempt to map external buffer\n");
		return NULL;
	}
	buf_priv = mapper->dmabuf->priv;

	if (risc1_map_from_users_debug)
		dev_warn(core->dev, "risc1_map_from_users 4\n");

	*out_mapper = mapper;
	if (!mapper->vaddr)
		mapper->vaddr = dma_buf_vmap(mapper->attach->dmabuf);
	retval = mapper->vaddr + p->offset - mapper->offset +
			(vaddr_mmu_risc1 & GENMASK(inpage_offset, 0));
	*offset = retval - mapper->vaddr;

	if (risc1_map_from_users_debug)
	{
		dev_warn(core->dev, "risc1_map_from_users vaddr 0x%p offset 0x%08lx moffset 0x%08x\n",
				 mapper->vaddr, p->offset, mapper->offset);
		dev_warn(core->dev, "risc1_map_from_users vaddr 0x%08x inpage_offset %d GENMASK 0x%08lx\n",
				 vaddr_mmu_risc1, inpage_offset, GENMASK(inpage_offset, 0));
		dev_warn(core->dev, "risc1_map_from_users retval 0x%p offset 0x%08lx\n",
				 retval, *offset);
	}

	if (buf_priv->buf_info.p == 0)
		*user_vaddr_cpu = 0;
	else
		*user_vaddr_cpu = buf_priv->buf_info.p + *offset;

	if (risc1_map_from_users_debug)
		dev_warn(core->dev, "risc1_map_from_users 5\n");

	// Invalidate CPU caches
	ret = sync_buffer(core, size, *offset, mapper,
			  RISC1_BUF_SYNC_DIR_TO_CPU);

	if (risc1_map_from_users_debug)
		dev_warn(core->dev, "risc1_map_from_users 6\n");

	if (ret)
		return NULL;

	return retval;
}

int risc1_get_job_inst_count(struct risc1_priv *core, void __user *arg)
{
	struct risc1_job_inst_desc *desc;
	u32 count;
	int ret;
	unsigned long queue_flags;

	count = 0;
	spin_lock_irqsave(&core->queue_lock, queue_flags);
	list_for_each_entry(desc, &core->job_queue, queue_node) {
		count += 1;
	}
	spin_unlock_irqrestore(&core->queue_lock, queue_flags);

	ret = copy_to_user(arg, &count, sizeof(u32));
	if (ret)
		return ret;
	return 0;
}

int risc1_get_job_inst_list(struct risc1_priv *core, void __user *arg)
{
	struct risc1_job_inst_desc *desc;
	struct risc1_job_instance_info list_elem;
	struct risc1_job_instance_list list;
	int ret = 0;
	u32 count = 0;
	unsigned long queue_flags;

	ret = copy_from_user(&list, arg,
			     sizeof(struct risc1_job_instance_list));
	if (ret)
		return -EACCES;

	spin_lock_irqsave(&core->queue_lock, queue_flags);
	list_for_each_entry(desc, &core->job_queue, queue_node) {
		if (count == list.job_instance_count)
			break;
		list_elem.id = hash_long((u64)desc, sizeof(long) * 8);
		list_elem.pid = desc->pid;
		strcpy(list_elem.name, desc->name);
		ret = copy_to_user(&list.info[count], &list_elem,
				   sizeof(struct risc1_job_instance_info));
		if (ret)
			goto unlock_restore;
		count += 1;
	}

	list.job_instance_ret = count;

	ret = copy_to_user(arg, &list,
			   sizeof(struct risc1_job_instance_list));

unlock_restore:
	spin_unlock_irqrestore(&core->queue_lock, queue_flags);
	return ret;
}
