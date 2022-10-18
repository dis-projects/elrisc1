// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright 2021-2022 RnD Center "ELVEES", JSC
 */

#include <linux/anon_inodes.h>
#include <linux/hash.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include "risc1-debug.h"
#include "risc1-mmu.h"

static int external_memory_rw(struct risc1_job_inst_dbg_desc *desc,
			      struct risc1_dbg_mem *mem,
			      enum risc1_job_inst_dbg_rw rw)
{
	int ret;
	struct risc1_job_inst_desc *job_inst = desc->inst;
	struct risc1_priv *core = job_inst->core;
	struct userptr_mapper *mapper = NULL;
	void *data; u64 user_ptr; size_t offset;

	data = risc1_map_from_users(job_inst, mem->vaddr, &mapper,
				       &offset, &user_ptr, mem->size);
	if (!data)
		return -EACCES;

	if (rw == RISC1_JOB_INST_DBG_READ) {
		ret = copy_to_user(mem->data, data, mem->size);
		if (ret)
			return -EACCES;
	} else {
		ret = copy_from_user(data, mem->data, mem->size);
		if (ret)
			return -EACCES;

		sync_buffer(job_inst->core, mem->size, offset,
			    mapper,
			    RISC1_BUF_SYNC_DIR_TO_DEVICE);

		iowrite32(1 | (1 << 1) | (1 << 12)| (1 << 14), core->regs + (RISC1_CSR + 0 - RISC1_BASE));
	}
	return 0;
}

static int risc1_dbg_memory_rw(struct risc1_job_inst_dbg_desc *desc,
				  void __user *arg,
				  enum risc1_job_inst_dbg_rw rw)
{
#if 0 // TODO: fix
	int ret = 0; uint32_t reg_tmp;
	unsigned long start, end;
	uint32_t pfn, old_pfn;
	struct risc1_dbg_mem mem;
	struct risc1_job_inst_desc *job_inst = desc->inst;
	struct risc1_priv *core = job_inst->core;

	ret = copy_from_user((void *)&mem, (const void __user *)arg,
			     sizeof(struct risc1_dbg_mem));
	if (ret)
		return -EACCES;

	old_pfn = risc1_read(core, DSP_CTRL);
	// Disable prefetcher
	pfn = old_pfn & ~(3 << 16);
	risc1_write(pfn, core, DSP_CTRL);

	// Flush all DSP caches
	risc1_write(DSP_INVCTRL_FLUSH_ALL, core, DSP_INVCTRL);
	ret = risc1_pollreg_timeout(core, DSP_MBARREG, reg_tmp,
				       reg_tmp == 0,
				       0, E50_CACHE_TIMEOUT_USEC);
	WARN_ON(ret);

	// Reset pipeline
	risc1_write(pfn | CTRL_PipelineFlush, core, DSP_CTRL);

	start = mem.vaddr;
	end = mem.vaddr + mem.size;
	// DDR
		ret = external_memory_rw(desc, &mem, rw);
	// Restore pfn
	risc1_write(old_pfn, core, DSP_CTRL);

	return ret;
#endif
	return 0;
}

static int risc1_dbg_register_rw(struct risc1_job_inst_dbg_desc *desc,
				    void __user *arg,
				    enum risc1_job_inst_dbg_rw rw)
{
	int ret = 0, reg, i = 0;
	struct risc1_dbg_mem mem;
	struct risc1_job_inst_desc *job_inst = desc->inst;
	struct risc1_priv *core = job_inst->core;
	uint32_t *data;
	uint32_t group, size;
	uint32_t resume;

	ret = copy_from_user(&mem, arg, sizeof(struct risc1_dbg_mem));
	if (ret)
		return -EACCES;

	group = mem.vaddr & 7;
	if (/*mem.vaddr > 0x1ff || */ mem.size > 32 * 4) /* one group per call */
		return -EACCES;

	data = kmalloc(mem.size, GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	size = mem.size;
	reg = mem.vaddr >> 3;
	if (rw == RISC1_JOB_INST_DBG_READ) {

		if (mem.vaddr == 0x1ff) { // PC
			mutex_lock(&core->reg_lock);
			iowrite32(1, core->regs + (RISC1_OnCD + RISC1_ONCD_PCR - RISC1_BASE));
			*data = ioread32(core->regs + (RISC1_OnCD + RISC1_ONCD_PC - RISC1_BASE));
			mutex_unlock(&core->reg_lock);
		} else {
			if (!desc->inst->no_ds) {
				uint32_t oscr;
				mutex_lock(&core->reg_lock);
				oscr = ioread32(core->regs + (RISC1_OnCD + RISC1_ONCD_OSCR - RISC1_BASE));
				oscr |= 1 << 11;
				iowrite32(oscr, core->regs + (RISC1_OnCD + RISC1_ONCD_OSCR - RISC1_BASE));
				mutex_unlock(&core->reg_lock);
				desc->inst->no_ds = 1;
			}

			for (i = 0; size >= 4; reg++, size -= 4)
				data[i++] = risc1_read_reg(core, group, reg);
		}

		ret = copy_to_user(mem.data, data, mem.size);
		if (ret)
		{
			ret = -EACCES;
			goto err;
		}
	} else if (rw == RISC1_JOB_INST_DBG_WRITE) {
		ret = copy_from_user(data, mem.data, mem.size);
		if (ret)
			return -EACCES;
		if (mem.vaddr == 0x1ff) { // PC, TODO start after fix
			mutex_lock(&core->reg_lock);
			iowrite32(*data, core->regs + (RISC1_OnCD + RISC1_ONCD_PC - RISC1_BASE));
			mutex_unlock(&core->reg_lock);
			desc->inst->pc_wr = 1;
		} else {
			for (i = 0; size >= 4; reg++, size -= 4)
				risc1_write_reg(data[i++], core, group, reg);
		}
	} else {
		WARN_ON(1);
		ret = -EINVAL;
		goto err;
	}

	kfree(data);
	return 0;
err:
	kfree(data);

	return ret;
}

static int risc1_dbg_job_inst_interrupt(
			struct risc1_job_inst_dbg_desc *desc,
			void __user *arg)
{
	struct risc1_job_inst_desc *job_inst = desc->inst;

	job_inst->debug_state = RISC1_DBG_INTERRUPTED;
	job_inst->stop_reason = RISC1_STOP_REASON_DBG_INTERRUPT;
	return 0;
}

static int risc1_dbg_job_inst_continue(
			struct risc1_job_inst_dbg_desc *desc,
			void __user *arg)
{

	struct risc1_job_inst_desc *job_inst = desc->inst;
#if 0 //TODO: fix
	struct risc1_priv *core = job_inst->core;
	u32 reg, dbsar;

	reg = risc1_read(core, DSP_PC);
	for (dbsar = DSP_DBSAR0; dbsar <= DSP_DBSAR3; dbsar += DSP_DBSARNEXT) {
		if (risc1_read(core, dbsar) == reg) {
			risc1_write(1, core, DSP_DBCNTR);
			job_inst->step_breakpoint = 1;
			risc1_write(0xFFFFFFFF, core, dbsar);
			job_inst->dbsar_addr =  dbsar;
			job_inst->dbsar_value = reg;
			job_inst->dbcnt_rest_plus_1 = 0;
			break;
		}
	}
#endif
	job_inst->do_step = 0;

	job_inst->debug_state = RISC1_DBG_RUN;

	return 0;
}

static int risc1_dbg_get_stop_reason(
			struct risc1_job_inst_dbg_desc *desc,
			void __user *arg)
{
	struct risc1_job_inst_desc *job_inst = desc->inst;
	struct risc1_dbg_stop_reason stop_reason;

	stop_reason.reason = job_inst->stop_reason;

	return copy_to_user(arg, &stop_reason,
			    sizeof(struct risc1_dbg_stop_reason));
}

static int risc1_dbg_hw_breakpoint_set(
		struct risc1_job_inst_dbg_desc *desc, void __user *arg)
{
	struct risc1_job_inst_desc *job_inst = desc->inst;
	struct risc1_priv *core = job_inst->core;
	u32 vaddr;
	int ret;
	u32 obcr;

	ret = copy_from_user(&vaddr, arg, sizeof(u32));
	if (ret)
		return -EACCES;

	/* Check usage */
	mutex_lock(&core->reg_lock);
	obcr = ioread32(core->regs + (RISC1_OnCD + RISC1_ONCD_OBCR - RISC1_BASE));
	if ((obcr & 0xc0) == 0) {
		/* First can be used */
		iowrite32(vaddr, core->regs + (RISC1_OnCD + RISC1_ONCD_OMLR0 - RISC1_BASE));
		obcr &= ~0xc1;
		obcr |=  0x48;
	} else if ((obcr & 0x300) == 0) {
		/* Second can be used */
		iowrite32(vaddr, core->regs + (RISC1_OnCD + RISC1_ONCD_OMLR1 - RISC1_BASE));
		obcr &= ~0x332;
		obcr |=  0x120;
	} else {
		mutex_unlock(&core->reg_lock);
		return -EBUSY;
	}
	iowrite32(obcr, core->regs + (RISC1_OnCD + RISC1_ONCD_OBCR - RISC1_BASE));
	mutex_unlock(&core->reg_lock);

	return -EBUSY;
}

static int risc1_dbg_hw_breakpoint_clear(
		struct risc1_job_inst_dbg_desc *desc, void __user *arg)
{

	struct risc1_job_inst_desc *job_inst = desc->inst;
	struct risc1_priv *core = job_inst->core;
	u32 vaddr, regval;
	int ret;
	u32 obcr;

	ret = copy_from_user(&vaddr, arg, sizeof(u32));
	if (ret)
		return -EACCES;

	mutex_lock(&core->reg_lock);
	regval = ioread32(core->regs + (RISC1_OnCD + RISC1_ONCD_OMLR0 - RISC1_BASE));
	obcr = ioread32(core->regs + (RISC1_OnCD + RISC1_ONCD_OBCR - RISC1_BASE));

	if ((obcr & 0xc0) != 0 && vaddr == regval) {
		obcr &= ~0xc0;
		iowrite32(obcr, core->regs + (RISC1_OnCD + RISC1_ONCD_OBCR - RISC1_BASE));
		mutex_unlock(&core->reg_lock);
		return 0;
	}

	regval = ioread32(core->regs + (RISC1_OnCD + RISC1_ONCD_OMLR1 - RISC1_BASE));
	if ((obcr & 0x300) == 0 && vaddr == regval) {
		obcr &= ~0x300;
		iowrite32(obcr, core->regs + (RISC1_OnCD + RISC1_ONCD_OBCR - RISC1_BASE));
		mutex_unlock(&core->reg_lock);
		return 0;
	}

	mutex_unlock(&core->reg_lock);
	return 0;
}

static int risc1_dbg_step(struct risc1_job_inst_dbg_desc *desc,
			     void __user *arg)
{
	struct risc1_job_inst_desc *job_inst = desc->inst;
	struct risc1_priv *core = job_inst->core;
	u32 steps;
	u32 reg, addr0, addr1, obcr;
	int ret = 0;

	ret = copy_from_user(&steps, arg, sizeof(u32));
	if (ret)
		return -EACCES;

	if (steps == 0)
		return -EINVAL;

	if (job_inst->debug_state != RISC1_DBG_INTERRUPTED)
		return -EINVAL;

	mutex_lock(&core->reg_lock);
	iowrite32(1, core->regs + (RISC1_OnCD + RISC1_ONCD_PCR - RISC1_BASE));
	reg = ioread32(core->regs + (RISC1_OnCD + RISC1_ONCD_PC - RISC1_BASE));
	addr0 = ioread32(core->regs + (RISC1_OnCD + RISC1_ONCD_OMLR0 - RISC1_BASE));
	addr1 = ioread32(core->regs + (RISC1_OnCD + RISC1_ONCD_OMLR1 - RISC1_BASE));
	obcr = ioread32(core->regs + (RISC1_OnCD + RISC1_ONCD_OBCR - RISC1_BASE));
	if ((addr0 == reg) && ((obcr & (0x3 << 2)) != 0)) {
		ret = 1;
	} else if ((addr1 == reg) && ((obcr & (0x3 << 4)) != 0)){
		ret = 2;
	}
	if (ret) {
		job_inst->step_breakpoint = 1;
		job_inst->bp_value = reg;
		job_inst->bp_addr = ret;
		job_inst->bpcnt_rest_plus_1 = steps;
		steps = 1;
	}
#if 0 //TODO: fix
	reg = risc1_read(core, DSP_PC);
	for (dbsar = DSP_DBSAR0; dbsar <= DSP_DBSAR3; dbsar += DSP_DBSARNEXT) {
		if (risc1_read(core, dbsar) == reg) {
			risc1_write(0xFFFFFF, core, dbsar);
			job_inst->step_breakpoint = 1;
			job_inst->dbsar_addr =  dbsar;
			job_inst->dbsar_value = reg;
			job_inst->dbcnt_rest_plus_1 = steps;
			steps = 1;
			break;
		}
	}
	risc1_write(steps, core, DSP_DBCNTR);
#endif

	iowrite32(steps - 1, core->regs + (RISC1_OnCD + RISC1_ONCD_OTC - RISC1_BASE));
	reg = ioread32(core->regs + (RISC1_OnCD + RISC1_ONCD_OSCR - RISC1_BASE));
	reg |= 1 << 2; // TME
	iowrite32(reg, core->regs + (RISC1_OnCD + RISC1_ONCD_OSCR - RISC1_BASE));
	mutex_unlock(&core->reg_lock);
	job_inst->do_step = 1;

	job_inst->debug_state = RISC1_DBG_RUN;

	return 0;
}

long risc1_dbg_ioctl_safe(struct file *file, unsigned int cmd,
			   unsigned long arg)
{
	struct risc1_job_inst_dbg_desc *pdata =
		(struct risc1_job_inst_dbg_desc *)file->private_data;
	void __user *const uptr = (void __user *)arg;
	int ret;

	switch (cmd) {
	case RISC1_IOC_DBG_MEMORY_READ:
		ret = risc1_dbg_memory_rw(pdata, uptr,
					     RISC1_JOB_INST_DBG_READ);
		break;
	case RISC1_IOC_DBG_MEMORY_WRITE:
		ret = risc1_dbg_memory_rw(pdata, uptr,
					     RISC1_JOB_INST_DBG_WRITE);
		break;
	case RISC1_IOC_DBG_REGISTER_READ:
		ret = risc1_dbg_register_rw(pdata, uptr,
					       RISC1_JOB_INST_DBG_READ);
		break;
	case RISC1_IOC_DBG_REGISTER_WRITE:
		ret = risc1_dbg_register_rw(pdata, uptr,
					       RISC1_JOB_INST_DBG_WRITE);
		break;
	case RISC1_IOC_DBG_JOB_INSTANCE_INTERRUPT:
		ret = risc1_dbg_job_inst_interrupt(pdata, uptr);
		break;
	case RISC1_IOC_DBG_JOB_INSTANCE_CONTINUE:
		ret = risc1_dbg_job_inst_continue(pdata, uptr);
		break;
	case RISC1_IOC_DBG_GET_STOP_REASON:
		ret = risc1_dbg_get_stop_reason(pdata, uptr);
		break;
	case RISC1_IOC_DBG_HW_BREAKPOINT_SET:
		ret = risc1_dbg_hw_breakpoint_set(pdata, uptr);
		break;
	case RISC1_IOC_DBG_HW_BREAKPOINT_CLEAR:
		ret = risc1_dbg_hw_breakpoint_clear(pdata, uptr);
		break;
	case RISC1_IOC_DBG_STEP:
		ret = risc1_dbg_step(pdata, uptr);
		break;
	case RISC1_IOC_DUMP:
		ret = risc1_mmu_dump(pdata->inst);
		break;
	default:
		ret = -ENOTTY;
		break;
	}

	return ret;
}

static long risc1_dbg_ioctl(struct file *file, unsigned int cmd,
			       unsigned long arg)
{
	struct risc1_job_inst_dbg_desc *pdata =
		(struct risc1_job_inst_dbg_desc *)file->private_data;
	struct risc1_job_inst_desc *job_inst = pdata->inst;
	int ret = 0;

	mutex_lock(&job_inst->debug_lock);
	job_inst->debug_request = DBG_REQUEST_IOCTL;
	wake_up(&job_inst->irq_waitq);
	wait_event(job_inst->debug_waitq,
		   job_inst->debug_request == DBG_REQUEST_NONE ||
			job_inst->debug_state == RISC1_DBG_EXITED ||
			job_inst->debug_request == DBG_READY_TO_PROCESS);
	if (job_inst->debug_request == DBG_READY_TO_PROCESS) {
		ret = risc1_dbg_ioctl_safe(file, cmd, arg);
		job_inst->debug_request = DBG_PROCESSED;
		wake_up(&job_inst->irq_waitq);
	}
	wait_event(job_inst->debug_waitq,
		   job_inst->debug_request == DBG_REQUEST_NONE ||
			job_inst->debug_state == RISC1_DBG_EXITED);
	if (job_inst->debug_request != DBG_REQUEST_NONE)
		ret = -EACCES;
	mutex_unlock(&job_inst->debug_lock);

	return ret;
}

static int risc1_job_inst_dbg_release(struct inode *inode,
					 struct file *file)
{
	struct risc1_job_inst_dbg_desc *desc = file->private_data;
	struct risc1_job_inst_desc *inst = desc->inst;
	int ret = 0;

	mutex_lock(&inst->debug_lock);
	inst->debug_request = DBG_REQUEST_DETACH;
	wake_up(&inst->irq_waitq);
	wait_event(inst->debug_waitq,
		   desc->inst->debug_request == DBG_REQUEST_NONE ||
			desc->inst->debug_state == RISC1_DBG_EXITED);
	if (inst->debug_state != RISC1_DBG_EXITED)
		ret = inst->debug_result;
	mutex_unlock(&inst->debug_lock);

	fput(desc->inst_file);
	kfree(desc);
	return ret;
}

static unsigned int risc1_job_inst_dbg_poll(struct file *file,
					       poll_table *wait)
{
	struct risc1_job_inst_dbg_desc *desc = file->private_data;
	struct risc1_job_inst_desc *inst = desc->inst;

	poll_wait(file, &inst->poll_dbg_waitq, wait);

	/* The spec doesn't suggest which events the job waits for, so
	 * we'll signal every IO event */
	if (inst->state == RISC1_JOB_STATUS_INTERRUPTED)
		return POLLIN | POLLRDNORM | POLLOUT | POLLWRNORM;

	return 0;
}

static const struct file_operations risc1_job_inst_dbg_fops = {
	.unlocked_ioctl = risc1_dbg_ioctl,
	.release = risc1_job_inst_dbg_release,
	.poll = risc1_job_inst_dbg_poll,
};

int export_dbg_fd(struct risc1_job_inst_dbg_desc *desc)
{
	return anon_inode_getfd("risc1jobinstancedebug",
				&risc1_job_inst_dbg_fops, desc, O_RDWR);
}

int risc1_job_dbg_attach(struct risc1_priv *core, void __user *arg)
{
	int ret;
	long hashval;
	struct risc1_job_inst_desc *inst_desc, *inst_next;
	struct risc1_job_instance_dbg inst_dbg;
	struct risc1_job_inst_dbg_desc *desc;
	unsigned long flags;
	struct fd fd;

	desc = kzalloc(sizeof(struct risc1_job_inst_dbg_desc),
		       GFP_KERNEL);
	if (!desc)
		return -ENOMEM;

	ret = copy_from_user(&inst_dbg, arg,
			     sizeof(struct risc1_job_instance_dbg));
	if (ret) {
		ret = -EACCES;
		goto clean_kfree;
	}

	spin_lock_irqsave(&core->queue_lock, flags);
	list_for_each_entry_safe(inst_desc, inst_next, &core->job_queue,
				 queue_node) {
		hashval = hash_long((u64)inst_desc, sizeof(long) * 8);
		if (inst_dbg.job_instance_id == hashval) {
			desc->inst = inst_desc;
			break;
		}
	}
	if (desc->inst) {
		fd = fdget(desc->inst->self_fd);
		desc->inst_file = get_file(fd.file);
		fdput(fd);
	}

	spin_unlock_irqrestore(&core->queue_lock, flags);
	if (!desc->inst) {
		ret = -EINVAL;
		goto clean_kfree;
	}

	ret = export_dbg_fd(desc);
	if (ret < 0)
		goto clean_inst_fd;

	inst_dbg.job_instance_dbg_fd = ret;

	ret = copy_to_user(arg, &inst_dbg,
			   sizeof(struct risc1_job_instance_dbg));
	if (ret) {
		ret = -EACCES;
		goto clean_fd;
	}

	mutex_lock(&desc->inst->debug_lock);
	desc->inst->debug_request = DBG_REQUEST_ATTACH;
	wake_up(&desc->inst->irq_waitq);
	wait_event(desc->inst->debug_waitq,
		   desc->inst->debug_request == DBG_REQUEST_NONE ||
			desc->inst->debug_state == RISC1_DBG_EXITED);
	if (desc->inst->debug_state == RISC1_DBG_EXITED)
		ret =  -EINVAL;
	else
		ret = desc->inst->debug_result;
	mutex_unlock(&desc->inst->debug_lock);

	if (ret < 0)
		goto clean_fd;

	return 0;
clean_fd:
	put_unused_fd(inst_dbg.job_instance_dbg_fd);
clean_inst_fd:
	fput(desc->inst_file);
clean_kfree:
	kfree(desc);
	return ret;
}
