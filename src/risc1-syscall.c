// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright 2020 RnD Center "ELVEES", JSC
 */

#include <linux/anon_inodes.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/sort.h>
#include <linux/uaccess.h>

#include "risc1-syscall.h"
#include "risc1-trace.h"

extern u32 risc1_syscall_debug;
extern u32 event_vcpu_handler_debug;

__packed struct timeval_compat{
	uint64_t sec;
	uint64_t usec;
};

__packed struct stat_compat {
	int16_t st_dev;
	uint16_t st_ino;
	uint32_t st_mode;
	uint16_t st_nlink;
	uint16_t st_uid;
	uint16_t st_gid;
	int16_t st_rdev;
	int32_t st_size;
	int32_t st_atime;
	int32_t st_spare1;
	int32_t st_mtime;
	int32_t st_spare2;
	int32_t st_ctime;
	int32_t st_spare3;
	int32_t st_blksize;
	int32_t st_blocks;

	int32_t st_spare4[2];
};

__packed struct tms_compat {
	uint64_t tms_utime;
	uint64_t tms_stime;
	uint64_t tms_cutime;
	uint64_t tms_cstime;
};

static int syscall_gettimeofday(struct timeval_compat *tv)
{
	struct timespec64 ts;

	ktime_get_real_ts64(&ts);
	tv->sec = ts.tv_sec;
	tv->usec = ts.tv_nsec / 1000;

	if (ts.tv_sec > U32_MAX)
		return -ERANGE;
	return 0;
}

static const char *get_syscallname_by_id(int syscall_idx)
{
	switch (syscall_idx) {
	case SC_GETTIMEOFDAY:
		return "SC_GETTIMEOFDAY";
	case SC_READ:
		return "SC_READ";
	case SC_WRITE:
		return "SC_WRITE";
	case SC_OPEN:
		return "SC_OPEN";
	case SC_CLOSE:
		return "SC_CLOSE";
	case SC_FSTAT:
		return "SC_FSTAT";
	case SC_LSEEK:
		return "SC_LSEEK";
	case SC_ISATTY:
		return "SC_ISATTY";
	case SC_CHDIR:
		return "SC_CHDIR";
	case SC_STAT:
		return "SC_STAT";
	case SC_TIMES:
		return "SC_TIMES";
	case SC_LINK:
		return "SC_LINK";
	case SC_UNLINK:
		return "SC_UNLINK";
	case SC_GET_ENV:
		return "SC_GET_ENV";
	}
	return "SC_UNKNOWN";
}

int syscall_handler(struct risc1_job_inst_desc *job_inst, uint32_t command, int mode)
{
	struct risc1_priv *core = job_inst->core;
	u64 arg0, arg1, arg2;
	void *virt_arg0, *virt_arg1;
	struct userptr_mapper *mapper;
	size_t offset, size;
	unsigned long flags_state;
	const char *syscall_name;
	int needFlush, self_processed, ret;
	uint32_t pc, epc, status;
	uint32_t syscall_idx = (command >> 6) & 0xfffff;

	/* check syscall command */
	if ((command & 0xfc00003f) != 0x0000000c)
		return 1;

	job_inst->message.type = RISC1_MESSAGE_EMPTY;
	spin_lock_irqsave(&job_inst->state_lock, flags_state);
	job_inst->state = RISC1_JOB_STATUS_SYSCALL;
	spin_unlock_irqrestore(&job_inst->state_lock, flags_state);

	/* Read syscall command */
	syscall_name = get_syscallname_by_id(syscall_idx);

	arg0 = risc1_read_reg(core, RISC1_ONCD_GRFCPU, 4);
	arg1 = risc1_read_reg(core, RISC1_ONCD_GRFCPU, 5);
	arg2 = risc1_read_reg(core, RISC1_ONCD_GRFCPU, 6);

	syscall_name = get_syscallname_by_id(syscall_idx);

	if (risc1_syscall_debug)
		dev_warn(core->dev,
			"syscall %s arg0: 0x%08x arg1: 0x%08x arg2: 0x%08x %d\n",
			syscall_name, (u32)arg0, (u32)arg1, (u32)arg2, syscall_idx);

	switch (syscall_idx) {
	case SC_READ: // (int fd, void *buf, size_t cout)
		size = arg2;
		trace_syscall(syscall_name, 0, size);

		virt_arg0 = risc1_map_from_users(job_inst, arg1, &mapper,
						    &offset, &arg1, size);
		if (!virt_arg0)
			return -EINVAL;
		if (!arg1)
			return -EACCES;
		needFlush = 1;
		self_processed = 0;
		break;
	case SC_WRITE: // (int fd, void *buf, size_t cout)
		size = arg2;
		trace_syscall(syscall_name, 0, size);

		virt_arg0 = risc1_map_from_users(job_inst, arg1, &mapper,
						    &offset, &arg1, size);
		if (!virt_arg0)
			return -EINVAL;
		if (!arg1)
			return -EACCES;
		needFlush = 0;
		self_processed = 0;
		break;
	case SC_GETTIMEOFDAY: // (struct timeval *tv, struct timezone *tz)
		size = sizeof(struct timeval);
		trace_syscall(syscall_name, size, 0);

		virt_arg0 = risc1_map_from_users(job_inst, arg0, &mapper,
						    &offset, &arg0, size);
		if (!virt_arg0)
			return -EINVAL;

		job_inst->message.retval = syscall_gettimeofday(virt_arg0);
		needFlush = 1;
		self_processed = 1;
		break;
	case SC_OPEN: // (char *filename, int flags, int mode)
		// The string's length is in R7
		size = risc1_read_reg(core, RISC1_ONCD_GRFCPU, 7);
		trace_syscall(syscall_name, size, 0);

		virt_arg0 = risc1_map_from_users(job_inst, arg0, &mapper,
						    &offset, &arg0, size);
		if (!virt_arg0)
			return -EINVAL;
		if (!arg0)
			return -EACCES;

		//dev_warn(core->dev, "strlen(virt_arg0) %d size %d addr %p\n",
		//	strlen(virt_arg0), size, virt_arg0);
		WARN_ON(strlen(virt_arg0) != size);
		needFlush = 0;
		self_processed = 0;
		break;
	case SC_CLOSE: // (int file)
	case SC_ISATTY: // (int file)
		arg1 = arg2 = 0;
	case SC_LSEEK: // (int file, int offset, int dir)
		needFlush = 0;
		self_processed = 0;
		trace_syscall(syscall_name, 0, 0);
		break;
	case SC_FSTAT: // (int file, struct stat *st)
		size = sizeof(struct stat_compat);
		trace_syscall(syscall_name, 0, size);

		virt_arg0 = risc1_map_from_users(job_inst, arg1, &mapper,
						    &offset, &arg1, size);
		if (!virt_arg0)
			return -EINVAL;
		if (!arg1)
			return -EACCES;
		arg2 = 0;
		needFlush = 1;
		self_processed = 0;
		break;
	case SC_STAT: // (const char *filename, struct stat *buf)
		// The string's length is in arg2
		size = arg2;
		trace_syscall(syscall_name, size,
			      sizeof(struct stat_compat));

		// FIXME: We do not know the real size of filename string
		virt_arg0 = risc1_map_from_users(job_inst, arg0, &mapper,
						    &offset, &arg0, size);
		if (!virt_arg0)
			return -EINVAL;
		if (!arg0)
			return -EACCES;

		//dev_warn(core->dev, "strlen(virt_arg0) %d size %d\n",
		//	strlen(virt_arg0), size);
		WARN_ON(strlen(virt_arg0) != size);
		size = sizeof(struct stat_compat);
		virt_arg1 = risc1_map_from_users(job_inst, arg1, &mapper,
						    &offset, &arg1, size);
		if (!virt_arg1)
			return -EINVAL;
		if (!arg1)
			return -EACCES;
		arg2 = 0;
		needFlush = 1;
		self_processed = 0;
		break;
	case SC_LINK: // (const char *oldpath, const char *newpath)
		// The string's length is in arg2
		size = arg2;
		trace_syscall(syscall_name, size, size);

		virt_arg0 = risc1_map_from_users(job_inst, arg0, &mapper,
						    &offset, &arg0, size);
		if (!virt_arg0)
			return -EINVAL;
		if (!arg0)
			return -EACCES;

		// dev_warn(core->dev, "strlen(virt_arg0) %d size %d\n",
		//		strlen(virt_arg0), size);
		WARN_ON(strlen(virt_arg0) != size);
		// The string's length is in R7
		size = risc1_read_reg(core, RISC1_ONCD_GRFCPU, 7);
		virt_arg1 = risc1_map_from_users(job_inst, arg1, &mapper,
						    &offset, &arg1, size);
		if (!virt_arg1)
			return -EINVAL;
		if (!arg1)
			return -EACCES;

		// dev_warn(core->dev, "strlen(virt_arg1) %d size %d\n",
		//		strlen(virt_arg1), size);
		WARN_ON(strlen(virt_arg1) != size);
		arg2 = 0;
		needFlush = 0;
		self_processed = 0;
		break;
	case SC_UNLINK: // (const char *path)
	case SC_CHDIR: // (const char *path)
		// The string's length is in arg1
		size = arg1;
		trace_syscall(syscall_name, size, size);

		virt_arg0 = risc1_map_from_users(job_inst, arg0, &mapper,
						    &offset, &arg0, size);
		if (!virt_arg0)
			return -EINVAL;
		if (!arg0)
			return -EACCES;

		// dev_warn(core->dev, "strlen(virt_arg0) %d size %d\n",
		//		strlen(virt_arg0), size);
		WARN_ON(strlen(virt_arg0) != size);
		arg1 = arg2 = 0;
		needFlush = 0;
		self_processed = 0;
		break;
	case SC_TIMES: // (struct times *buf)
		size = sizeof(struct tms_compat);
		trace_syscall(syscall_name, size, 0);

		virt_arg0 = risc1_map_from_users(job_inst, arg0, &mapper,
						    &offset, &arg0, size);
		if (!virt_arg0)
			return -EINVAL;
		if (!arg0)
			return -EACCES;
		arg1 = arg2 = 0;
		needFlush = 1;
		self_processed = 0;
		break;
	case SC_GET_ENV: // (char *env, uint32_t *size)
		if (!arg1)
			return -EINVAL;
		size = sizeof(uint32_t);
		trace_syscall(syscall_name, size, 0);

		virt_arg1 = risc1_map_from_users(job_inst, arg1, &mapper,
						    &offset, &arg1, size);
		if (!virt_arg1)
			return -EINVAL;
		if (!arg1)
			return -EACCES;
		if (arg0) {
			size = *((u32 *) virt_arg1);
			virt_arg0 = risc1_map_from_users(job_inst, arg0,
							    &mapper, &offset,
							    &arg0, size);
			if (!virt_arg0)
				return -EINVAL;
			if (!arg0)
				return -EACCES;
		}
		needFlush = 1;
		self_processed = 0;
		break;
	default:
		return -EINVAL;
	}

	if (!self_processed) {
		job_inst->message.arg0 = arg0;
		job_inst->message.arg1 = arg1;
		job_inst->message.arg2 = arg2;
		job_inst->message.num = syscall_idx;
		job_inst->message.type = RISC1_MESSAGE_SYSCALL;
		job_inst->syscall_handled = 0;

		wake_up(&job_inst->poll_waitq);
		if (irq_timeout_msec)
			ret = !wait_event_timeout(job_inst->syscall_waitq,
					job_inst->syscall_handled ||
						job_inst->abort,
					msecs_to_jiffies(irq_timeout_msec));
		else {
			wait_event(job_inst->syscall_waitq,
				job_inst->syscall_handled ||
					job_inst->abort);
			ret = 0;
		}

		job_inst->syscall_handled = 0;
		job_inst->message.type = RISC1_MESSAGE_EMPTY;

		if (ret || job_inst->abort)
			return -ETIME;
	}

	if (needFlush) {
		//Flush CPU caches
		ret = sync_buffer(core, size, offset, mapper,
				  RISC1_BUF_SYNC_DIR_TO_DEVICE);
		if (ret)
			return ret;

		/* Invalidate RISC1 data cache */
		iowrite32(3 | (1 << 14),
			core->regs + (RISC1_CSR + 0 - RISC1_BASE));
	}

	if (risc1_syscall_debug)
		dev_warn(core->dev, "syscall return %d\n",
			job_inst->message.retval);

	risc1_write_reg(job_inst->message.retval, core, RISC1_ONCD_GRFCPU, 2);

	if (mode) {	// Continue execution
		epc = risc1_read_reg(core, RISC1_ONCD_GCP0, 14);
		risc1_write_reg(epc + 4, core, RISC1_ONCD_GCP0, 14);
		return 0;
	}

	/* Fix state */
	status = risc1_read_reg(core, RISC1_ONCD_GCP0, 12);
	status &= ~(1 << 1); // EXL
	risc1_write_reg(status, core, RISC1_ONCD_GCP0, 12);

	ret = risc1_read_reg(core, RISC1_ONCD_GRFCPU, 2);

	if (risc1_syscall_debug)
		dev_warn(core->dev, "after syscall result %d\n", ret);

	epc = risc1_read_reg(core, RISC1_ONCD_GCP0, 14);
	pc = epc + 4;
	mutex_lock(&core->reg_lock);
	iowrite32(pc, core->regs + (RISC1_OnCD + RISC1_ONCD_PC - RISC1_BASE));
	if (risc1_syscall_debug)
		dev_warn(core->dev, "after syscall pc 0x%08x\n", pc);

	/* check real pc */
	iowrite32(1, core->regs + (RISC1_OnCD + RISC1_ONCD_PCR - RISC1_BASE));
	pc = ioread32(core->regs + (RISC1_OnCD + RISC1_ONCD_PC - RISC1_BASE));
	mutex_unlock(&core->reg_lock);

	if (risc1_syscall_debug)
		dev_warn(core->dev, "after syscall real pc 0x%08x\n", pc);

	return 0;
}

int event_vcpu_handler(struct risc1_job_inst_desc *job_inst)
{
	struct risc1_priv *core = job_inst->core;
	u64 arg0, arg1, arg2, arg3;
	u64 virt_arg0;
	uint32_t epc, status;
	int needFlush, self_processed, ret;
	struct userptr_mapper *mapper;
	size_t offset, size;
	unsigned long flags_state;

	job_inst->message.type = RISC1_MESSAGE_EMPTY;
	spin_lock_irqsave(&job_inst->state_lock, flags_state);
	job_inst->state = RISC1_JOB_STATUS_SYSCALL;
	spin_unlock_irqrestore(&job_inst->state_lock, flags_state);

	/* Select syscall/event_vcpu mode */
	status = risc1_read_reg(core, RISC1_ONCD_GCP0, 12);
	if (status & (1 << 1)) { // EXL, exception !!
		uint32_t cause = risc1_read_reg(core, RISC1_ONCD_GCP0, 13);
		uint32_t command;
		epc = risc1_read_reg(core, RISC1_ONCD_GCP0, 14);
		command = risc1_read_mem(core, epc);

		if (event_vcpu_handler_debug) {
			dev_warn(core->dev,
					 "event_vcpu_handler syscall pc 0x%08x command 0x%08x status 0x%08x cause 0x%08x\n",
					 epc, command, status, cause);
		}

		if (((cause >> 2) & 0x1f) != 8) /* Syscall ? */
			return 1;

		return syscall_handler(job_inst, command, 1);
	}

	arg0 = risc1_read_reg(core, RISC1_ONCD_GRFCPU, 4);
	arg1 = risc1_read_reg(core, RISC1_ONCD_GRFCPU, 5);
	arg2 = risc1_read_reg(core, RISC1_ONCD_GRFCPU, 6);
	arg3 = risc1_read_reg(core, RISC1_ONCD_GRFCPU, 7);

	mutex_lock(&core->reg_lock);
	iowrite32(1, core->regs + (RISC1_OnCD + RISC1_ONCD_PCR - RISC1_BASE));
	epc = ioread32(core->regs + (RISC1_OnCD + RISC1_ONCD_PC - RISC1_BASE));
	mutex_unlock(&core->reg_lock);
	if (event_vcpu_handler_debug)
		dev_warn(core->dev, "event_vcpu_handler pc 0x%08x 0x%08x\n",
			epc, (uint32_t)arg0);

	switch(arg0) {
	case 1: // putchar
		if (event_vcpu_handler_debug)
			dev_warn(core->dev, "putchar %c\n", (char)arg1);

		self_processed = 0;
		break;
	case 2: // putstr
		if (event_vcpu_handler_debug)
			dev_warn(core->dev, "putstr\n");

		self_processed = 0;
		size = arg2;
		trace_syscall("putstr", 0, size);

		virt_arg0 = (u64)risc1_map_from_users(job_inst, arg1, &mapper,
						    &offset, &arg1, size);
		if (!virt_arg0)
			return -EINVAL;
		if (!arg1)
			return -EACCES;
		needFlush = 0;
		self_processed = 0;
		break;
	default:
		dev_warn(core->dev, "unknown EVENT call %lld\n", arg0);
		return -1;
	}

	if (!self_processed) {
		job_inst->message.arg0 = arg1;
		job_inst->message.arg1 = arg2;
		job_inst->message.arg2 = arg3;
		job_inst->message.num = arg0 + EVENT_VCPU_BASE;
		job_inst->message.type = RISC1_MESSAGE_SYSCALL;
		job_inst->syscall_handled = 0;

		wake_up(&job_inst->poll_waitq);
		if (irq_timeout_msec)
			ret = !wait_event_timeout(job_inst->syscall_waitq,
					job_inst->syscall_handled ||
						job_inst->abort,
					msecs_to_jiffies(irq_timeout_msec));
		else {
			wait_event(job_inst->syscall_waitq,
				job_inst->syscall_handled ||
					job_inst->abort);
			ret = 0;
		}

		job_inst->syscall_handled = 0;
		job_inst->message.type = RISC1_MESSAGE_EMPTY;

		if (ret || job_inst->abort)
			return -ETIME;
	}

	/* Fix return */
	risc1_write_reg(job_inst->message.retval, core, RISC1_ONCD_GRFCPU, 2);

	return 0;
}

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("ELcore-50 syscall implementations");
