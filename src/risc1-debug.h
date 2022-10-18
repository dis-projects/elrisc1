/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright 2021 RnD Center "ELVEES", JSC
 */
#ifndef _LINUX_RISC1_DEBUG_H
#define _LINUX_RISC1_DEBUG_H

#include "risc1-job-instance.h"

extern int mod_dbg_registers;

/*
 * Internal debug job instance data structure
 */
struct risc1_job_inst_dbg_desc {
	struct risc1_job_inst_desc *inst;
	struct file *inst_file;
};

enum risc1_job_inst_dbg_rw {
	RISC1_JOB_INST_DBG_READ,
	RISC1_JOB_INST_DBG_WRITE
};

int risc1_job_dbg_attach(struct risc1_priv *core, void __user *arg);
int export_dbg_fd(struct risc1_job_inst_dbg_desc *inst_desc);
long risc1_dbg_ioctl_safe(struct file *file, unsigned int cmd,
			     unsigned long arg);

#endif
