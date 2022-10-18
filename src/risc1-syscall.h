/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright 2020 RnD Center "ELVEES", JSC
 */

#ifndef _LINUX_RISC1_SYSCALL_H
#define _LINUX_RISC1_SYSCALL_H

#include "risc1-job-instance.h"

int syscall_handler(struct risc1_job_inst_desc *job_inst, uint32_t command, int mode);
int event_vcpu_handler(struct risc1_job_inst_desc *job_inst);

#endif
