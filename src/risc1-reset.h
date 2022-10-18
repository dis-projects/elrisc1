/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright 2020 RnD Center "ELVEES", JSC
 */
#ifndef _LINUX_RISC1_RESET_H
#define _LINUX_RISC1_RESET_H

#include "risc1-core.h"

void risc1_reset_fini(struct risc1_priv *drv_priv);
int risc1_reset_init(struct risc1_priv *drv_priv);

#endif
