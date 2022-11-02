/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright 2020 RnD Center "ELVEES", JSC
 */
#ifndef _LINUX_RISC1_CORE_H
#define _LINUX_RISC1_CORE_H

#include <linux/cdev.h>
#include <linux/clk.h>
#include <linux/clk-provider.h>
#include <linux/delay.h>
#include <linux/kernel.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/sizes.h>
#include <linux/types.h>

#include "risc1.h"
#include "regs.h"

extern u32 reg_dump_enable;

struct risc1_priv { // cluster_priv + elcore50_core
	int nirqs;
	dev_t dev_num;
	unsigned int *irqs;
	struct device *dev;
	struct device *devc;
	void __iomem *mem;
	void __iomem *regs;
	struct reset_control *resets;
	int clock_count;
	struct clk **clocks;
	struct cdev cdev;
	int cdev_idr;
	/* the list is used for a) telling interrupts which job is current and
	 * b) cleaning up all jobs on remove() */
	struct list_head job_queue;
	struct workqueue_struct *work_q;
	spinlock_t queue_lock;
    void __iomem *risc1_regs;
	struct mutex reg_lock;
};

static inline void risc1_buf_cpy(struct risc1_priv *drv_priv,
				    void __iomem *dst, void *src, size_t size)
{
	memcpy_toio(dst, src, size);
}

static inline u32 risc1_read_reg(struct risc1_priv *core,
	unsigned int const group, unsigned int const reg)
{
	u32 code = group;
	u32 result;

	/* Read reg by OnCD */
	if (group < 2) {
		code |= reg << 16;
	} else {
		code |= reg << 3;
	}

	mutex_lock(&core->reg_lock);
	iowrite32(code, core->regs + (RISC1_OnCD +  RISC1_ONCD_IRDEC - RISC1_BASE));
	iowrite32(0, core->regs + (RISC1_OnCD +  RISC1_ONCD_REGFR - RISC1_BASE));
	result = ioread32(core->regs + (RISC1_OnCD +  RISC1_ONCD_REGF - RISC1_BASE));
	mutex_unlock(&core->reg_lock);

	return result;
}

static inline void risc1_write_reg(u32 const value, struct risc1_priv *core,
	unsigned int const group, unsigned int const reg)
{
	u32 code = group | (reg << 3);

	mutex_lock(&core->reg_lock);
	iowrite32(code, core->regs + (RISC1_OnCD +  RISC1_ONCD_IRDEC - RISC1_BASE));
	iowrite32(value, core->regs + (RISC1_OnCD +  RISC1_ONCD_REGF - RISC1_BASE));
	mutex_unlock(&core->reg_lock);
}

static inline u32 risc1_get_paddr(u32 addr)
{
	if (addr >= 0xc0000000)
		return addr;
	if (addr >= 0xa0000000)
		return addr - 0xa0000000;
	return addr & 0x7fffffff;
}

static inline u32 risc1_read_mem(struct risc1_priv *core, uint32_t addr)
{
	int count = 100;
	uint32_t value;
	uint32_t paddr = risc1_get_paddr(addr);

	mutex_lock(&core->reg_lock);
	iowrite32(paddr, core->regs + (RISC1_OnCD + RISC1_ONCD_OMAR - RISC1_BASE));
	iowrite32(0xd, core->regs + (RISC1_OnCD + RISC1_ONCD_MEM - RISC1_BASE));

	do
	{
		value = ioread32(core->regs + (RISC1_OnCD + RISC1_ONCD_OSCR - RISC1_BASE));
	} while (!(value & (1 << 5)) && count-- > 0);
	if (count <= 0) {
		dev_warn(core->dev, "Memory timeout for 0x%8x\n", paddr);
	}

	value = ioread32(core->regs + (RISC1_OnCD + RISC1_ONCD_OMDR - RISC1_BASE));
	mutex_unlock(&core->reg_lock);

	return value;
}

static inline u32 risc1_read(struct risc1_priv *core,
				unsigned int const reg)
{
	u32 value = ioread32(core->risc1_regs + reg);

	dev_dbg(core->dev, "rd reg 0x%08x val 0x%08x\n",
		(unsigned int) reg, value);
	return value;
}

static inline u64 risc1_read64(struct risc1_priv *core,
				  unsigned int const reg)
{
	u64 value;

	value = readq(core->risc1_regs + reg);

	dev_dbg(core->dev, "rd reg 0x%0x val 0x%016llx\n",
		(unsigned int) reg, value);
	return value;
}

static inline void risc1_write(u32 const value, struct risc1_priv *core,
				  unsigned int const reg)
{
	dev_dbg(core->dev, "wr reg 0x%08x val 0x%x\n",
		(unsigned int) reg, value);
	iowrite32(value, core->risc1_regs + reg);
}

#define risc1_pollreg(core, addr, val, cond, sleep_us) \
({ \
	might_sleep_if(sleep_us); \
	for (;;) { \
		(val) = risc1_read(core, addr); \
		if (cond) \
			break; \
		if (sleep_us) \
			usleep_range((sleep_us >> 2) + 1, sleep_us); \
	} \
	0; \
})

#define risc1_pollreg_timeout(core, addr, val, cond, sleep_us, timeout_us) \
({ \
	ktime_t timeout = ktime_add_us(ktime_get(), timeout_us); \
	might_sleep_if(sleep_us); \
	for (;;) { \
		(val) = risc1_read(core, addr); \
		if (cond) \
			break; \
		if (timeout_us && ktime_compare(ktime_get(), timeout) > 0) { \
			(val) = risc1_read(core, addr); \
			break; \
		} \
		if (sleep_us) \
			usleep_range((sleep_us >> 2) + 1, sleep_us); \
	} \
	(cond) ? 0 : -ETIMEDOUT; \
})

void risc1_buf_cpy(struct risc1_priv *drv_priv, void __iomem *dst,
		      void *src, size_t size);
u32 risc1_read(struct risc1_priv *core, unsigned int const reg);
u64 risc1_read64(struct risc1_priv *core, unsigned int const reg);
void risc1_write(u32 const value, struct risc1_priv *core,
		    unsigned int const reg);
int risc1_get_core_idx(struct risc1_priv *core, void __user *arg);
int risc1_get_caps(struct risc1_priv *core, void __user *arg);
void risc1_core_abort(struct risc1_priv *core);
void print_dump(struct risc1_priv *core, int flags);
void risc1_core_reset(struct risc1_priv *core);
int risc1_core_stopped(struct risc1_priv *core);
irqreturn_t risc1_irq(int irq, void *priv);

#endif
