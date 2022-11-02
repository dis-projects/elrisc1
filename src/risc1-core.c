// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright 2020-2022 RnD Center "ELVEES", JSC
 */

#include <linux/uaccess.h>

#include "risc1-core.h"
#include "risc1-syscall.h"

extern u32 irq_debug;
extern u32 job_debug;

int risc1_get_core_idx(struct risc1_priv *core, void __user *arg)
{
	u32 regval;
	struct risc1_device_info device_info;
	int ret;

	regval = risc1_read(core, DSP_IDR);

	device_info.nclusters = IDR_NCLUSTERS(regval);
	device_info.cluster_id = IDR_CLUSTER(regval);
	device_info.cluster_cap = IDR_CLUSTERCAP(regval);
	device_info.core_in_cluster_id = IDR_CORENUM(regval);

	ret = copy_to_user(arg, &device_info,
			   sizeof(struct risc1_device_info));
	if (ret)
		return ret;

	return 0;
}

int risc1_get_caps(struct risc1_priv *core, void __user *arg)
{
	struct risc1_caps risc1_caps;
	int ret;

	strcpy(risc1_caps.drvname, "risc1");
	risc1_caps.hw_id = risc1_read_reg(core, RISC1_ONCD_GCP0, 15);

	ret = copy_to_user(arg, &risc1_caps, sizeof(struct risc1_caps));
	if (ret)
		return ret;

	return 0;
}

void risc1_core_abort(struct risc1_priv *core)
{
	uint32_t value;

	/* switch off device interrupts and force-stop it */
	dev_warn(core->dev, "risc1_core_abort\n");
	mutex_lock(&core->reg_lock);
	iowrite32(0x4, core->regs + (RISC1_OnCD + RISC1_ONCD_IR - RISC1_BASE));
	value = ioread32(core->regs + (RISC1_OnCD + RISC1_ONCD_IR - RISC1_BASE));
	mutex_unlock(&core->reg_lock);

	dev_warn(core->dev, "risc1_core_abort %08x\n", value);
}

void print_dump(struct risc1_priv *core, int flags)
{
	uint32_t value;
	int i;

	mutex_lock(&core->reg_lock);
	if (flags & RISC1_DUMP_TOP)
	{
		value = ioread32(core->regs + (RISC1_URB + SDR_RISC1_PPOLICY - RISC1_BASE));
		dev_warn(core->dev, "RISC1 PPOLICY: %08x\n", value);

		value = ioread32(core->regs + (RISC1_URB + SDR_RISC1_PSTATUS - RISC1_BASE));
		dev_warn(core->dev, "RISC1 PSTATUS: %08x\n", value);

		value = ioread32(core->regs + (RISC1_URB + SDR_BBD_RST_CTL - RISC1_BASE));
		dev_warn(core->dev, "SDR_BBD_RST_CTL: %08x\n", value);

		value = ioread32(core->regs + (RISC1_URB + SDR_ACC_RST_CTL - RISC1_BASE));
		dev_warn(core->dev, "SDR_ACC_RST_CTL: %08x\n", value);
	}

	if (flags & RISC1_DUMP_ONCD)
	{
		/* Dump RISC1 OnCD registers */
		value = ioread32(core->regs + (RISC1_OnCD + RISC1_ONCD_IR - RISC1_BASE));
		dev_warn(core->dev, "IR     : %08x\n", value);

		value = ioread32(core->regs + (RISC1_OnCD + RISC1_ONCD_IDCODE - RISC1_BASE));
		dev_warn(core->dev, "IDCODE : %08x\n", value);

		value = ioread32(core->regs + (RISC1_OnCD + RISC1_ONCD_OSCR - RISC1_BASE));
		dev_warn(core->dev, "OSCR   : %08x\n", value);

		value = ioread32(core->regs + (RISC1_OnCD + RISC1_ONCD_OBCR - RISC1_BASE));
		dev_warn(core->dev, "OBCR   : %08x\n", value);

		iowrite32(1, core->regs + (RISC1_OnCD + RISC1_ONCD_PCDEC - RISC1_BASE));
		value = ioread32(core->regs + (RISC1_OnCD + RISC1_ONCD_PCDEC - RISC1_BASE));
		dev_warn(core->dev, "PCDEC  : %08x\n", value);

		iowrite32(1, core->regs + (RISC1_OnCD + RISC1_ONCD_PCEXE - RISC1_BASE));
		value = ioread32(core->regs + (RISC1_OnCD + RISC1_ONCD_PCEXE - RISC1_BASE));
		dev_warn(core->dev, "PCEXE  : %08x\n", value);

		iowrite32(1, core->regs + (RISC1_OnCD + RISC1_ONCD_PCMEM - RISC1_BASE));
		value = ioread32(core->regs + (RISC1_OnCD + RISC1_ONCD_PCMEM - RISC1_BASE));
		dev_warn(core->dev, "PCMEM  : %08x\n", value);

		iowrite32(1, core->regs + (RISC1_OnCD + RISC1_ONCD_PCR - RISC1_BASE));
		value = ioread32(core->regs + (RISC1_OnCD + RISC1_ONCD_PC - RISC1_BASE));
		dev_warn(core->dev, "PC     : %08x\n", value);

		iowrite32(1, core->regs + (RISC1_OnCD + RISC1_ONCD_PCWB - RISC1_BASE));
		value = ioread32(core->regs + (RISC1_OnCD + RISC1_ONCD_PCWB - RISC1_BASE));
		dev_warn(core->dev, "PCWB   : %08x\n", value);

		value = ioread32(core->regs + (RISC1_CSR + 0 - RISC1_BASE));
		dev_warn(core->dev, "CSR    : %08x\n", value);

		value = ioread32(core->regs + (RISC1_CSR + 4 - RISC1_BASE));
		dev_warn(core->dev, "EVENT  : %08x\n", value);
	}
	mutex_unlock(&core->reg_lock);

	if (flags & RISC1_DUMP_REG)
	{
		for (i = 0; i <= 31; i++)
		{
			value = risc1_read_reg(core, RISC1_ONCD_GRFCPU, i);
			dev_warn(core->dev, "R%02d : %08x\n", i, value);
		}
	}

	if (flags & RISC1_DUMP_FPU)
	{

		for (i = 0; i <= 31; i++)
		{
			value = risc1_read_reg(core, RISC1_ONCD_GRFFPU, i);
			dev_warn(core->dev, "F%02d : %08x\n", i, value);
		}
	}

	if (flags & RISC1_DUMP_CP0)
	{
		for (i = 0; i <= 31; i++)
		{
			value = risc1_read_reg(core, RISC1_ONCD_GCP0, i);
			dev_warn(core->dev, "CP0.%02d : %08x\n", i, value);
		}
	}

	if (flags & RISC1_DUMP_HILO)
	{
		value = risc1_read_reg(core, RISC1_ONCD_GHILO, 0);
		dev_warn(core->dev, "Lo : %08x\n", value);

		value = risc1_read_reg(core, RISC1_ONCD_GHILO, 1);
		dev_warn(core->dev, "Hi : %08x\n", value);
	}

	if (flags & RISC1_DUMP_CP1)
	{
		value = risc1_read_reg(core, RISC1_ONCD_GCP1, 0);
		dev_warn(core->dev, "FIR  : %08x\n", value);
		value = risc1_read_reg(core, RISC1_ONCD_GCP1, 1);
		dev_warn(core->dev, "FCSR : %08x\n", value);
		value = risc1_read_reg(core, RISC1_ONCD_GCP1, 2);
		dev_warn(core->dev, "FDLY : %08x\n", value);
	}

	if (flags & RISC1_DUMP_TLB)
	{
		/* TLB output */
		for (i = 0; i < 16; i++)
		{
			value = risc1_read_reg(core, RISC1_ONCD_GTLB0, i);
			dev_warn(core->dev, "TLB0.%x : %08x\n", i, value);
			value = risc1_read_reg(core, RISC1_ONCD_GTLB1, i);
			dev_warn(core->dev, "TLB1.%x : %08x\n", i, value);
			value = risc1_read_reg(core, RISC1_ONCD_GTLBV, i);
			dev_warn(core->dev, "TLBW.%x : %08x\n", i, value);
			value = risc1_read_reg(core, RISC1_ONCD_GTLBV, i) + 0x10;
			dev_warn(core->dev, "TLBV.%x : %08x\n", i, value);
		}
	}

	if (flags & RISC1_DUMP_MEM) {
		mutex_lock(&core->reg_lock);
		value = ioread32(core->regs + (RISC1_OnCD + RISC1_ONCD_OSCR - RISC1_BASE));
		iowrite32(value | 3, core->regs + (RISC1_OnCD + RISC1_ONCD_OSCR - RISC1_BASE));
		mutex_unlock(&core->reg_lock);
		for (i = 0x10000000; i <= 0x10000500; i += 4) {
			value = risc1_read_mem(core, i);
			dev_warn(core->dev, "m %08x: %08x\n", i, value);
		}

	}
}

void risc1_core_reset(struct risc1_priv *core)
{
	uint32_t value;

	value = ioread32(core->regs + (RISC1_URB + SDR_RISC1_PSTATUS - RISC1_BASE));

	/* Warm reset */
	if (value != RISC1_PPOLICY_PP_WARM_RST) {
		int count = 100;
		iowrite32(RISC1_PPOLICY_PP_WARM_RST, core->regs + (RISC1_URB + SDR_RISC1_PPOLICY - RISC1_BASE));
		do {
			value = ioread32(core->regs + (RISC1_URB + SDR_RISC1_PSTATUS - RISC1_BASE));
			if (job_debug)
				dev_warn(core->dev, "RISC1 PSTATUS: %08x\n", value);
		} while(value != RISC1_PPOLICY_PP_WARM_RST && count-- > 0);
	}

	value = ioread32(core->regs + (RISC1_URB + SDR_RISC1_PSTATUS - RISC1_BASE));
	if (job_debug)
		dev_warn(core->dev, "RISC1 PSTATUS: %08x\n", value);

	/* PPON */
	if (value != RISC1_PPOLICY_PP_ON) {
		int count = 100;
		iowrite32(RISC1_PPOLICY_PP_ON, core->regs + (RISC1_URB + SDR_RISC1_PPOLICY - RISC1_BASE));
		do {
			value = ioread32(core->regs + (RISC1_URB + SDR_RISC1_PSTATUS - RISC1_BASE));
			if (job_debug)
				dev_warn(core->dev, "RISC1 PSTATUS: %08x\n", value);
		} while(value != RISC1_PPOLICY_PP_ON && count-- > 0);
	}

	mutex_lock(&core->reg_lock);
	iowrite32(1, core->regs + (RISC1_OnCD + RISC1_ONCD_PCR - RISC1_BASE));
	value = ioread32(core->regs + (RISC1_OnCD + RISC1_ONCD_PC - RISC1_BASE));
	if (job_debug)
		dev_warn(core->dev, "PC6    : %08x\n", value);

	/* Final reset initialization */
	value = ioread32(core->regs + (RISC1_CSR + 0 - RISC1_BASE));
	iowrite32(value | (1 << 1) | (1 << 12)| (1 << 14), core->regs + (RISC1_CSR + 0 - RISC1_BASE));
	iowrite32(0x7, (core->regs + (RISC1_URB + SDR_ACC_RST_CTL - RISC1_BASE)));
	iowrite32(0x44 , core->regs + (RISC1_OnCD + RISC1_ONCD_IR - RISC1_BASE));
	iowrite32(0x50 , core->regs + (RISC1_OnCD + RISC1_ONCD_IR - RISC1_BASE));
	mutex_unlock(&core->reg_lock);
}

static void risc1_iommu_irq(struct risc1_priv *core, int i)
{
	uint32_t reg_tmp;

	/* Select TLB */
	iowrite32((i ^ 1) << 1, core->regs + (RISC1_VMMU + 0x0c - RISC1_BASE));
	dev_warn(core->dev, "TLB%d\n", i);
	reg_tmp = ioread32(core->regs + (RISC1_VMMU + 0x10 - RISC1_BASE)); // TLBXCPT_ADDR
	dev_warn(core->dev, "TLBXCPT_ADDR: 0x%08x\n", reg_tmp);
	reg_tmp = ioread32(core->regs + (RISC1_VMMU + 0x14 - RISC1_BASE)); // TLBXCPT_TYPE
	dev_warn(core->dev, "TLBXCPT_TYPE: 0x%x\n", reg_tmp);

	/* Skip transaction */
	reg_tmp = 1 << (5 + (i & 1));
	iowrite32(reg_tmp, core->regs + (RISC1_VMMU + 0x40 + 4 * i - RISC1_BASE)); // TLB_CTRL
}

irqreturn_t risc1_irq(int irq, void *priv)
{

	struct risc1_priv *core = (struct risc1_priv *) priv;
	struct risc1_job_inst_desc *desc;
	unsigned long flags;
	int empty;
	static int counter = 100;

	if(irq_debug)
		printk(KERN_INFO "risc1_irq %d\n", irq);

	if (irq == core->irqs[0]) { // IOMMU/VMMU
		uint32_t reg_tmp, ntlbs;
		int i;

		reg_tmp = ioread32(core->regs + (RISC1_VMMU + 8 - RISC1_BASE)); // PTW_CFG
		ntlbs = (reg_tmp >> 11) & 0xf;

		for (i = 0; i < 4; i++) {
			if (ntlbs & (1 << i)) {
				risc1_iommu_irq(core, i);
			}
		}

		goto finish;
	}

	spin_lock_irqsave(&core->queue_lock, flags);
	desc = list_first_entry(&core->job_queue,
				struct risc1_job_inst_desc,
				queue_node);
	empty = list_empty(&core->job_queue);
	spin_unlock_irqrestore(&core->queue_lock, flags);

	// Clear event
	iowrite32(0, core->regs + (RISC1_CSR + 4 - RISC1_BASE));

	if (empty) {
		dev_err(core->dev, "IRQ received, but no jobs in queue!\n");
		return IRQ_NONE;
	}

	desc->irq_state = 1;
	wake_up(&desc->irq_waitq);

	if (irq_debug && counter > 0) {
		counter--;
		dev_warn(core->dev, "RISC1 IRQ received %d\n", irq);
	}

finish:
	return IRQ_HANDLED;
}

