// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright 2018-2022 RnD Center "ELVEES", JSC
 */

#include <linux/debugfs.h>
#include <linux/idr.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/pm_runtime.h>
#include <linux/of_address.h>

#include "risc1-job-instance.h"
#include "risc1-debug.h"
#include "risc1-syscall.h"
#include "risc1-reset.h"

static struct class *elrisc1_class;

static struct dentry *pdentry;

static struct idr risc1_idr;
static spinlock_t risc1_idr_lock;

int mod_caches = 3;
int mod_dbg_registers;

u32 irq_timeout_msec;
u32 reg_dump_enable;
u32 event_handler_debug;
u32 core_debug;
u32 risc1_write_regs_debug;
u32 risc1_map_from_users_debug;
u32 risc1_syscall_debug;
u32 exception_debug;
u32 event_vcpu_handler_debug;
u32 irq_debug;
u32 job_debug;

module_param_named(caches, mod_caches, int, 0);
module_param_named(dbg_registers_simple, mod_dbg_registers, int, 0);

/* RUNTIME POWER MANAGEMENT FUNCTIONS */

static int risc1_runtime_suspend(struct device *dev)
{
	struct risc1_priv *drv_priv = dev_get_drvdata(dev);
	int i;

	for (i = 0; i < drv_priv->clock_count; ++i)
		clk_disable(drv_priv->clocks[i]);

	return 0;
}

static int risc1_runtime_resume(struct device *dev)
{
	struct risc1_priv *drv_priv = dev_get_drvdata(dev);
	int ret, i;

	for (i = 0; i < drv_priv->clock_count; ++i) {
		ret = clk_enable(drv_priv->clocks[i]);
		if (ret < 0) {
			dev_err(dev, "could not enable %d clock\n", i);
			goto err_suspend;
		}
	}
	return 0;
err_suspend:
	while (i >= 0)
		clk_disable(drv_priv->clocks[--i]);

	return ret;
}

/* END POWER MANAGEMENT FUNCTIONS */

/* FILE FUNCTIONS */

static int risc1_open(struct inode *inode, struct file *file)
{
	struct risc1_priv *core;
	int ret;

	core = container_of(inode->i_cdev, struct risc1_priv, cdev);

	file->private_data = core;

	ret = pm_runtime_get_sync(core->dev);

	return ret < 0 ? ret : 0;
}

static long risc1_ioctl(struct file *file, unsigned int cmd,
			   unsigned long arg)
{
	struct risc1_priv *pdata =
		(struct risc1_priv *)file->private_data;
	void __user *const uptr = (void __user *)arg;

	switch (cmd) {
	case RISC1_IOC_CREATE_JOB:
		return risc1_create_job(file, uptr);
	case RISC1_IOC_ENQUEUE_JOB:
		return risc1_enqueue_job_inst(pdata, uptr);
	case RISC1_IOC_GET_JOB_STATUS:
		return risc1_get_job_inst_status(pdata, uptr);
	case RISC1_IOC_GET_JOB_COUNT:
		return risc1_get_job_inst_count(pdata, uptr);
	case RISC1_IOC_GET_JOB_LIST:
		return risc1_get_job_inst_list(pdata, uptr);
	case RISC1_IOC_DBG_JOB_ATTACH:
		return risc1_job_dbg_attach(pdata, uptr);
	case RISC1_IOC_GET_CORE_IDX:
		return risc1_get_core_idx(pdata, uptr);
	case RISC1_IOC_CREATE_MAPPER:
		return risc1_create_mapper(pdata, uptr);
	case RISC1_IOC_CREATE_BUFFER:
		return risc1_create_buffer(pdata, uptr);
	case RISC1_IOC_SYNC_BUFFER:
		return risc1_sync_buffer(pdata, uptr);
	case RISC1_IOC_DUMP:
		print_dump(pdata, arg);
		return 0;
	case RISC1_GET_CAPS:
		return risc1_get_caps(pdata, uptr);
	}
	return -ENOTTY;
}

static int risc1_release(struct inode *inode, struct file *file)
{
	struct risc1_priv *core;

	core = container_of(inode->i_cdev, struct risc1_priv, cdev);

	pm_runtime_put(core->dev);

	return 0;
}

// TODO: remove it after debug
static int risc1_mmap(struct file *file, struct vm_area_struct *vma)
{
	unsigned long size, phys = 0x0;
	unsigned long baddr = vma->vm_pgoff << PAGE_SHIFT;
	int retval;

	size = vma->vm_end - vma->vm_start;

	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
	vma->vm_flags |= VM_DONTEXPAND | VM_DONTDUMP;

	/*printk(KERN_INFO "baddr 0x%lx size 0x%lx\n", baddr, size);*/
	vma->vm_pgoff = 0;
	retval = vm_iomap_memory(vma, phys + baddr, size);
	if (retval) {
		printk(KERN_INFO "mmap: remap failed with error %d. ", retval);
		return -ENOMEM;
	}

	return 0;
}

static const struct file_operations risc1_fops = {
	.owner = THIS_MODULE,
	.open = risc1_open,
	.unlocked_ioctl = risc1_ioctl,
	.release = risc1_release,
	.mmap = risc1_mmap,
};

/* END FILE FUNCTIONS */

/* PROBE/INIT/DESTROY */

static int risc1_core_init(struct risc1_priv *core,
			      struct risc1_priv *drv_priv,
			      unsigned int major, unsigned int minor)
{
	struct device *dev;
	int ret;

	dev_info(drv_priv->dev, "risc1_core_init\n");
	cdev_init(&core->cdev, &risc1_fops);
	ret = cdev_add(&core->cdev, MKDEV(major, minor), 1);
	if (ret < 0) {
		dev_err(drv_priv->dev, "Failed to add RISC1 cdev\n");
		goto err_none;
	}

	dev_info(drv_priv->dev, "risc1_core_init before idr\n");
	idr_preload(GFP_KERNEL);
	spin_lock(&risc1_idr_lock);

	core->cdev_idr = idr_alloc(&risc1_idr, core, 0, ~0, GFP_KERNEL);

	spin_unlock(&risc1_idr_lock);
	idr_preload_end();

	if (core->cdev_idr < 0)  {
		dev_err(drv_priv->dev, "Failed to allocate RISC1 cdev\n");
		goto err_none;
	}

	dev_info(drv_priv->dev, "risc1_core_init before device_create\n");
	dev = device_create(elrisc1_class, drv_priv->dev,
				MKDEV(major, minor),
				NULL, "risc1");
	if (IS_ERR(dev)) {
		/* this way we can be assured cores[i] is deallocated */
		dev_err(drv_priv->dev, "Failed to create RISC1 device\n");
		ret = PTR_ERR(dev);
		goto err_cdev;
	}
	core->devc = dev;

	dev_info(drv_priv->dev, "risc1_core_init before workqueue\n");
	INIT_LIST_HEAD(&core->job_queue);
	spin_lock_init(&core->queue_lock);
	core->work_q = alloc_ordered_workqueue("risc1-wq%i", 0,
					       core->cdev_idr);
	if (!core->work_q) {
		dev_err(core->dev, "Failed to allocate workqueue\n");
		ret = -ENOMEM;
		goto err_device;
	}
	return 0;
err_device:
	device_destroy(elrisc1_class, MKDEV(major, minor));
err_cdev:
	cdev_del(&core->cdev);
err_none:
	if (core->cdev_idr)
		idr_remove(&risc1_idr, core->cdev_idr);
	return ret;
}

static void risc1_core_destroy(struct risc1_priv *core,
				  struct risc1_priv *drv_priv)
{
	struct risc1_job_inst_desc *cursor, *store;

	list_for_each_entry_safe(cursor, store, &core->job_queue, queue_node) {
		risc1_cancel_job_inst(cursor);
	}
	destroy_workqueue(core->work_q);
	device_destroy(elrisc1_class, core->cdev.dev);
	cdev_del(&core->cdev);
	idr_remove(&risc1_idr, core->cdev_idr);
}

static int risc1_cores_init(struct risc1_priv *drv_priv)
{
	int ret, major, minor; //, i;

	ret = alloc_chrdev_region(&drv_priv->dev_num, 0, 1, "risc1");
	if (ret < 0) {
		dev_err(drv_priv->dev, "Failed to allocate chrdev region\n");
		return ret;
	}

	major = MAJOR(drv_priv->dev_num);
	minor = MINOR(drv_priv->dev_num);

	ret = risc1_core_init(drv_priv, drv_priv, major, minor);
	if (ret) {
			dev_err(drv_priv->dev, "Failed to initialize risc1\n");
			goto err_dev;
	}
	return 0;

err_dev:
	unregister_chrdev_region(drv_priv->dev_num, 1);
	return ret;
}

static void risc1_free_irqs(struct risc1_priv *drv_priv)
{
	int irq;

	for (irq = 0; irq < drv_priv->nirqs; ++irq)
	{
		if (drv_priv->irqs[irq] == 0)
			break;
		devm_free_irq(drv_priv->dev,
					  drv_priv->irqs[irq],
					  drv_priv);
	}

	devm_kfree(drv_priv->dev, drv_priv->irqs);
}

static void risc1_cores_destroy(struct risc1_priv *drv_priv)
{
	risc1_free_irqs(drv_priv);
	unregister_chrdev_region(drv_priv->dev_num, 1);
}

static int risc1_clock_init(struct risc1_priv *drv_priv)
{
	struct device_node *np = drv_priv->dev->of_node;
	int i, ret;

	drv_priv->clock_count = of_clk_get_parent_count(np);
	if (!drv_priv->clock_count)
		return 0;

	drv_priv->clocks = devm_kcalloc(drv_priv->dev, drv_priv->clock_count,
					sizeof(struct clk *), GFP_KERNEL);
	if (!drv_priv->clocks)
		return -ENOMEM;

	for (i = 0; i < drv_priv->clock_count; ++i) {
		drv_priv->clocks[i] = of_clk_get(np, i);
		if (drv_priv->clocks[i]) {
			ret = clk_prepare_enable(drv_priv->clocks[i]);
			if (ret) {
				dev_err(drv_priv->dev, "clock %d error: %ld\n",
					i, PTR_ERR(drv_priv->clocks[i]));
				clk_put(drv_priv->clocks[i]);
				drv_priv->clocks[i] = NULL;
				return ret;
			}
		}
	}

	return 0;
}

static void risc1_clock_destroy(struct risc1_priv *drv_priv)
{
	int i;

	if (!drv_priv->clocks)
		return;

	for (i = 0; i < drv_priv->clock_count; ++i) {
		if (drv_priv->clocks[i]) {
			clk_unprepare(drv_priv->clocks[i]);
			clk_put(drv_priv->clocks[i]);
		}
	}

	devm_kfree(drv_priv->dev, drv_priv->clocks);
}

static int risc1_probe(struct platform_device *pdev)
{
	struct risc1_priv *drv_priv;
	int ret;
	struct device_node *target;
#ifndef RISC1_MCOM03
	uint32_t tmp_read;
#endif

	int i, count;

	struct resource *res;
	//struct resource r;
	uint32_t value;

	drv_priv = devm_kzalloc(&pdev->dev, sizeof(struct risc1_priv),
				GFP_KERNEL);
	if (!drv_priv)
		return -ENOMEM;
	drv_priv->dev = &pdev->dev;

	dev_info(drv_priv->dev, "risc1_probe\n");

	ret = risc1_reset_init(drv_priv);
	if (ret)
		return ret;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!res) {
		dev_err(&pdev->dev, "Failed to get registers\n");
		return -ENOENT;
	}

	ret = dma_set_mask(&pdev->dev, DMA_BIT_MASK(64));
	if (ret) {
		dev_err(&pdev->dev, "Failed to set DMAMASK\n");
		return ret;
	}

	drv_priv->regs = devm_ioremap_resource(&pdev->dev, res);
	if (IS_ERR(drv_priv->regs)) {
		dev_err(&pdev->dev, "Failed to map registers: %ld\n",
			PTR_ERR(drv_priv->regs));
		return PTR_ERR(drv_priv->regs);
	}

#if 0
	res = platform_get_resource(pdev, IORESOURCE_MEM, 1);
	if (!res) {
		dev_err(&pdev->dev, "Failed to get mem\n");
		return -ENOENT;
	}

	drv_priv->surb_regs = devm_ioremap_resource(&pdev->dev, res);
	if (IS_ERR(drv_priv->surb_regs)) {
		dev_err(&pdev->dev, "Failed to map surb registers: %ld\n",
			PTR_ERR(drv_priv->surb_regs));
		return PTR_ERR(drv_priv->surb_regs);
	}
#endif

	res = platform_get_resource(pdev, IORESOURCE_MEM, 1);
	if (!res) {
		dev_err(&pdev->dev, "Failed to get mem\n");
		return -ENOENT;
	}

	drv_priv->mem = devm_ioremap_resource(&pdev->dev, res);
	if (IS_ERR(drv_priv->mem)) {
		dev_err(&pdev->dev, "Failed to map mem: %ld\n",
			PTR_ERR(drv_priv->mem));
		return PTR_ERR(drv_priv->mem);
	}

#if 0
	target = of_parse_phandle(pdev->dev.of_node, "memory-region", 0);
	if (!target) {
		dev_err(&pdev->dev, "Failed to get memory-region\n");
		return -ENOENT;
	}

	ret = of_address_to_resource(target, 0, &r);
	if (ret) {
  		dev_err(&pdev->dev, "No memory address assigned to the region\n");
  		return ret;
	}

	drv_priv->mem = devm_ioremap_resource(&pdev->dev, &r);
	if (IS_ERR(drv_priv->mem)) {
		dev_err(&pdev->dev, "Failed to map registers\n");
		return PTR_ERR(drv_priv->mem);
	}
#endif

	dev_info(drv_priv->dev, "risc1_probe clocks init\n");

	ret = risc1_clock_init(drv_priv);
	if (ret)
		goto err_clock;

	pm_runtime_set_active(drv_priv->dev);
	pm_runtime_enable(drv_priv->dev);

	dev_info(drv_priv->dev, "risc1_probe before risc1_cores_init\n");
	ret = risc1_cores_init(drv_priv);
	if (ret)
		return ret;

	dev_info(drv_priv->dev, "risc1_probe before irq initialization\n");

	drv_priv->nirqs = platform_irq_count(pdev);
	drv_priv->irqs = devm_kcalloc(&pdev->dev, drv_priv->nirqs,
				      sizeof(unsigned int),
				      GFP_KERNEL | __GFP_ZERO);
	if (!drv_priv->irqs) {
		ret = -ENOMEM;
		goto err_device;
	}

	for (i = 0; i < drv_priv->nirqs; i++) {
		drv_priv->irqs[i] = platform_get_irq(pdev, i);
		if (drv_priv->irqs[i] < 0) {
			dev_err(&pdev->dev,
				"Failed to get interrupt\n");
			ret = drv_priv->irqs[i];
			goto err_irq;
		}
		ret = devm_request_irq(&pdev->dev, drv_priv->irqs[i],
				       risc1_irq, IRQF_SHARED,
				       "risc1",
					   drv_priv);

		if (ret) {
			dev_err(&pdev->dev,
				"Failed to get interrupt resource\n");
			ret = -EINVAL;
			goto err_irq;
		}
		dev_info(drv_priv->dev, "risc1 irq %d\n", drv_priv->irqs[i]);
	}
	dev_info(drv_priv->dev, "risc1_probe before platform_set_drvdata\n");
	platform_set_drvdata(pdev, drv_priv);

	dev_info(drv_priv->dev, "risc1_probe before pm_runtime_suspend\n");
	pm_runtime_suspend(drv_priv->dev);

	mutex_init(&drv_priv->reg_lock);
	dev_info(drv_priv->dev, "RISC1 core initialized at %px\n",
		 drv_priv);

	drv_priv->risc1_regs = drv_priv->regs; // + (RISC1_VMMU - RISC1_BASE);

	value = ioread32(drv_priv->regs + (RISC1_URB + SDR_BBD_RST_CTL - RISC1_BASE));
	dev_warn(drv_priv->dev, "SDR_BBD_RST_CTL: %08x\n", value);
	iowrite32(1, drv_priv->regs + (RISC1_URB + SDR_BBD_RST_CTL - RISC1_BASE));

	value = ioread32(drv_priv->regs + (RISC1_URB + SDR_PCI_RST_CTL - RISC1_BASE));
	dev_warn(drv_priv->dev, "SDR_PCI_RST_CTL: %08x\n", value);
	iowrite32(1, drv_priv->regs + (RISC1_URB + SDR_PCI_RST_CTL - RISC1_BASE));

	value = ioread32(drv_priv->regs + (RISC1_URB + SDR_EXT_RST_CTL - RISC1_BASE));
	dev_warn(drv_priv->dev, "SDR_EXT_RST_CTL: %08x\n", value);
	iowrite32(1, drv_priv->regs + (RISC1_URB + SDR_EXT_RST_CTL - RISC1_BASE));

	value = ioread32(drv_priv->regs + (RISC1_URB + SDR_RISC1_PPOLICY - RISC1_BASE));
	dev_warn(drv_priv->dev, "RISC1 PPOLICY: %08x\n", value);
	value = ioread32(drv_priv->regs + (RISC1_URB + SDR_RISC1_PSTATUS - RISC1_BASE));
	dev_warn(drv_priv->dev, "RISC1 PSTATUS: %08x\n", value);
	value = ioread32(drv_priv->regs + (RISC1_URB + SDR_ACC_RST_CTL - RISC1_BASE));
	dev_warn(drv_priv->dev, "RISC1 SDR_ACC_RST_CTL: %08x\n", value);

#if 0
	value = ioread32(drv_priv->surb_regs + SURB_SDR_PPOLICY);
	dev_warn(drv_priv->dev, "SURB_SDR_PPOLICY: %08x\n", value);
	value = ioread32(drv_priv->surb_regs + SURB_SDR_PSTATUS);
	dev_warn(drv_priv->dev, "SURB_SDR_PSTATUS: %08x\n", value);
	value = ioread32(drv_priv->surb_regs + SURB_SDR_DBGEN);
	dev_warn(drv_priv->dev, "SURB_SDR_DBGEN: %08x\n", value);
#endif

	value = ioread32(drv_priv->regs + (RISC1_URB + SDR_RISC1_PSTATUS - RISC1_BASE));
	dev_warn(drv_priv->dev, "RISC1 PSTATUS: %08x\n", value);
	/* PPON */
	if (value != RISC1_PPOLICY_PP_ON) {
		int count = 100;
		iowrite32(RISC1_PPOLICY_PP_ON, drv_priv->regs + (RISC1_URB + SDR_RISC1_PPOLICY - RISC1_BASE));
		do {
			value = ioread32(drv_priv->regs + (RISC1_URB + SDR_RISC1_PSTATUS - RISC1_BASE));
			dev_warn(drv_priv->dev, "RISC1 PSTATUS: %08x\n", value);
		} while(value != RISC1_PPOLICY_PP_ON && count-- > 0);
	}

	/* Program */
	dev_info(drv_priv->dev, "risc1 mem init\n");
	iowrite32(0x1000ffff, drv_priv->mem);	/* 1: b 1b */
	iowrite32(0x0, drv_priv->mem + 4);		/* nop */

	dev_info(drv_priv->dev, "risc1 IR init\n");
	iowrite32(0x44 , drv_priv->regs + (RISC1_OnCD + RISC1_ONCD_IR - RISC1_BASE));

	value = ioread32(drv_priv->regs + (RISC1_CSR + 0 - RISC1_BASE));
	iowrite32(value | 1 | (1 << 1) | (1 << 12)| (1 << 14), drv_priv->regs + (RISC1_CSR + 0 - RISC1_BASE));

	value = ioread32(drv_priv->regs + (RISC1_OnCD + RISC1_ONCD_OSCR - RISC1_BASE));
	iowrite32(value | 3, drv_priv->regs + (RISC1_OnCD + RISC1_ONCD_OSCR - RISC1_BASE));

	iowrite32(1, drv_priv->regs + (RISC1_OnCD + RISC1_ONCD_PCR - RISC1_BASE));
	value = ioread32(drv_priv->regs + (RISC1_OnCD + RISC1_ONCD_PC - RISC1_BASE));
	dev_warn(drv_priv->dev, "PC4    : %08x\n", value);

	/* Check reset memory */
	count = 100;
	iowrite32(0x03b00000, drv_priv->regs + (RISC1_OnCD + RISC1_ONCD_OMAR - RISC1_BASE));
	iowrite32(0xd, drv_priv->regs + (RISC1_OnCD + RISC1_ONCD_MEM - RISC1_BASE));
	do {
		value = ioread32(drv_priv->regs + (RISC1_OnCD + RISC1_ONCD_OSCR - RISC1_BASE));
	} while(!(value & (1 << 5)) && count-- > 0);
	dev_warn(drv_priv->dev, "OSCR: %08x\n", value);

	value = ioread32(drv_priv->regs + (RISC1_OnCD + RISC1_ONCD_OMDR - RISC1_BASE));
	dev_warn(drv_priv->dev, "m %08x: %08x\n", 0x03b00000, value);

	count = 100;
	iowrite32(0x03b00004, drv_priv->regs + (RISC1_OnCD + RISC1_ONCD_OMAR - RISC1_BASE));
	iowrite32(0xd, drv_priv->regs + (RISC1_OnCD + RISC1_ONCD_MEM - RISC1_BASE));
	do {
		value = ioread32(drv_priv->regs + (RISC1_OnCD + RISC1_ONCD_OSCR - RISC1_BASE));
	} while(!(value & (1 << 5)) && count-- > 0);
	dev_warn(drv_priv->dev, "OSCR: %08x\n", value);

	value = ioread32(drv_priv->regs + (RISC1_OnCD + RISC1_ONCD_OMDR - RISC1_BASE));
	dev_warn(drv_priv->dev, "m %08x: %08x\n", 0x03b00004, value);

	count = 100;
	iowrite32(0x10000000, drv_priv->regs + (RISC1_OnCD + RISC1_ONCD_OMAR - RISC1_BASE));
	iowrite32(0xd, drv_priv->regs + (RISC1_OnCD + RISC1_ONCD_MEM - RISC1_BASE));
	do {
		value = ioread32(drv_priv->regs + (RISC1_OnCD + RISC1_ONCD_OSCR - RISC1_BASE));
	} while(!(value & (1 << 5)) && count-- > 0);
	dev_warn(drv_priv->dev, "OSCR: %08x\n", value);

	value = ioread32(drv_priv->regs + (RISC1_OnCD + RISC1_ONCD_OMDR - RISC1_BASE));
	dev_warn(drv_priv->dev, "m %08x: %08x\n", 0x10000000, value);

	count = 100;
	iowrite32(0x10000004, drv_priv->regs + (RISC1_OnCD + RISC1_ONCD_OMAR - RISC1_BASE));
	iowrite32(0xd, drv_priv->regs + (RISC1_OnCD + RISC1_ONCD_MEM - RISC1_BASE));
	do {
		value = ioread32(drv_priv->regs + (RISC1_OnCD + RISC1_ONCD_OSCR - RISC1_BASE));
	} while(!(value & (1 << 5)) && count-- > 0);
	dev_warn(drv_priv->dev, "OSCR: %08x\n", value);

	value = ioread32(drv_priv->regs + (RISC1_OnCD + RISC1_ONCD_OMDR - RISC1_BASE));
	dev_warn(drv_priv->dev, "m %08x: %08x\n", 0x10000004, value);

	value = ioread32(drv_priv->regs + (RISC1_URB + SDR_RISC1_PSTATUS - RISC1_BASE));
	dev_warn(drv_priv->dev, "RISC1 PSTATUS: %08x\n", value);

	risc1_core_reset(drv_priv);

#if 0
    /* Final reset initialization */
	value = ioread32(drv_priv->regs + (RISC1_CSR + 0 - RISC1_BASE));
	iowrite32(value | (1 << 1) | (1 << 12)| (1 << 14), drv_priv->regs + (RISC1_CSR + 0 - RISC1_BASE));
	iowrite32(0x7, (drv_priv->regs + (RISC1_URB + SDR_ACC_RST_CTL - RISC1_BASE)));
	iowrite32(0x44 , drv_priv->regs + (RISC1_OnCD + RISC1_ONCD_IR - RISC1_BASE));
	iowrite32(0x50 , drv_priv->regs + (RISC1_OnCD + RISC1_ONCD_IR - RISC1_BASE));
#endif

	print_dump(drv_priv, RISC1_DUMP_MAIN);
	return 0;

err_irq:
	risc1_free_irqs(drv_priv);
err_device:
	risc1_cores_destroy(drv_priv);
err_clock:
	pm_runtime_disable(drv_priv->dev);
	risc1_clock_destroy(drv_priv);
	risc1_reset_fini(drv_priv);
	dev_err(drv_priv->dev, "risc1 init failed, error %d\n", ret);
	return ret;
}

static int risc1_remove(struct platform_device *pdev)
{
	struct risc1_priv *drv_priv = platform_get_drvdata(pdev);

	risc1_cores_destroy(drv_priv);
	risc1_reset_fini(drv_priv);
	pm_runtime_disable(drv_priv->dev);
	risc1_clock_destroy(drv_priv);
	return 0;
}

static const struct dev_pm_ops risc1_pm_ops = {
	SET_RUNTIME_PM_OPS(risc1_runtime_suspend,
			   risc1_runtime_resume,
			   NULL)
};

#ifdef CONFIG_OF
static const struct of_device_id elrisc1_dt_ids[] = {
	{ .compatible = "elvees,risc1" },
	{}
};
MODULE_DEVICE_TABLE(of, elrisc1_dt_ids);
#endif

static struct platform_driver risc1_driver = {
	.driver = {
		.name = "risc1",
		.pm = &risc1_pm_ops,
		.of_match_table = of_match_ptr(elrisc1_dt_ids),
	},
	.probe = risc1_probe,
	.remove = risc1_remove,
};

static int __init risc1_init(void)
{
	struct dentry *irq_timeout_dentry, *reg_dump_dentry, *event_handler_debug_dentry,
		*core_debug_dentry, *risc1_write_regs_debug_dentry,
		*risc1_map_from_users_debug_dentry, *risc1_syscall_debug_dentry,
		*exception_debug_dentry, *event_vcpu_handler_debug_dentry,
		*irq_debug_dentry, *job_debug_dentry;

	elrisc1_class = class_create(THIS_MODULE, "risc1");

	pdentry = debugfs_create_dir("risc1", NULL);
	if (!pdentry)
		return -ENOMEM;

	idr_init(&risc1_idr);
	spin_lock_init(&risc1_idr_lock);

	irq_timeout_dentry = debugfs_create_u32("irq-timeout-msec", 0600,
						pdentry, &irq_timeout_msec);
	if (!irq_timeout_dentry) {
		debugfs_remove_recursive(pdentry);
		return -ENOMEM;
	}

	reg_dump_dentry = debugfs_create_u32("reg-dump-enable", 0600, pdentry,
					     &reg_dump_enable);

	event_handler_debug_dentry = debugfs_create_u32("event_handler_debug",
						 0600, pdentry, &event_handler_debug);

	core_debug_dentry = debugfs_create_u32("core_debug",
						 0600, pdentry, &core_debug);

	risc1_write_regs_debug_dentry = debugfs_create_u32("risc1_write_regs_debug",
						 0600, pdentry, &risc1_write_regs_debug);

	risc1_map_from_users_debug_dentry = debugfs_create_u32("risc1_map_from_users_debug",
						 0600, pdentry, &risc1_map_from_users_debug);

	risc1_syscall_debug_dentry = debugfs_create_u32("risc1_syscall_debug",
						 0600, pdentry, &risc1_syscall_debug);

	exception_debug_dentry = debugfs_create_u32("exception_debug",
						 0600, pdentry, &exception_debug);

	event_vcpu_handler_debug_dentry = debugfs_create_u32("event_vcpu_handler_debug",
						 0600, pdentry, &event_vcpu_handler_debug);

	irq_debug_dentry = debugfs_create_u32("irq_debug",
						 0600, pdentry, &irq_debug);

	job_debug_dentry = debugfs_create_u32("job_debug",
						 0600, pdentry, &job_debug);

	return platform_driver_register(&risc1_driver);
}

static void __exit risc1_exit(void)
{
	platform_driver_unregister(&risc1_driver);
	debugfs_remove_recursive(pdentry);
	idr_destroy(&risc1_idr);
	class_destroy(elrisc1_class);
}

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("ELVEES RISC1 driver");

module_init(risc1_init);
module_exit(risc1_exit);
