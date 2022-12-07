#include <linux/debugfs.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/of_address.h>
#include <linux/of_device.h>
#include <linux/of_reserved_mem.h>
#include <linux/of_clk.h>
#include <linux/clk.h>
#include <linux/dma-mapping.h>
#include <linux/regmap.h>
#include <linux/remoteproc.h>
#include <linux/reset.h>
#include <linux/workqueue.h>

#include "../drivers/remoteproc/remoteproc_internal.h"

#include "regs.h"
#include "risc1.h"

#define RSC_TBL_SIZE    (1024)
#define MAX_RPROC_MEM   3

/* memory region */
typedef struct risc1_rproc_mem {
    void __iomem *cpu_addr;
    u32 dev_addr;
    size_t size;
} risc1_rproc_mem;

struct risc1_rproc {
    struct risc1_rproc_mem mem[MAX_RPROC_MEM];
    struct work_struct workqueue;
	struct device *dev;
    struct rproc *rproc;
    void __iomem *rsc_va;
    void __iomem *mbox;
	struct clk **clocks;
    int clock_count;
    u32 event;
    int irq;
    bool secured_soc;
    bool early_boot;
    int started;
};

static struct class *elrisc1_class;

static struct dentry *pdentry;

static struct idr risc1_idr;
static spinlock_t risc1_idr_lock;

static u32 stop_timeout_msec;
static u32 reset_debug;

static void risc1_reset(struct risc1_rproc *ddata);

static inline u32 risc1_get_paddr(u32 addr)
{
	if (addr >= 0xc0000000)
		return addr;
	if (addr >= 0xa0000000)
		return addr - 0xa0000000;
	return addr & 0x7fffffff;
}

static int risc1_rproc_parse_dt(struct platform_device *pdev)
{
    struct device *dev = &pdev->dev;
    struct device_node *np = dev->of_node;
	struct device_node *node;
    struct rproc *rproc = platform_get_drvdata(pdev);
    struct risc1_rproc *ddata = rproc->priv;
    struct resource *res, r;
	int ret, i;

    printk(KERN_INFO "risc1_rproc_parse_dt\n");

    if (of_property_read_bool(np, "early-booted")) {
        ddata->early_boot = true;
    }

    /* irq */
    ddata->irq = platform_get_irq(pdev, 0);
	if (ddata->irq < 0) {
		dev_err(&pdev->dev, "Failed to get interrupt\n");
		return ddata->irq;
	}

    ddata->event = 9;
    of_property_read_u32(np, "event", &ddata->event);

    /* reg */
	for (i = 0; i < 2; i++) {
		res = platform_get_resource(pdev, IORESOURCE_MEM, i);
		if (!res) {
			dev_err(&pdev->dev, "Failed to get registers %d\n", i);
			return -ENOENT;
		}

		ret = dma_set_mask(&pdev->dev, DMA_BIT_MASK(64));
		if (ret) {
			dev_err(&pdev->dev, "Failed to set DMAMASK %d\n", i);
			return ret;
		}

		ddata->mem[i].cpu_addr = devm_ioremap_resource(&pdev->dev, res);
		if (IS_ERR(ddata->mem[i].cpu_addr)) {
			dev_err(&pdev->dev, "Failed to map registers: %ld\n",
					PTR_ERR(ddata->mem[i].cpu_addr));
			return PTR_ERR(ddata->mem[i].cpu_addr);
		}

		ddata->mem[i].dev_addr = res->start;
		ddata->mem[i].size = resource_size(res);
        dev_info(dev, "ioremap 0x%x %ld 0x%016lx\n",
            ddata->mem[i].dev_addr, ddata->mem[i].size, ddata->mem[i].cpu_addr);
	}

    /* mbox reg */
    res = platform_get_resource(pdev, IORESOURCE_MEM, 2);
	if (!res) {
		dev_err(&pdev->dev, "Failed to get registers 2\n");
		return -ENOENT;
	}

    ddata->mbox = devm_ioremap_resource(&pdev->dev, res);
	if (IS_ERR(ddata->mbox)) {
		dev_err(&pdev->dev, "Failed to map registers: %ld\n",
		    PTR_ERR(ddata->mbox));
		return PTR_ERR(ddata->mbox);
	}
    dev_info(dev, "ioremap 0x%x %ld 0x%016lx\n",
        res->start, resource_size(res), ddata->mbox);

	/* memory-region */
    node = of_parse_phandle(np, "memory-region", 0);
    if (!node) {
        dev_err(dev, "no memory-region specified\n");
        return -EINVAL;
    }

	ret = of_address_to_resource(node, 0, &r);
    if (ret)
        return ret;

    ddata->mem[2].cpu_addr = devm_ioremap_resource(&pdev->dev, &r);
    if (IS_ERR(ddata->mem[2].cpu_addr)) {
		dev_err(&pdev->dev, "Failed to map memory region: %ld\n",
		PTR_ERR(ddata->mem[2].cpu_addr));
		return PTR_ERR(ddata->mem[2].cpu_addr);
    }

	ddata->mem[2].dev_addr = r.start;
    ddata->mem[2].size = resource_size(&r);
    dev_info(dev, "ioremap 0x%x %ld 0x%016lx\n",
            ddata->mem[2].dev_addr, ddata->mem[2].size, ddata->mem[2].cpu_addr);

    return 0;
}

static int risc1_rproc_elf_load_rsc_table(struct rproc *rproc,
                                          const struct firmware *fw)
{
    struct resource_table *table = NULL;
    struct risc1_rproc *ddata = rproc->priv;
    int status;

    printk(KERN_INFO "risc1_rproc_elf_load_rsc_table\n");

    if (!ddata->early_boot) {
        status = rproc_elf_load_rsc_table(rproc, fw);
        if (status)
            goto no_rsc_table;

        return 0;
	}

    if (ddata->rsc_va) {
        table = (struct resource_table *)ddata->rsc_va;
        /* Assuming that the resource table fits in 1kB is fair */
        rproc->cached_table = kmemdup(table, RSC_TBL_SIZE, GFP_KERNEL);
        if (!rproc->cached_table)
            return -ENOMEM;

        rproc->table_ptr = rproc->cached_table;
        rproc->table_sz = RSC_TBL_SIZE;
        return 0;
    }

    rproc->cached_table = NULL;
    rproc->table_ptr = NULL;
    rproc->table_sz = 0;

no_rsc_table:
    dev_warn(&rproc->dev, "no resource table found for this firmware\n");
    return 0;
}

static int risc1_rproc_parse_fw(struct rproc *rproc, const struct firmware *fw)
{
    printk(KERN_INFO "risc1_rproc_parse_fw\n");
    return risc1_rproc_elf_load_rsc_table(rproc, fw);
}

static int elf_load_segments(struct rproc *rproc, const struct firmware *fw)
{
    struct device *dev = &rproc->dev;
    struct elf32_hdr *ehdr;
    struct elf32_phdr *phdr;
    int i, ret = 0;
    const u8 *elf_data = fw->data;

    ehdr = (struct elf32_hdr *)elf_data;
    phdr = (struct elf32_phdr *)(elf_data + ehdr->e_phoff);

    /* go through the available ELF segments */
    for (i = 0; i < ehdr->e_phnum; i++, phdr++)
    {
        u32 da = phdr->p_paddr;
        u32 memsz = phdr->p_memsz;
        u32 filesz = phdr->p_filesz;
        u32 offset = phdr->p_offset;
        void *ptr;

        if (phdr->p_type != PT_LOAD)
            continue;

        dev_info(dev, "phdr: type %d da 0x%x memsz 0x%x filesz 0x%x\n",
                phdr->p_type, da, memsz, filesz);

        if (filesz > memsz)
        {
            dev_err(dev, "bad phdr filesz 0x%x memsz 0x%x\n",
                    filesz, memsz);
            ret = -EINVAL;
            break;
        }

        if (offset + filesz > fw->size)
        {
            dev_err(dev, "truncated fw: need 0x%x avail 0x%zx\n",
                    offset + filesz, fw->size);
            ret = -EINVAL;
            break;
        }

        /* grab the kernel address for this device address */
        ptr = rproc_da_to_va(rproc, da, memsz);
        if (!ptr)
        {
            dev_err(dev, "bad phdr da 0x%x mem 0x%x\n", da, memsz);
            ret = -EINVAL;
            break;
        }

        /* put the segment where the remote processor expects it */
        if (phdr->p_filesz)
        {
            // memcpy(ptr, elf_data + phdr->p_offset, filesz);
            u32 *pptr = (u32 *)ptr;
            u32 *src = (u32 *)(elf_data + phdr->p_offset);
            u32 size = filesz / 4;
            int i;
            for (i = 0; i < size; i++)
                *pptr++ = *src++;
        }
#if 0 /* risc1 will zero bss */
        /*
         * Zero out remaining memory for this segment.
         *
         * This isn't strictly required since dma_alloc_coherent already
         * did this for us. albeit harmless, we may consider removing
         * this.
         */
        if (memsz > filesz)
        {
            // memset(ptr + filesz, 0, memsz - filesz);
            u32 *pptr = (u32 *)(ptr + filesz);
            u32 size = (memsz - filesz) / 4;
            int i;
            dev_info(dev, "zero out %d 0x%016lx %d %d\n",
                     size, pptr, memsz, filesz);
            for (i = 0; i < size; i++)
                *pptr++ = 0;
        }
#endif
    }

    return ret;
}

static int risc1_rproc_elf_load_segments(struct rproc *rproc,
                                         const struct firmware *fw)
{
    struct risc1_rproc *ddata = rproc->priv;

    if (!ddata->early_boot)
        return elf_load_segments(rproc, fw);

    return 0;
}

static struct resource_table *
risc1_rproc_elf_find_loaded_rsc_table(struct rproc *rproc,
                                      const struct firmware *fw)
{
    struct risc1_rproc *ddata = rproc->priv;

    printk(KERN_INFO "risc1_rproc_elf_find_loaded_rsc_table\n");

    if (!ddata->early_boot)
        return rproc_elf_find_loaded_rsc_table(rproc, fw);

    return (struct resource_table *)ddata->rsc_va;
}

static int risc1_rproc_elf_sanity_check(struct rproc *rproc,
                                        const struct firmware *fw)
{
    struct risc1_rproc *ddata = rproc->priv;

    printk(KERN_INFO "risc1_rproc_elf_sanity_check\n");

    if (!ddata->early_boot)
        return rproc_elf_sanity_check(rproc, fw);

    return 0;
}

static u32 risc1_rproc_elf_get_boot_addr(struct rproc *rproc,
                                         const struct firmware *fw)
{
    struct risc1_rproc *ddata = rproc->priv;

    printk(KERN_INFO "risc1_rproc_elf_get_boot_addr\n");

    if (!ddata->early_boot)
        return rproc_elf_get_boot_addr(rproc, fw);

    return 0;
}

static inline u32 risc1_read_reg(struct risc1_rproc *ddata,
	unsigned int const group, unsigned int const reg)
{
    void __iomem *regs = ddata->mem[0].cpu_addr;
	u32 code = group;
	u32 result;

	/* Read reg by OnCD */
	if (group < 2) {
		code |= reg << 16;
	} else {
		code |= reg << 3;
	}

	iowrite32(code, regs + (RISC1_OnCD +  RISC1_ONCD_IRDEC - RISC1_BASE));
	iowrite32(0, regs + (RISC1_OnCD +  RISC1_ONCD_REGFR - RISC1_BASE));
	result = ioread32(regs + (RISC1_OnCD +  RISC1_ONCD_REGF - RISC1_BASE));

	return result;
}

static void risc1_dump(struct risc1_rproc *ddata, int flags)
{
    void __iomem *regs = ddata->mem[0].cpu_addr;
    uint32_t value;
	int i;

	if (flags & RISC1_DUMP_ONCD)
	{
		/* Dump RISC1 OnCD registers */
		value = ioread32(regs + (RISC1_OnCD + RISC1_ONCD_IR - RISC1_BASE));
		dev_warn(ddata->dev, "IR     : %08x\n", value);

		value = ioread32(regs + (RISC1_OnCD + RISC1_ONCD_IDCODE - RISC1_BASE));
		dev_warn(ddata->dev, "IDCODE : %08x\n", value);

		value = ioread32(regs + (RISC1_OnCD + RISC1_ONCD_OSCR - RISC1_BASE));
		dev_warn(ddata->dev, "OSCR   : %08x\n", value);

		value = ioread32(regs + (RISC1_OnCD + RISC1_ONCD_OBCR - RISC1_BASE));
		dev_warn(ddata->dev, "OBCR   : %08x\n", value);

		iowrite32(1, regs + (RISC1_OnCD + RISC1_ONCD_PCDEC - RISC1_BASE));
		value = ioread32(regs + (RISC1_OnCD + RISC1_ONCD_PCDEC - RISC1_BASE));
		dev_warn(ddata->dev, "PCDEC  : %08x\n", value);

		iowrite32(1, regs + (RISC1_OnCD + RISC1_ONCD_PCEXE - RISC1_BASE));
		value = ioread32(regs + (RISC1_OnCD + RISC1_ONCD_PCEXE - RISC1_BASE));
		dev_warn(ddata->dev, "PCEXE  : %08x\n", value);

		iowrite32(1, regs + (RISC1_OnCD + RISC1_ONCD_PCMEM - RISC1_BASE));
		value = ioread32(regs + (RISC1_OnCD + RISC1_ONCD_PCMEM - RISC1_BASE));
		dev_warn(ddata->dev, "PCMEM  : %08x\n", value);

		iowrite32(1, regs + (RISC1_OnCD + RISC1_ONCD_PCR - RISC1_BASE));
		value = ioread32(regs + (RISC1_OnCD + RISC1_ONCD_PC - RISC1_BASE));
		dev_warn(ddata->dev, "PC     : %08x\n", value);

		iowrite32(1, regs + (RISC1_OnCD + RISC1_ONCD_PCWB - RISC1_BASE));
		value = ioread32(regs + (RISC1_OnCD + RISC1_ONCD_PCWB - RISC1_BASE));
		dev_warn(ddata->dev, "PCWB   : %08x\n", value);

		value = ioread32(regs + (RISC1_CSR + 0 - RISC1_BASE));
		dev_warn(ddata->dev, "CSR    : %08x\n", value);

		value = ioread32(regs + (RISC1_CSR + 4 - RISC1_BASE));
		dev_warn(ddata->dev, "EVENT  : %08x\n", value);
	}

    if (flags & RISC1_DUMP_NMI) {
        value = ioread32(regs + (RISC1_URB + SDR_RISC1_SOFT_NMI_STATUS - RISC1_BASE));
        dev_warn(ddata->dev, "SDR_RISC1_SOFT_NMI_STATUS  : %08x\n", value);
        value = ioread32(regs + (RISC1_URB + SDR_RISC1_SOFT_NMI_MASK - RISC1_BASE));
        dev_warn(ddata->dev, "SDR_RISC1_SOFT_NMI_MASK    : %08x\n", value);
    }

    if (flags & RISC1_DUMP_CP0)
	{
		for (i = 0; i <= 31; i++)
		{
			value = risc1_read_reg(ddata, RISC1_ONCD_GCP0, i);
			dev_warn(ddata->dev, "CP0.%02d : %08x\n", i, value);
		}
	}
}

static void handle_event(struct work_struct *work)
{
        struct risc1_rproc *ddata =
                container_of(work, struct risc1_rproc, workqueue);

        rproc_vq_interrupt(ddata->rproc, 0);
        rproc_vq_interrupt(ddata->rproc, 1);
}

static irqreturn_t risc1_rproc_vring_interrupt(int irq, void *dev_id)
{
    struct risc1_rproc *ddata = dev_id;

    /* Use CLR_IRQ_u to clear interrupt */
    iowrite32(0xff, ddata->mbox + 0x1014); /* page 1942-1944 */
    schedule_work(&ddata->workqueue);

    return IRQ_HANDLED;
}

static int risc1_rproc_start(struct rproc *rproc)
{
    struct risc1_rproc *ddata = rproc->priv;
    void __iomem *regs = ddata->mem[0].cpu_addr;
    int ret;

    printk(KERN_INFO "risc1_rproc_start\n");

    INIT_WORK(&ddata->workqueue, handle_event);
    ret = request_irq(ddata->irq, risc1_rproc_vring_interrupt, 0,
                          dev_name(ddata->dev), rproc);
    if (ret) {
        dev_err(ddata->dev, "failed to enable vring interrupt, ret = %d\n",
                ret);
        goto out;
    }

    iowrite32(1, regs + (RISC1_URB + SDR_RISC1_SOFT_NMI_SET - RISC1_BASE));
    ddata->started = 1;
    //risc1_dump(ddata, RISC1_DUMP_ONCD | RISC1_DUMP_NMI);
    return 0;
out:
    return ret;
}

static int risc1_rproc_stop(struct rproc *rproc)
{
    struct risc1_rproc *ddata = rproc->priv;
    void __iomem *regs = ddata->mem[0].cpu_addr;

    printk(KERN_INFO "risc1_rproc_stop\n");

    if (ddata->started) {
        free_irq(ddata->irq, rproc);
        flush_work(&ddata->workqueue);
    }

    /* Real stop */
    iowrite32(0x04 , regs + (RISC1_OnCD + RISC1_ONCD_IR - RISC1_BASE));
    iowrite32(1, regs + (RISC1_URB + SDR_RISC1_SOFT_NMI_CLEAR - RISC1_BASE));
    //risc1_dump(ddata, RISC1_DUMP_ONCD | RISC1_DUMP_NMI | RISC1_DUMP_CP0);
    msleep(stop_timeout_msec);

    risc1_reset(ddata);

    ddata->started = 0;

    return 0;
}

static void risc1_rproc_kick(struct rproc *rproc, int vqid)
{
    struct risc1_rproc *ddata = rproc->priv;

    printk(KERN_INFO "risc1_rproc_kick\n");
    /* use SET_IRQ for risc1 from cpu 0 */
    iowrite32(1 << 4, ddata->mbox + 0x1014); /* page 1942-1943 */
}

static void *risc1_rproc_da_to_va(struct rproc *rproc, u64 da, int len)
{
	struct risc1_rproc *ddata = rproc->priv;
	u32 ma;
	void *va = NULL;
	unsigned int i;

	printk(KERN_INFO "risc1_rproc_da_to_va %d\n", len);

	if (len <= 0)
        return NULL;

	ma = risc1_get_paddr(da);
	printk(KERN_INFO "risc1_rproc_da_to_va 0x%x\n", ma);

	/* Check regions */
	for (i = 0; i < MAX_RPROC_MEM; i++) {
		printk(KERN_INFO "risc1_rproc_da_to_va %d 0x%x %ld 0x%016lx\n",
			i, ddata->mem[i].dev_addr, ddata->mem[i].size, ddata->mem[i].cpu_addr);

		if ((ma >= ddata->mem[i].dev_addr)
			&& (ma + len <= ddata->mem[i].dev_addr + ddata->mem[i].size)) {
				unsigned int offset = ma - ddata->mem[i].dev_addr;
				va = (__force void *)(ddata->mem[i].cpu_addr + offset);
                printk(KERN_INFO "risc1_rproc_da_to_va va 0x%016lx offset 0x%x\n", va, offset);
				break;
		}
	}

	return va;
}

static struct rproc_ops risc1_rproc_ops = {
    .start          = risc1_rproc_start,
    .stop           = risc1_rproc_stop,
	.da_to_va = risc1_rproc_da_to_va,
    .kick           = risc1_rproc_kick,
    .load = risc1_rproc_elf_load_segments,
    .parse_fw = risc1_rproc_parse_fw,
    .find_loaded_rsc_table = risc1_rproc_elf_find_loaded_rsc_table,
    .sanity_check = risc1_rproc_elf_sanity_check,
    .get_boot_addr = risc1_rproc_elf_get_boot_addr,
};

static const struct of_device_id risc1_rproc_match[] = {
    { .compatible = "elvees,risc1-rproc" },
    {},
};
MODULE_DEVICE_TABLE(of, risc1_rproc_match);

static int risc1_clock_init(struct risc1_rproc *drv_priv)
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

static void risc1_reset(struct risc1_rproc *ddata)
{
	uint32_t value;
    void __iomem *regs = ddata->mem[0].cpu_addr;

	value = ioread32(regs + (RISC1_URB + SDR_RISC1_PSTATUS - RISC1_BASE));

	/* Warm reset */
	if (value != RISC1_PPOLICY_PP_WARM_RST) {
		int count = 100;
		iowrite32(RISC1_PPOLICY_PP_WARM_RST, regs + (RISC1_URB + SDR_RISC1_PPOLICY - RISC1_BASE));
		do {
			value = ioread32(regs + (RISC1_URB + SDR_RISC1_PSTATUS - RISC1_BASE));
			if (reset_debug)
				dev_warn(ddata->dev, "RISC1 PSTATUS: %08x\n", value);
		} while(value != RISC1_PPOLICY_PP_WARM_RST && count-- > 0);
	}

	value = ioread32(regs + (RISC1_URB + SDR_RISC1_PSTATUS - RISC1_BASE));
	if (reset_debug)
		dev_warn(ddata->dev, "RISC1 PSTATUS: %08x\n", value);

	/* PPON */
	if (value != RISC1_PPOLICY_PP_ON) {
		int count = 100;
		iowrite32(RISC1_PPOLICY_PP_ON, regs + (RISC1_URB + SDR_RISC1_PPOLICY - RISC1_BASE));
		do {
			value = ioread32(regs + (RISC1_URB + SDR_RISC1_PSTATUS - RISC1_BASE));
			if (reset_debug)
				dev_warn(ddata->dev, "RISC1 PSTATUS: %08x\n", value);
		} while(value != RISC1_PPOLICY_PP_ON && count-- > 0);
	}

}

static int risc1_rproc_probe(struct platform_device *pdev)
{
    struct device *dev = &pdev->dev;
    struct risc1_rproc *ddata;
    struct device_node *np = dev->of_node;
    struct rproc *rproc;
    const char *fw_name = NULL;
    int ret;

    ret = of_property_read_string(dev->of_node, "firmware",
                                      &fw_name);

    printk(KERN_INFO "risc1_rproc_probe %s\n", fw_name);

    rproc = rproc_alloc(dev, np->name, &risc1_rproc_ops, fw_name, sizeof(*ddata));
    if (!rproc)
        return -ENOMEM;


    rproc->has_iommu = false; /* workaround */
    ddata = rproc->priv;
    ddata->rproc = rproc;

    platform_set_drvdata(pdev, rproc);

    ret = risc1_rproc_parse_dt(pdev);
    if (ret)
        goto free_rproc;

	ddata->dev = dev;
	ret = risc1_clock_init(ddata);

    if (!ddata->early_boot) {
        risc1_reset(ddata);
        ret = risc1_rproc_stop(rproc);
        if (ret)
            goto free_rproc;
    }

    if (ret)
        goto free_rproc;

    ret = rproc_add(rproc);
    if (ret)
        goto free_rproc;

    return 0;

free_rproc:
    if (device_may_wakeup(dev)) {
        device_init_wakeup(dev, false);
    }
    rproc_free(rproc);
    return ret;
}


static int risc1_rproc_remove(struct platform_device *pdev)
{
    struct rproc *rproc = platform_get_drvdata(pdev);
    struct risc1_rproc *ddata = rproc->priv;
    struct device *dev = &pdev->dev;

    if (atomic_read(&rproc->power) > 0)
        rproc_shutdown(rproc);

    rproc_del(rproc);

    if (device_may_wakeup(dev)) {
        device_init_wakeup(dev, false);
    }
    rproc_free(rproc);

    return 0;
}


static struct platform_driver risc1_rproc_driver = {
    .probe = risc1_rproc_probe,
    .remove = risc1_rproc_remove,
    .driver = {
        .name = "risc1-rproc",
        .of_match_table = of_match_ptr(risc1_rproc_match),
    },
};
//module_platform_driver(risc1_rproc_driver);

static int __init risc1_init(void)
{
    struct dentry *stop_timeout_dentry, *reset_debug_dentry;

    elrisc1_class = class_create(THIS_MODULE, "risc1-rproc");

    pdentry = debugfs_create_dir("risc1-rproc", NULL);
	if (!pdentry)
		return -ENOMEM;

    stop_timeout_dentry = debugfs_create_u32("stop-timeout-msec", 0600,
						pdentry, &stop_timeout_msec);

    reset_debug_dentry = debugfs_create_u32("reset_debug", 0600,
						pdentry, &reset_debug);

    return platform_driver_register(&risc1_rproc_driver);
}

static void __exit risc1_exit(void)
{
	platform_driver_unregister(&risc1_rproc_driver);
	debugfs_remove_recursive(pdentry);
	idr_destroy(&risc1_idr);
	class_destroy(elrisc1_class);
}

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("ELVEES RISC1 driver");

module_init(risc1_init);
module_exit(risc1_exit);
