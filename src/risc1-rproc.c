#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/of_address.h>
#include <linux/of_device.h>
#include <linux/of_reserved_mem.h>
#include <linux/dma-mapping.h>
#include <linux/regmap.h>
#include <linux/remoteproc.h>
#include <linux/reset.h>
#include <linux/workqueue.h>

#include "../drivers/remoteproc/remoteproc_internal.h"

#include "regs.h"

#define RSC_TBL_SIZE    (1024)
#define MAX_RPROC_MEM   3

/* memory region */
typedef struct risc1_rproc_mem {
    void __iomem *cpu_addr;
    u32 dev_addr;
    size_t size;
} risc1_rproc_mem;

struct risc1_rproc {
    struct workqueue_struct *workqueue;
    struct risc1_rproc_mem mem[MAX_RPROC_MEM];
    bool secured_soc;
    bool early_boot;
    void __iomem *rsc_va;
};

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
	}

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

static int risc1_rproc_elf_load_segments(struct rproc *rproc,
                                         const struct firmware *fw)
{
    struct risc1_rproc *ddata = rproc->priv;

    if (!ddata->early_boot)
        return rproc_elf_load_segments(rproc, fw);

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

static int risc1_rproc_start(struct rproc *rproc)
{
    printk(KERN_INFO "risc1_rproc_start\n");
    return 0;
}

static int risc1_rproc_stop(struct rproc *rproc)
{
    printk(KERN_INFO "risc1_rproc_stop\n");
    return 0;
}

static void risc1_rproc_kick(struct rproc *rproc, int vqid)
{
    printk(KERN_INFO "risc1_rproc_kick\n");
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
		printk(KERN_INFO "risc1_rproc_da_to_va %d 0x%x %d\n",
			i, ddata->mem[i].dev_addr, ddata->mem[i].size);

		if (ma >= ddata->mem[i].dev_addr
			&& ma + len < ddata->mem[i].dev_addr + ddata->mem[i].size) {
				unsigned int offset = ma - ddata->mem[i].dev_addr;
				va = (__force void *)(ddata->mem[i].cpu_addr + offset);
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
    ddata->workqueue = create_workqueue(dev_name(dev));
    if (!ddata->workqueue) {
        dev_err(dev, "cannot create workqueue\n");
        ret = -ENOMEM;
        goto free_rproc;
    }

    platform_set_drvdata(pdev, rproc);

    ret = risc1_rproc_parse_dt(pdev);
    if (ret)
        goto free_wkq;

    if (!ddata->early_boot) {
        ret = risc1_rproc_stop(rproc);
        if (ret)
            goto free_wkq;
    }

    if (ret)
        goto free_wkq;

    ret = rproc_add(rproc);
    if (ret)
        goto free_wkq;

    return 0;

free_wkq:
    destroy_workqueue(ddata->workqueue);
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
module_platform_driver(risc1_rproc_driver);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("ELVEES RISC1 driver");
