// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright 2020 RnD Center "ELVEES", JSC
 */

#include <linux/err.h>
#include <linux/errno.h>
#include <linux/reset.h>

#include "risc1-reset.h"

void risc1_reset_fini(struct risc1_priv *drv_priv)
{
#if 0
	if (drv_priv->resets)
		reset_control_assert(drv_priv->resets);
#endif
}

int risc1_reset_init(struct risc1_priv *drv_priv)
{
#if 0
	int ret;

	drv_priv->resets = devm_reset_control_array_get(drv_priv->dev, 1, 0);
	if (IS_ERR(drv_priv->resets)) {
		dev_warn(drv_priv->dev, "Failed to initialize resets\n");
		drv_priv->resets = NULL;
	}

	if (drv_priv->resets) {
		ret = reset_control_deassert(drv_priv->resets);
		if (ret)
			return ret;
	}

#endif
	return 0;
}
