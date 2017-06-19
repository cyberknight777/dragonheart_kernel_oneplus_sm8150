/*
 *  Copyright (C) 2011 The Chromium OS Authors
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#define pr_fmt(fmt) "chromeos_arm: " fmt

#include <linux/gpio.h>
#include <linux/of.h>
#include <linux/of_gpio.h>
#include <linux/platform_device.h>

#include "chromeos.h"

static int dt_gpio_init(struct platform_device *pdev, const char *of_list_name,
			const char *gpio_desc_name, const char *sysfs_name)
{
	int gpio, err;
	enum of_gpio_flags flags;
	struct device_node *np = pdev->dev.of_node;
	unsigned long gpio_flags = GPIOF_DIR_IN;

	gpio = of_get_named_gpio_flags(np, of_list_name, 0, &flags);
	if (!gpio_is_valid(gpio)) {
		dev_err(&pdev->dev, "invalid %s descriptor\n", of_list_name);
		return -EINVAL;
	}

	if (flags & OF_GPIO_ACTIVE_LOW)
		gpio_flags |= GPIOF_ACTIVE_LOW;

	err = gpio_request_one(gpio, gpio_flags, gpio_desc_name);
	if (err)
		return err;

	gpio_export(gpio, 0);
	gpio_export_link(&pdev->dev, sysfs_name, gpio);
	return 0;
}

static int chromeos_arm_probe(struct platform_device *pdev)
{
	int err;
	struct device_node *np = pdev->dev.of_node;

	if (!np) {
		err = -ENODEV;
		goto err;
	}

	err = dt_gpio_init(pdev, "write-protect-gpio",
			   "firmware-write-protect", "write-protect");
	if (err)
		goto err;
	err = dt_gpio_init(pdev, "recovery-switch",
			   "firmware-recovery-switch", "recovery-switch");
	err = dt_gpio_init(pdev, "developer-switch",
			   "firmware-developer-switch", "developer-switch");

	dev_info(&pdev->dev, "chromeos system detected\n");

	err = 0;
err:
	of_node_put(np);

	return err;
}

static struct platform_driver chromeos_arm_driver = {
	.probe = chromeos_arm_probe,
	.driver = {
		.name = "chromeos_arm",
	},
};

static int __init chromeos_arm_init(void)
{
	struct device_node *fw_dn;
	struct platform_device *pdev;

	fw_dn = of_find_compatible_node(NULL, NULL, "chromeos-firmware");
	if (!fw_dn)
		return -ENODEV;

	pdev = platform_device_register_simple("chromeos_arm", -1, NULL, 0);
	pdev->dev.of_node = fw_dn;

	platform_driver_register(&chromeos_arm_driver);

	return 0;
}
subsys_initcall(chromeos_arm_init);
