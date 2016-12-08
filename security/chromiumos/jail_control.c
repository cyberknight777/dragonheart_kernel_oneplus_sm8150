/*
 * Control device for requesting jails
 *
 * Copyright (C) 2016 Google, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/export.h>
#include <linux/fs.h>
#include <linux/kdev_t.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <uapi/linux/device_jail.h>

#include "jail_device.h"
#include "jail_request.h"

#define JAIL_CONTROL_NAME "jail-control"

static int add_device(struct jail_control_add_dev __user *arg)
{
	struct jail_control_add_dev karg;
	dev_t dev;
	u32 dev_encoded;
	int ret;

	if (copy_from_user(&karg, arg, sizeof(karg)))
		return -EFAULT;

	ret = add_jail_device(karg.path, &dev);
	if (ret < 0 && ret != -EEXIST)
		return ret;

	dev_encoded = new_encode_dev(dev);
	if (copy_to_user(&arg->devnum, &dev_encoded, sizeof(arg->devnum)))
		return -EFAULT;

	return ret;
}

static int remove_device(u32 __user *arg)
{
	u32 dev_encoded;

	if (copy_from_user(&dev_encoded, arg, sizeof(dev_encoded)))
		return -EFAULT;

	return remove_jail_device(new_decode_dev(dev_encoded));
}

static long jail_control_ioctl(struct file *file, unsigned int cmd,
			       unsigned long arg)
{
	switch (cmd) {
	case JAIL_CONTROL_ADD_DEVICE:
		return add_device((struct jail_control_add_dev __user *) arg);
	case JAIL_CONTROL_REMOVE_DEVICE:
		return remove_device((u32 __user *) arg);
	default:
		return -ENOTTY;
	}
}

static const struct file_operations jail_control_fops = {
	.owner			= THIS_MODULE,
	.open			= simple_open,
	.unlocked_ioctl		= jail_control_ioctl,
	.llseek			= noop_llseek,
};

static struct miscdevice jail_control_dev = {
	.minor			= MISC_DYNAMIC_MINOR,
	.name			= JAIL_CONTROL_NAME,
	.fops			= &jail_control_fops,
};

static int __init jailed_cdev_init(void)
{
	int ret;

	ret = jail_device_setup();
	if (ret < 0) {
		pr_err(JAIL_CONTROL_NAME ": failed to set up jails\n");
		return ret;
	}

	ret = jail_request_setup();
	if (ret < 0) {
		pr_err(JAIL_CONTROL_NAME ": failed to set up request device\n");
		goto err_setup_request;
	}

	ret = misc_register(&jail_control_dev);
	if (ret < 0) {
		pr_err(JAIL_CONTROL_NAME ": failed to create control device\n");
		goto err_register;
	}

	return 0;

err_register:
	jail_request_teardown();
err_setup_request:
	jail_device_teardown();
	return ret;
}

static void __exit jailed_cdev_exit(void)
{
	misc_deregister(&jail_control_dev);
	jail_request_teardown();
	jail_device_teardown();
}

module_init(jailed_cdev_init);
module_exit(jailed_cdev_exit);

MODULE_AUTHOR("Eric Caruso <ejcaruso@chromium.org>");
MODULE_DESCRIPTION("Character device jailed using Permission Broker");
MODULE_VERSION("1.0");
MODULE_LICENSE("GPL");
