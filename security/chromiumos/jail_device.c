/*
 * Jailed character device
 *
 * Copyright (C) 2016 Google, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/cdev.h>
#include <linux/cred.h>
#include <linux/device.h>
#include <linux/err.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/uaccess.h>
#include <linux/usb.h>
#include <uapi/linux/device_jail.h>
#include <uapi/linux/usbdevice_fs.h>

#include "jail_request.h"

#define JAIL_DEV_NAME "jailed-%d-%d"
#define JAIL_MAX_DEV 256
#define JAIL_NAME "device_jail"

static dev_t jail_devnum;

struct jail_device {
	char *inner_name;
	struct path inner_path;
	int idx;
	struct device dev;
	struct cdev cdev;
};

struct jail_file_data {
	struct file *inner_file;
	int num_ifs_detached;
	int ifnums_to_reattach[USB_MAXINTERFACES];
};

/* Indexed by minor number. */
static struct jail_device *jails[JAIL_MAX_DEV] = { };
static struct mutex jails_mutex;

/* Used in class_find_device or bus_find_device. */
static int match_device_by_devt(struct device *dev, const void *data)
{
	const dev_t *devt = data;

	return dev->devt == *devt;
}

/*
 * This looks like casting away const but since it's a function argument
 * this is actually an upcast that the compiler isn't smart enough to
 * recognize...
 */
#define bus_match_device_by_devt \
	((int (*)(struct device *, void *)) match_device_by_devt)

/*
 * Sandboxing functions. For now these only have an effect on USB devices,
 * and fail harmlessly for other classes of devices.
 */
static int jail_detach(struct jail_device *jail, struct jail_file_data *jfile)
{
	struct device *dev;
	struct usb_device *usbdev;
	struct usb_host_config *config;
	int i;
	int num_intfs;
	dev_t devt = jail->inner_path.dentry->d_inode->i_rdev;

	dev = bus_find_device(&usb_bus_type, NULL, &devt,
		bus_match_device_by_devt);
	if (!dev)
		return -EINVAL;

	usbdev = to_usb_device(dev);
	usb_lock_device(usbdev);

	/* Look for all interfaces in the active configuration. */
	config = usbdev->actconfig;
	if (!config)
		goto no_config;

	num_intfs = min_t(int, config->desc.bNumInterfaces, USB_MAXINTERFACES);
	for (i = 0; i < num_intfs; i++) {
		struct usb_driver *driver;
		struct usb_interface *intf = config->interface[i];

		if (!intf)
			continue;

		/* Check if this interface is already detached. */
		if (!intf->dev.driver)
			continue;
		driver = to_usb_driver(intf->dev.driver);

		dev_info(&jail->dev, "detaching driver %s\n", driver->name);
		usb_driver_release_interface(driver, intf);

		jfile->ifnums_to_reattach[jfile->num_ifs_detached++] =
			intf->altsetting[0].desc.bInterfaceNumber;
	}

no_config:
	usb_unlock_device(usbdev);
	put_device(dev);
	return 0;
}

static int jail_attach(struct jail_device *jail, struct jail_file_data *jfile)
{
	struct device *dev;
	struct usb_device *usbdev;
	dev_t devt = jail->inner_path.dentry->d_inode->i_rdev;
	int i;
	int ret;

	dev = bus_find_device(&usb_bus_type, NULL, &devt,
		bus_match_device_by_devt);
	if (!dev)
		return 0;

	usbdev = to_usb_device(dev);
	usb_lock_device(usbdev);

	for (i = 0; i < jfile->num_ifs_detached; i++) {
		int ifnum = jfile->ifnums_to_reattach[i];
		struct usb_interface *intf = usb_ifnum_to_if(usbdev, ifnum);

		if (!intf) {
			dev_warn(&jail->dev, "failed to find interface %d\n",
				 ifnum);
			continue;
		}

		ret = device_attach(&intf->dev);
		if (ret < 0) {
			dev_err(&jail->dev,
				"failed to reattach driver for interface %d\n",
				ifnum);
			break;
		}

		dev_info(&jail->dev, "reattached driver for interface %d\n",
			 ifnum);
	}

	usb_unlock_device(usbdev);
	put_device(dev);
	return ret;
}

/**
 * jail_open - open a jailed device
 *
 * This attempts to open the underlying device, and then
 * asks permission_broker if this is an allowable action,
 * and if so what it should do with the resulting file.
 */
static int jail_open(struct inode *inode, struct file *file)
{
	struct cdev *cdev = inode->i_cdev;
	struct jail_device *jail = container_of(cdev, struct jail_device, cdev);
	struct jail_file_data *jfile;
	const struct cred *old_cred;
	struct cred *new_cred;
	int ret;

	ret = -ENOMEM;
	jfile = kzalloc(sizeof(*jfile), GFP_KERNEL);
	if (!jfile)
		goto err_alloc_file;

	/*
	 * Escalate privileges to open the file. Permission broker will tell us
	 * what kind of sandboxing to do or whether we should just close the
	 * file.
	 */
	new_cred = prepare_creds();
	if (!new_cred)
		goto err_alloc_cred;

	new_cred->fsuid = GLOBAL_ROOT_UID;
	new_cred->fsgid = GLOBAL_ROOT_GID;
	old_cred = override_creds(new_cred);
	jfile->inner_file = dentry_open(&jail->inner_path, file->f_flags,
					current_cred());
	revert_creds(old_cred);

	if (IS_ERR(jfile->inner_file)) {
		ret = PTR_ERR(jfile->inner_file);
		goto err_open_inner;
	}
	jfile->num_ifs_detached = 0;

	ret = -EACCES;
	switch (request_access(jail->inner_name)) {
	case JAIL_REQUEST_ALLOW:
		break;
	case JAIL_REQUEST_ALLOW_WITH_LOCKDOWN:
		usb_file_drop_privileges(jfile->inner_file);
		break;
	case JAIL_REQUEST_ALLOW_WITH_DETACH:
		ret = jail_detach(jail, jfile);
		if (ret < 0)
			goto err_request_access;
		break;
	case JAIL_REQUEST_DENY:
		goto err_request_access;
	default:
		dev_err(&jail->dev, "unknown access level\n");
		goto err_request_access;
	}

	file->private_data = jfile;
	return 0;

err_request_access:
	fput(jfile->inner_file);
err_open_inner:
err_alloc_cred:
	kfree(jfile);
err_alloc_file:
	return ret;
}

static int jail_release(struct inode *inode, struct file *file)
{
	struct cdev *cdev = inode->i_cdev;
	struct jail_device *jail = container_of(cdev, struct jail_device, cdev);
	struct jail_file_data *jfile = file->private_data;

	if (jfile->num_ifs_detached)
		jail_attach(jail, jfile);

	fput(jfile->inner_file);
	kfree(jfile);
	return 0;
}

static ssize_t jail_read(struct file *file, char __user *buf, size_t count,
			 loff_t *ppos)
{
	struct jail_file_data *jfile = file->private_data;
	struct file *inner = jfile->inner_file;

	return vfs_read(inner, buf, count, ppos);
}

static ssize_t jail_write(struct file *file, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	struct jail_file_data *jfile = file->private_data;
	struct file *inner = jfile->inner_file;

	return vfs_write(inner, buf, count, ppos);
}

static long ioctl_wrapper(long (*ioctl_fn)(struct file *, unsigned int,
					   unsigned long),
			  struct file *file, unsigned int cmd,
			  unsigned long arg)
{
	int ret;

	if (!ioctl_fn)
		return -ENOTTY;

	/* ioctl filters can happen here */

	ret = ioctl_fn(file, cmd, arg);
	if (ret == -ENOIOCTLCMD)
		return -ENOTTY;
	return ret;
}

static long jail_ioctl(struct file *file, unsigned int cmd,
		       unsigned long arg)
{
	struct jail_file_data *jfile = file->private_data;
	struct file *inner = jfile->inner_file;

	return ioctl_wrapper(inner->f_op->unlocked_ioctl,
			     inner, cmd, arg);
}

static long jail_compat_ioctl(struct file *file, unsigned int cmd,
			      unsigned long arg)
{
	struct jail_file_data *jfile = file->private_data;
	struct file *inner = jfile->inner_file;

	return ioctl_wrapper(inner->f_op->compat_ioctl,
			     inner, cmd, arg);
}

static unsigned int jail_poll(struct file *file,
			      struct poll_table_struct *wait)
{
	struct jail_file_data *jfile = file->private_data;
	struct file *inner = jfile->inner_file;

	if (inner->f_op->poll)
		return inner->f_op->poll(inner, wait);
	return -EINVAL;
}

static loff_t jail_llseek(struct file *file, loff_t off, int whence)
{
	struct jail_file_data *jfile = file->private_data;
	struct file *inner = jfile->inner_file;

	return vfs_llseek(inner, off, whence);
}

static const struct file_operations jail_fops = {
	.owner		= THIS_MODULE,
	.open		= jail_open,
	.release	= jail_release,
	.read		= jail_read,
	.write		= jail_write,
	.unlocked_ioctl	= jail_ioctl,
	.compat_ioctl	= jail_compat_ioctl,
	.poll		= jail_poll,
	.llseek		= jail_llseek,
};

static struct class jail_class = {
	.owner		= THIS_MODULE,
	.name		= JAIL_NAME,
};

static int match_device_by_inner_devt(struct device *dev, const void *data)
{
	const dev_t *devt = data;
	struct jail_device *jail = container_of(dev, struct jail_device, dev);

	return jail->inner_path.dentry->d_inode->i_rdev == *devt;
}

int add_jail_device(const char __user *path, dev_t *new_devt)
{
	struct jail_device *jail;
	struct device *existing;
	struct device *usbdev;
	struct inode *inode;
	int idx;
	int ret;
	dev_t devt;

	jail = kzalloc(sizeof(*jail), GFP_KERNEL);
	if (!jail)
		return -ENOMEM;

	ret = user_path(path, &jail->inner_path);
	if (ret < 0) {
		pr_err("%s: could not resolve path\n", __func__);
		goto err_path;
	}
	inode = jail->inner_path.dentry->d_inode;

	ret = -EINVAL;
	if (!S_ISCHR(inode->i_mode)) {
		pr_err("%s: not a character device\n", __func__);
		goto err_not_cdev;
	}

	usbdev = bus_find_device(&usb_bus_type, NULL, &inode->i_rdev,
		bus_match_device_by_devt);
	if (!usbdev) {
		pr_err("%s: currently supports only USB devices\n", __func__);
		goto err_not_usbdev;
	}
	put_device(usbdev);

	mutex_lock(&jails_mutex);

	/*
	 * If the device already exists, set *new_devt anyway.
	 * Do this here to avoid spamming the logs when we try to
	 * register another kobject later.
	 */
	ret = -EEXIST;
	existing = class_find_device(
		&jail_class, NULL, &inode->i_rdev, match_device_by_inner_devt);
	if (existing) {
		*new_devt = existing->devt;
		put_device(existing);
		goto err_exists;
	}

	/* Find an open spot in the jails array. */
	ret = -ENOMEM;
	for (idx = 0; idx < JAIL_MAX_DEV; idx++) {
		if (!jails[idx])
			break;
	}
	if (idx == JAIL_MAX_DEV)
		goto err_full;

	devt = jail_devnum + idx;
	pr_info("%s: assigned new index %d (devt %d:%d)\n",
		__func__, idx, MAJOR(devt), MINOR(devt));


	ret = -ENOMEM;
	jail->inner_name = kzalloc(PATH_MAX, GFP_KERNEL);
	if (!jail->inner_name)
		goto err_alloc_path;
	ret = strncpy_from_user(jail->inner_name, path, PATH_MAX - 1);
	if (ret < 0)
		goto err_copy_path;

	pr_info("%s: initializing device " JAIL_DEV_NAME "\n",
		__func__, MAJOR(inode->i_rdev), MINOR(inode->i_rdev));

	/* register cdev */
	cdev_init(&jail->cdev, &jail_fops);
	ret = cdev_add(&jail->cdev, devt, 1);
	if (ret)
		goto err_register_cdev;

	/* register device */
	jail->dev.class = &jail_class;
	jail->dev.devt = devt;
	dev_set_name(&jail->dev, JAIL_DEV_NAME,
		MAJOR(inode->i_rdev), MINOR(inode->i_rdev));
	ret = device_register(&jail->dev);
	if (ret)
		goto err_register_dev;

	*new_devt = devt;

	/* add jail to array */
	jails[idx] = jail;
	jail->idx = idx;
	mutex_unlock(&jails_mutex);
	return 0;

err_register_dev:
	cdev_del(&jail->cdev);
err_register_cdev:
err_copy_path:
	kfree(jail->inner_name);
err_alloc_path:
err_full:
err_exists:
	mutex_unlock(&jails_mutex);
err_not_usbdev:
err_not_cdev:
	path_put(&jail->inner_path);
err_path:
	kfree(jail);
	return ret;
}

static void destroy_jail_locked(struct jail_device *jail)
{
	jails[jail->idx] = NULL;
	device_unregister(&jail->dev);
	cdev_del(&jail->cdev);

	kfree(jail->inner_name);
	path_put(&jail->inner_path);
	kfree(jail);
}

int remove_jail_device(dev_t devt)
{
	struct device *dev = class_find_device(&jail_class, NULL, &devt,
					       match_device_by_devt);

	if (!dev)
		return -ENOENT;

	mutex_lock(&jails_mutex);
	destroy_jail_locked(container_of(dev, struct jail_device, dev));
	mutex_unlock(&jails_mutex);
	return 0;
}

int jail_device_setup(void)
{
	int ret;

	ret = class_register(&jail_class);
	if (ret) {
		pr_err(JAIL_NAME ": failed to register device class\n");
		return ret;
	}

	ret = alloc_chrdev_region(&jail_devnum, 0, JAIL_MAX_DEV, JAIL_NAME);
	if (ret < 0) {
		pr_err(JAIL_NAME ": failed to allocate chrdev region\n");
		goto err_region;
	}

	pr_info(JAIL_NAME ": allocated device range %d -> %d\n",
		jail_devnum, jail_devnum + JAIL_MAX_DEV);

	mutex_init(&jails_mutex);
	return 0;

err_region:
	class_unregister(&jail_class);
	return ret;
}

void jail_device_teardown(void)
{
	int i;

	mutex_lock(&jails_mutex);
	for (i = 0; i < JAIL_MAX_DEV; i++) {
		if (jails[i])
			destroy_jail_locked(jails[i]);
	}
	mutex_unlock(&jails_mutex);

	unregister_chrdev_region(jail_devnum, JAIL_MAX_DEV);

	class_unregister(&jail_class);
}
