/*
 * cros_ec_dev - expose the Chrome OS Embedded Controller to user-space
 *
 * Copyright (C) 2014 Google, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/fs.h>
#include <linux/mfd/core.h>
#include <linux/module.h>
#include <linux/notifier.h>
#include <linux/platform_device.h>
#include <linux/pm.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include "cros_ec_dev.h"

#define DRV_NAME "cros-ec-dev"

/* Device variables */
#define CROS_MAX_DEV 128
static int ec_major;

static const struct attribute_group *cros_ec_groups[] = {
	&cros_ec_attr_group,
	&cros_ec_lightbar_attr_group,
	&cros_ec_vbc_attr_group,
#if IS_ENABLED(CONFIG_MFD_CROS_EC_PD_UPDATE)
	&cros_ec_pd_attr_group,
#endif
#if IS_ENABLED(CONFIG_CHARGER_CROS_USB_PD)
	&cros_usb_pd_charger_attr_group,
#endif
	NULL,
};

static struct class cros_class = {
	.owner          = THIS_MODULE,
	.name           = "chromeos",
	.dev_groups     = cros_ec_groups,
};

/* Basic communication */
static int ec_get_version(struct cros_ec_dev *ec, char *str, int maxlen)
{
	struct ec_response_get_version *resp;
	static const char * const current_image_name[] = {
		"unknown", "read-only", "read-write", "invalid",
	};
	struct cros_ec_command *msg;
	int ret;

	msg = kmalloc(sizeof(*msg) + sizeof(*resp), GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	msg->version = 0;
	msg->command = EC_CMD_GET_VERSION + ec->cmd_offset;
	msg->insize = sizeof(*resp);
	msg->outsize = 0;

	ret = cros_ec_cmd_xfer(ec->ec_dev, msg);
	if (ret < 0)
		goto exit;

	if (msg->result != EC_RES_SUCCESS) {
		snprintf(str, maxlen,
			 "%s\nUnknown EC version: EC returned %d\n",
			 CROS_EC_DEV_VERSION, msg->result);
		ret = -EINVAL;
		goto exit;
	}

	resp = (struct ec_response_get_version *)msg->data;
	if (resp->current_image >= ARRAY_SIZE(current_image_name))
		resp->current_image = 3; /* invalid */

	snprintf(str, maxlen, "%s\n%s\n%s\n%s\n", CROS_EC_DEV_VERSION,
		 resp->version_string_ro, resp->version_string_rw,
		 current_image_name[resp->current_image]);

	ret = 0;
exit:
	kfree(msg);
	return ret;
}

int cros_ec_check_features(struct cros_ec_dev *ec, int feature)
{
	struct cros_ec_command *msg;
	int ret;

	if (ec->features[0] == -1U && ec->features[1] == -1U) {
		/* features bitmap not read yet */

		msg = kmalloc(sizeof(*msg) + sizeof(ec->features), GFP_KERNEL);
		if (!msg)
			return -ENOMEM;

		msg->version = 0;
		msg->command = EC_CMD_GET_FEATURES + ec->cmd_offset;
		msg->insize = sizeof(ec->features);
		msg->outsize = 0;

		ret = cros_ec_cmd_xfer(ec->ec_dev, msg);
		if (ret < 0 || msg->result != EC_RES_SUCCESS) {
			dev_warn(ec->dev, "cannot get EC features: %d/%d\n",
				 ret, msg->result);
			memset(ec->features, 0, sizeof(ec->features));
		} else {
			memcpy(ec->features, msg->data, sizeof(ec->features));
		}

		dev_dbg(ec->dev, "EC features %08x %08x\n",
			ec->features[0], ec->features[1]);

		kfree(msg);
	}

	return !!(ec->features[feature / 32] & EC_FEATURE_MASK_0(feature));
}
EXPORT_SYMBOL_GPL(cros_ec_check_features);

struct cros_ec_priv {
	struct cros_ec_dev *ec;
	struct notifier_block notifier;
	struct list_head events;
	wait_queue_head_t wait_event;
	unsigned long event_mask;
	size_t event_len;
};

struct ec_priv_event {
	struct list_head node;
	size_t size;
	uint8_t event_type;
	u8 data[0];
};

/* Arbitrary bounded size for the event queue */
#define MAX_EVENT_LEN PAGE_SIZE

static int ec_device_mkbp_event(struct notifier_block *nb,
	unsigned long queued_during_suspend, void *_notify)
{
	struct cros_ec_priv *priv = container_of(nb, struct cros_ec_priv,
						 notifier);
	struct cros_ec_device *ec_dev = priv->ec->ec_dev;
	struct ec_priv_event *event;
	unsigned long event_bit = 1 << ec_dev->event_data.event_type;
	int total_size = sizeof(struct ec_priv_event) + ec_dev->event_size;

	if (!(event_bit & priv->event_mask) ||
	    (priv->event_len + total_size) > MAX_EVENT_LEN)
		return NOTIFY_DONE;

	event = kzalloc(total_size, GFP_KERNEL);
	if (!event)
		return NOTIFY_DONE;

	event->size = ec_dev->event_size;
	event->event_type = ec_dev->event_data.event_type;
	memcpy(event->data, &ec_dev->event_data.data, ec_dev->event_size);

	spin_lock(&priv->wait_event.lock);
	list_add_tail(&event->node, &priv->events);
	priv->event_len += total_size;
	wake_up_locked(&priv->wait_event);
	spin_unlock(&priv->wait_event.lock);

	return NOTIFY_OK;
}

/* Device file ops */
static int ec_device_open(struct inode *inode, struct file *filp)
{
	struct cros_ec_dev *ec = container_of(inode->i_cdev,
					      struct cros_ec_dev, cdev);
	int retval;
	struct cros_ec_priv *priv = kzalloc(sizeof(struct cros_ec_priv),
					    GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	priv->ec = ec;
	filp->private_data = priv;
	INIT_LIST_HEAD(&priv->events);
	init_waitqueue_head(&priv->wait_event);
	nonseekable_open(inode, filp);

	priv->notifier.notifier_call = ec_device_mkbp_event;
	retval = blocking_notifier_chain_register(&ec->ec_dev->event_notifier,
						  &priv->notifier);
	if (retval) {
		dev_err(ec->dev, "failed to register event notifier\n");
		kfree(priv);
	}

	return retval;
}

static unsigned int ec_device_poll(struct file *filp, poll_table *wait)
{
	struct cros_ec_priv *priv = filp->private_data;

	poll_wait(filp, &priv->wait_event, wait);

	if (list_empty(&priv->events))
		return 0;

	return POLLIN | POLLRDNORM;
}

static int ec_device_release(struct inode *inode, struct file *filp)
{
	struct cros_ec_priv *priv = filp->private_data;
	struct cros_ec_dev *ec = priv->ec;
	struct ec_priv_event *evt, *tmp;

	blocking_notifier_chain_unregister(&ec->ec_dev->event_notifier,
					   &priv->notifier);
	list_for_each_entry_safe(evt, tmp, &priv->events, node) {
		list_del(&evt->node);
		kfree(evt);
	}
	kfree(priv);

	return 0;
}

static struct ec_priv_event *ec_fetch_event(struct cros_ec_priv *priv,
					    bool fetch, bool block)
{
	struct ec_priv_event *event;
	int error;

	spin_lock(&priv->wait_event.lock);
	if (!block && list_empty(&priv->events)) {
		event = ERR_PTR(-EWOULDBLOCK);
		goto out;
	}
	if (!fetch) {
		event = NULL;
		goto out;
	}
	error = wait_event_interruptible_locked(priv->wait_event,
						!list_empty(&priv->events));
	if (error) {
		event = ERR_PTR(error);
		goto out;
	}
	event = list_first_entry(&priv->events, struct ec_priv_event, node);
	list_del(&event->node);
	priv->event_len -= event->size + sizeof(struct ec_priv_event);
out:
	spin_unlock(&priv->wait_event.lock);
	return event;
}


static ssize_t ec_device_read(struct file *filp, char __user *buffer,
			      size_t length, loff_t *offset)
{
	struct cros_ec_priv *priv = filp->private_data;
	struct cros_ec_dev *ec = priv->ec;
	char msg[sizeof(struct ec_response_get_version) +
		 sizeof(CROS_EC_DEV_VERSION)];
	size_t count;
	int ret;


	if (priv->event_mask) { /* queued MKBP event */
		struct ec_priv_event *event;

		event = ec_fetch_event(priv, length != 0,
				       !(filp->f_flags & O_NONBLOCK));
		if (IS_ERR(event))
			return PTR_ERR(event);
		/*
		 * length == 0 is special - no IO is done but we check
		 * for error conditions.
		 */
		if (length == 0)
			return 0;

		/* the event is 1 byte of type plus the payload */
		count = min(length, event->size + 1);
		ret = copy_to_user(buffer, &event->event_type, count);
		kfree(event);
		if (ret) /* the copy failed */
			return -EFAULT;
		*offset = count;
		return count;
	}
	/* legacy behavior if no event mask is defined */
	if (*offset != 0)
		return 0;

	ret = ec_get_version(ec, msg, sizeof(msg));
	if (ret)
		return ret;

	count = min(length, strlen(msg));

	if (copy_to_user(buffer, msg, count))
		return -EFAULT;

	*offset = count;
	return count;
}

/* Ioctls */
static long ec_device_ioctl_xcmd(struct cros_ec_dev *ec, void __user *arg)
{
	long ret;
	struct cros_ec_command u_cmd;
	struct cros_ec_command *s_cmd;

	if (copy_from_user(&u_cmd, arg, sizeof(u_cmd)))
		return -EFAULT;

	if ((u_cmd.outsize > EC_MAX_MSG_BYTES) ||
	    (u_cmd.insize > EC_MAX_MSG_BYTES))
		return -EINVAL;

	s_cmd = kmalloc(sizeof(*s_cmd) + max(u_cmd.outsize, u_cmd.insize),
			GFP_KERNEL);
	if (!s_cmd)
		return -ENOMEM;

	if (copy_from_user(s_cmd, arg, sizeof(*s_cmd) + u_cmd.outsize)) {
		ret = -EFAULT;
		goto exit;
	}

	if (u_cmd.outsize != s_cmd->outsize ||
	    u_cmd.insize != s_cmd->insize) {
		ret = -EINVAL;
		goto exit;
	}

	s_cmd->command += ec->cmd_offset;
	ret = cros_ec_cmd_xfer(ec->ec_dev, s_cmd);
	/* Only copy data to userland if data was received. */
	if (ret < 0)
		goto exit;

	if (copy_to_user(arg, s_cmd, sizeof(*s_cmd) + s_cmd->insize))
		ret = -EFAULT;
exit:
	kfree(s_cmd);
	return ret;
}

static long ec_device_ioctl_readmem(struct cros_ec_dev *ec, void __user *arg)
{
	struct cros_ec_device *ec_dev = ec->ec_dev;
	struct cros_ec_readmem s_mem = { };
	long num;

	/* Not every platform supports direct reads */
	if (!ec_dev->cmd_readmem)
		return -ENOTTY;

	if (copy_from_user(&s_mem, arg, sizeof(s_mem)))
		return -EFAULT;

	num = ec_dev->cmd_readmem(ec_dev, s_mem.offset, s_mem.bytes,
				  s_mem.buffer);
	if (num <= 0)
		return num;

	if (copy_to_user((void __user *)arg, &s_mem, sizeof(s_mem)))
		return -EFAULT;

	return num;
}

static long ec_device_ioctl(struct file *filp, unsigned int cmd,
			    unsigned long arg)
{
	struct cros_ec_priv *priv = filp->private_data;
	struct cros_ec_dev *ec = priv->ec;

	if (_IOC_TYPE(cmd) != CROS_EC_DEV_IOC)
		return -ENOTTY;

	switch (cmd) {
	case CROS_EC_DEV_IOCXCMD:
		return ec_device_ioctl_xcmd(ec, (void __user *)arg);
	case CROS_EC_DEV_IOCRDMEM:
		return ec_device_ioctl_readmem(ec, (void __user *)arg);
	case CROS_EC_DEV_IOCEVENTMASK:
		priv->event_mask = arg;
		return 0;
	}

	return -ENOTTY;
}

/* Module initialization */
static const struct file_operations fops = {
	.open = ec_device_open,
	.poll = ec_device_poll,
	.release = ec_device_release,
	.read = ec_device_read,
	.unlocked_ioctl = ec_device_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = ec_device_ioctl,
#endif
};

static void __remove(struct device *dev)
{
	struct cros_ec_dev *ec = container_of(dev, struct cros_ec_dev,
					      class_dev);
	kfree(ec);
}

static const struct mfd_cell cros_usb_pd_charger_devs[] = {
	{
		.name = "cros-usb-pd-charger",
		.id   = -1,
	},
};

static void cros_ec_usb_pd_charger_register(struct cros_ec_dev *ec)
{
	int ret;

	ret = mfd_add_devices(ec->dev, 0, cros_usb_pd_charger_devs,
			      ARRAY_SIZE(cros_usb_pd_charger_devs),
			      NULL, 0, NULL);
	if (ret)
		dev_err(ec->dev, "failed to add usb-pd-charger device\n");
}

static void cros_ec_sensors_register(struct cros_ec_dev *ec)
{
	/*
	 * Issue a command to get the number of sensor reported.
	 * Build an array of sensors driver and register them all.
	 */
	int ret, i, id, sensor_num;
	struct mfd_cell *sensor_cells;
	struct cros_ec_sensor_platform *sensor_platforms;
	int sensor_type[MOTIONSENSE_TYPE_MAX];
	struct ec_params_motion_sense *params;
	struct ec_response_motion_sense *resp;
	struct cros_ec_command *msg;

	msg = kzalloc(sizeof(struct cros_ec_command) +
		      max(sizeof(*params), sizeof(*resp)), GFP_KERNEL);
	if (msg == NULL)
		return;

	msg->version = 2;
	msg->command = EC_CMD_MOTION_SENSE_CMD + ec->cmd_offset;
	msg->outsize = sizeof(*params);
	msg->insize = sizeof(*resp);

	params = (struct ec_params_motion_sense *)msg->data;
	params->cmd = MOTIONSENSE_CMD_DUMP;

	ret = cros_ec_cmd_xfer(ec->ec_dev, msg);
	if (ret < 0 || msg->result != EC_RES_SUCCESS) {
		dev_warn(ec->dev, "cannot get EC sensor information: %d/%d\n",
			 ret, msg->result);
		goto error;
	}

	resp = (struct ec_response_motion_sense *)msg->data;
	sensor_num = resp->dump.sensor_count;
	/* Allocate 1 extra sensor in FIFO are needed */
	sensor_cells = kzalloc(sizeof(struct mfd_cell) * (sensor_num + 1),
			       GFP_KERNEL);
	if (sensor_cells == NULL)
		goto error;

	sensor_platforms = kzalloc(sizeof(struct cros_ec_sensor_platform) *
		  (sensor_num + 1), GFP_KERNEL);
	if (sensor_platforms == NULL)
		goto error_platforms;

	memset(sensor_type, 0, sizeof(sensor_type));
	id = 0;
	for (i = 0; i < sensor_num; i++) {
		params->cmd = MOTIONSENSE_CMD_INFO;
		params->info.sensor_num = i;
		ret = cros_ec_cmd_xfer(ec->ec_dev, msg);
		if (ret < 0 || msg->result != EC_RES_SUCCESS) {
			dev_warn(ec->dev, "no info for EC sensor %d : %d/%d\n",
				 i, ret, msg->result);
			continue;
		}
		switch (resp->info.type) {
		case MOTIONSENSE_TYPE_ACCEL:
			sensor_cells[id].name = "cros-ec-accel";
			break;
		case MOTIONSENSE_TYPE_BARO:
			sensor_cells[id].name = "cros-ec-baro";
			break;
		case MOTIONSENSE_TYPE_GYRO:
			sensor_cells[id].name = "cros-ec-gyro";
			break;
		case MOTIONSENSE_TYPE_MAG:
			sensor_cells[id].name = "cros-ec-mag";
			break;
		case MOTIONSENSE_TYPE_PROX:
			sensor_cells[id].name = "cros-ec-prox";
			break;
		case MOTIONSENSE_TYPE_LIGHT:
			sensor_cells[id].name = "cros-ec-light";
			break;
		case MOTIONSENSE_TYPE_ACTIVITY:
			sensor_cells[id].name = "cros-ec-activity";
			break;
		case MOTIONSENSE_TYPE_SYNC:
			sensor_cells[id].name = "cros-ec-sync";
			break;
		default:
			dev_warn(ec->dev, "unknown type %d\n", resp->info.type);
			continue;
		}
		sensor_platforms[id].sensor_num = i;
		sensor_cells[id].id = sensor_type[resp->info.type];
		sensor_cells[id].platform_data = &sensor_platforms[id];
		sensor_cells[id].pdata_size =
			sizeof(struct cros_ec_sensor_platform);

		sensor_type[resp->info.type]++;
		id++;
	}

	if (sensor_type[MOTIONSENSE_TYPE_ACCEL] >= 2)
		ec->has_kb_wake_angle = true;

	if (cros_ec_check_features(ec, EC_FEATURE_MOTION_SENSE_FIFO)) {
		sensor_cells[id].name = "cros-ec-ring";
		id++;
	}

	ret = mfd_add_devices(ec->dev, 0, sensor_cells, id,
			      NULL, 0, NULL);
	if (ret)
		dev_err(ec->dev, "failed to add EC sensors\n");

	kfree(sensor_platforms);
error_platforms:
	kfree(sensor_cells);
error:
	kfree(msg);
}

#define CROS_EC_SENSOR_LEGACY_NUM 2
static struct mfd_cell cros_ec_accel_legacy_cells[CROS_EC_SENSOR_LEGACY_NUM];

static void cros_ec_accel_legacy_register(struct cros_ec_dev *ec)
{
	struct cros_ec_device *ec_dev = ec->ec_dev;
	u8 status;
	int i, ret;
	struct cros_ec_sensor_platform
		sensor_platforms[CROS_EC_SENSOR_LEGACY_NUM];

	/*
	 * EC that need legacy support are the main EC, directly connected to
	 * the AP.
	 */
	if (ec->cmd_offset != 0)
		return;

	/*
	 * Check if EC supports direct memory reads and if EC has
	 * accelerometers.
	 */
	if (!ec_dev->cmd_readmem)
		return;

	ret = ec_dev->cmd_readmem(ec_dev, EC_MEMMAP_ACC_STATUS, 1, &status);
	if (ret < 0) {
		dev_warn(ec->dev, "EC does not support direct reads.\n");
		return;
	}

	/* Check if EC has accelerometers. */
	if (!(status & EC_MEMMAP_ACC_STATUS_PRESENCE_BIT)) {
		dev_info(ec->dev, "EC does not have accelerometers.\n");
		return;
	}

	/*
	 * Register 2 accelerometers
	 */
	for (i = 0; i < CROS_EC_SENSOR_LEGACY_NUM; i++) {
		cros_ec_accel_legacy_cells[i].name = "cros-ec-accel-legacy";
		sensor_platforms[i].sensor_num = i;
		cros_ec_accel_legacy_cells[i].id = i;
		cros_ec_accel_legacy_cells[i].platform_data =
			&sensor_platforms[i];
		cros_ec_accel_legacy_cells[i].pdata_size =
			sizeof(struct cros_ec_sensor_platform);
	}
	ret = mfd_add_devices(ec->dev, PLATFORM_DEVID_AUTO,
			      cros_ec_accel_legacy_cells,
			      CROS_EC_SENSOR_LEGACY_NUM,
			      NULL, 0, NULL);
	if (ret)
		dev_err(ec_dev->dev, "failed to add EC sensors\n");
}

static const struct mfd_cell cros_ec_rtc_cell = {
	.name = "cros-ec-rtc",
};

static int ec_device_probe(struct platform_device *pdev)
{
	int retval = -ENOMEM;
	struct device *dev = &pdev->dev;
	struct cros_ec_platform *ec_platform = dev_get_platdata(dev);
	struct cros_ec_dev *ec = kzalloc(sizeof(*ec), GFP_KERNEL);

	if (!ec)
		return retval;

	dev_set_drvdata(dev, ec);
	ec->ec_dev = dev_get_drvdata(dev->parent);
	ec->dev = dev;
	ec->cmd_offset = ec_platform->cmd_offset;
	ec->features[0] = -1U; /* Not cached yet */
	ec->features[1] = -1U; /* Not cached yet */
	device_initialize(&ec->class_dev);
	cdev_init(&ec->cdev, &fops);

	/* check whether this is actually a Fingerprint MCU rather than an EC */
	if (cros_ec_check_features(ec, EC_FEATURE_FINGERPRINT)) {
		dev_info(dev, "Fingerprint MCU detected.\n");
		/*
		 * Help userspace differentiating ECs from FP MCU,
		 * regardless of the probing order.
		 */
		ec_platform->ec_name = CROS_EC_DEV_FP_NAME;
	}

	/* check whether this is actually a Touchpad MCU rather than an EC */
	if (cros_ec_check_features(ec, EC_FEATURE_TOUCHPAD)) {
		dev_info(dev, "Touchpad MCU detected.\n");
		/*
		 * Help userspace differentiating ECs from TP MCU,
		 * regardless of the probing order.
		 */
		ec_platform->ec_name = CROS_EC_DEV_TP_NAME;
	}

	/*
	 * Add the class device
	 * Link to the character device for creating the /dev entry
	 * in devtmpfs.
	 */
	ec->class_dev.devt = MKDEV(ec_major, pdev->id);
	ec->class_dev.class = &cros_class;
	ec->class_dev.parent = dev;
	ec->class_dev.release = __remove;

	retval = dev_set_name(&ec->class_dev, "%s", ec_platform->ec_name);
	if (retval) {
		dev_err(dev, "dev_set_name failed => %d\n", retval);
		goto failed;
	}

	/* check whether this EC is a sensor hub. */
	if (cros_ec_check_features(ec, EC_FEATURE_MOTION_SENSE))
		cros_ec_sensors_register(ec);
	else
		/* Workaroud for older EC firmware */
		cros_ec_accel_legacy_register(ec);

	/* check whether this EC instance has RTC host command support */
	if (cros_ec_check_features(ec, EC_FEATURE_RTC)) {
		retval = mfd_add_devices(ec->dev, PLATFORM_DEVID_AUTO,
					 &cros_ec_rtc_cell, 1, NULL, 0, NULL);
		if (retval)
			dev_err(ec->dev,
				"failed to add cros-ec-rtc device: %d\n",
				retval);
	}

	/* Take control of the lightbar from the EC. */
	lb_manual_suspend_ctrl(ec, 1);

	/* We can now add the sysfs class, we know which parameter to show */
	retval = cdev_device_add(&ec->cdev, &ec->class_dev);
	if (retval) {
		dev_err(dev, "cdev_device_add failed => %d\n", retval);
		goto failed;
	}

	if (cros_ec_debugfs_init(ec))
		dev_warn(dev, "failed to create debugfs directory\n");

	/* check whether this EC instance has the PD charge manager */
	if (cros_ec_check_features(ec, EC_FEATURE_USB_PD))
		cros_ec_usb_pd_charger_register(ec);

	return 0;

failed:
	put_device(&ec->class_dev);
	return retval;
}

static int ec_device_remove(struct platform_device *pdev)
{
	struct cros_ec_dev *ec = dev_get_drvdata(&pdev->dev);

	/* Let the EC take over the lightbar again. */
	lb_manual_suspend_ctrl(ec, 0);

	cros_ec_debugfs_remove(ec);

	cdev_del(&ec->cdev);
	device_unregister(&ec->class_dev);
	return 0;
}

static void ec_device_shutdown(struct platform_device *pdev)
{
	struct cros_ec_dev *ec = dev_get_drvdata(&pdev->dev);

	/* Be sure to clear up debugfs delayed works */
	cros_ec_debugfs_remove(ec);
}

static const struct platform_device_id cros_ec_id[] = {
	{ DRV_NAME, 0 },
	{ /* sentinel */ },
};
MODULE_DEVICE_TABLE(platform, cros_ec_id);

static __maybe_unused int ec_device_suspend(struct device *dev)
{
	struct cros_ec_dev *ec = dev_get_drvdata(dev);

	cros_ec_debugfs_suspend(ec);

	lb_suspend(ec);

	return 0;
}

static __maybe_unused int ec_device_resume(struct device *dev)
{
	struct cros_ec_dev *ec = dev_get_drvdata(dev);

	cros_ec_debugfs_resume(ec);

	lb_resume(ec);

	return 0;
}

static const struct dev_pm_ops cros_ec_dev_pm_ops = {
#ifdef CONFIG_PM_SLEEP
	.suspend = ec_device_suspend,
	.resume = ec_device_resume,
#endif
};

static struct platform_driver cros_ec_dev_driver = {
	.driver = {
		.name = DRV_NAME,
		.pm = &cros_ec_dev_pm_ops,
	},
	.probe = ec_device_probe,
	.remove = ec_device_remove,
	.shutdown = ec_device_shutdown,
};

static int __init cros_ec_dev_init(void)
{
	int ret;
	dev_t dev = 0;

	ret  = class_register(&cros_class);
	if (ret) {
		pr_err(CROS_EC_DEV_NAME ": failed to register device class\n");
		return ret;
	}

	/* Get a range of minor numbers (starting with 0) to work with */
	ret = alloc_chrdev_region(&dev, 0, CROS_MAX_DEV, CROS_EC_DEV_NAME);
	if (ret < 0) {
		pr_err(CROS_EC_DEV_NAME ": alloc_chrdev_region() failed\n");
		goto failed_chrdevreg;
	}
	ec_major = MAJOR(dev);

	/* Register the driver */
	ret = platform_driver_register(&cros_ec_dev_driver);
	if (ret < 0) {
		pr_warn(CROS_EC_DEV_NAME ": can't register driver: %d\n", ret);
		goto failed_devreg;
	}
	return 0;

failed_devreg:
	unregister_chrdev_region(MKDEV(ec_major, 0), CROS_MAX_DEV);
failed_chrdevreg:
	class_unregister(&cros_class);
	return ret;
}

static void __exit cros_ec_dev_exit(void)
{
	platform_driver_unregister(&cros_ec_dev_driver);
	unregister_chrdev(ec_major, CROS_EC_DEV_NAME);
	class_unregister(&cros_class);
}

module_init(cros_ec_dev_init);
module_exit(cros_ec_dev_exit);

MODULE_ALIAS("platform:" DRV_NAME);
MODULE_AUTHOR("Bill Richardson <wfrichar@chromium.org>");
MODULE_DESCRIPTION("Userspace interface to the Chrome OS Embedded Controller");
MODULE_VERSION("1.0");
MODULE_LICENSE("GPL");
