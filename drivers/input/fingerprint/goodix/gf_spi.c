/*
 * TEE driver for goodix fingerprint sensor
 * Copyright (C) 2016 Goodix
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#define pr_fmt(fmt)		KBUILD_MODNAME ": " fmt

#define CONFIG_MSM_RDM_NOTIFY
#undef CONFIG_FB

#include <linux/clk.h>
#include <linux/compat.h>
#include <linux/cpufreq.h>
#include <linux/delay.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/fb.h>
#include <linux/fs.h>
#include <linux/gpio.h>
#include <linux/init.h>
#include <linux/input.h>
#include <linux/interrupt.h>
#include <linux/ioctl.h>
#include <linux/irq.h>
#include <linux/ktime.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/notifier.h>
#include <linux/of_gpio.h>
#include <linux/oneplus/boot_mode.h>
#include <linux/platform_device.h>
#include <linux/pm_qos.h>
#include <linux/regulator/consumer.h>
#include <linux/regulator/consumer.h>
#include <linux/slab.h>
#include <linux/time.h>
#include <linux/timer.h>
#include <linux/uaccess.h>
#include <linux/workqueue.h>
#include <net/netlink.h>
#include <net/sock.h>
#include "gf_spi.h"
#include "../fingerprint_detect/fingerprint_detect.h"

#define VER_MAJOR   1
#define VER_MINOR   2
#define PATCH_LEVEL 8
#define WAKELOCK_HOLD_TIME 400 /* in ms */
#define GF_SPIDEV_NAME     "goodix,fingerprint"
/*device name after register in charater*/
#define GF_DEV_NAME            "goodix_fp"
#define	GF_INPUT_NAME	    "gf_input"	/*"goodix_fp" */
#define	CHRD_DRIVER_NAME	"goodix_fp_spi"
#define	CLASS_NAME		    "goodix_fp"
#define N_SPI_MINORS		32	/* ... up to 256 */

static int SPIDEV_MAJOR;
static DECLARE_BITMAP(minors, N_SPI_MINORS);
static LIST_HEAD(device_list);
static DEFINE_MUTEX(device_list_lock);
static struct wakeup_source fp_wakelock;
static struct gf_dev gf;
static int pid = -1;
struct sock *gf_nl_sk = NULL;

static inline void sendnlmsg(char *msg)
{
	struct sk_buff *skb_1;
	struct nlmsghdr *nlh;
	int len = NLMSG_SPACE(MAX_MSGSIZE);
	int ret = 0;
	if (!msg || !gf_nl_sk || !pid) {
		return ;
	}
	skb_1 = alloc_skb(len, GFP_KERNEL);
	if (!skb_1) {
		return;
	}
	nlh = nlmsg_put(skb_1, 0, 0, 0, MAX_MSGSIZE, 0);
	NETLINK_CB(skb_1).portid = 0;
	NETLINK_CB(skb_1).dst_group = 0;
	memcpy(NLMSG_DATA(nlh), msg, sizeof(char));
	ret = netlink_unicast(gf_nl_sk, skb_1, pid, MSG_DONTWAIT);
}

static inline void sendnlmsg_tp(struct fp_underscreen_info *msg, int length)
{
	struct sk_buff *skb_1;
	struct nlmsghdr *nlh;
	int len = NLMSG_SPACE(MAX_MSGSIZE);
	int ret = 0;
	if (!msg || !gf_nl_sk || !pid) {
		return ;
	}
	skb_1 = alloc_skb(len, GFP_KERNEL);
	if (!skb_1) {
		return;
	}
	nlh = nlmsg_put(skb_1, 0, 0, 0, length, 0);
	NETLINK_CB(skb_1).portid = 0;
	NETLINK_CB(skb_1).dst_group = 0;
	memcpy(NLMSG_DATA(nlh), msg, length);//core
	ret = netlink_unicast(gf_nl_sk, skb_1, pid, MSG_DONTWAIT);
}

static inline void nl_data_ready(struct sk_buff *__skb)
{
	struct sk_buff *skb;
	struct nlmsghdr *nlh;
	char str[100];
	skb = skb_get (__skb);
	if(skb->len >= NLMSG_SPACE(0))
	{
		nlh = nlmsg_hdr(skb);
		memcpy(str, NLMSG_DATA(nlh), sizeof(str));
		pid = nlh->nlmsg_pid;
		kfree_skb(skb);
	}
}

static inline int netlink_init(void)
{
	struct netlink_kernel_cfg netlink_cfg;
	memset(&netlink_cfg, 0, sizeof(struct netlink_kernel_cfg));
	netlink_cfg.groups = 0;
	netlink_cfg.flags = 0;
	netlink_cfg.input = nl_data_ready;
	netlink_cfg.cb_mutex = NULL;
	gf_nl_sk = netlink_kernel_create(&init_net, NETLINK_TEST,
			&netlink_cfg);
	if(!gf_nl_sk){
		return 1;
	}
	return 0;
}

static inline void netlink_exit(void)
{
	if(gf_nl_sk != NULL){
		netlink_kernel_release(gf_nl_sk);
		gf_nl_sk = NULL;
	}
}

static inline int gf_pinctrl_init(struct gf_dev* gf_dev)
{
	int ret = 0;
	struct device *dev = &gf_dev->spi->dev;

	gf_dev->gf_pinctrl = devm_pinctrl_get(dev);
	if (IS_ERR_OR_NULL(gf_dev->gf_pinctrl)) {
		ret = PTR_ERR(gf_dev->gf_pinctrl);
		goto err;
	}
	gf_dev->gpio_state_enable =
		pinctrl_lookup_state(gf_dev->gf_pinctrl, "fp_en_init");
	if (IS_ERR_OR_NULL(gf_dev->gpio_state_enable)) {
		ret = PTR_ERR(gf_dev->gpio_state_enable);
		goto err;
	}
	gf_dev->gpio_state_disable =
		pinctrl_lookup_state(gf_dev->gf_pinctrl, "fp_dis_init");
	if (IS_ERR_OR_NULL(gf_dev->gpio_state_disable)) {
		ret = PTR_ERR(gf_dev->gpio_state_disable);
		goto err;
	}

	return 0;
err:
	gf_dev->gf_pinctrl = NULL;
	gf_dev->gpio_state_enable = NULL;
	gf_dev->gpio_state_disable = NULL;
	return ret;
}

static inline int gf_parse_dts(struct gf_dev* gf_dev)
{
	int rc = 0;
	struct device *dev = &gf_dev->spi->dev;
	struct device_node *np = dev->of_node;

	gf_dev->reset_gpio = of_get_named_gpio(np, "fp-gpio-reset", 0);
	if (gf_dev->reset_gpio < 0) {
		return gf_dev->reset_gpio;
	}

	rc = devm_gpio_request(dev, gf_dev->reset_gpio, "goodix_reset");
	if (rc) {
		goto err_reset;
	}
	gpio_direction_output(gf_dev->reset_gpio, 0);

	gf_dev->irq_gpio = of_get_named_gpio(np, "fp-gpio-irq", 0);
	if (gf_dev->irq_gpio < 0) {
		return gf_dev->irq_gpio;
	}

	rc = devm_gpio_request(dev, gf_dev->irq_gpio, "goodix_irq");
	if (rc) {
		goto err_irq;
	}
	gpio_direction_input(gf_dev->irq_gpio);

	return rc;
err_irq:
	devm_gpio_free(dev, gf_dev->irq_gpio);
err_reset:
	devm_gpio_free(dev, gf_dev->reset_gpio);
	return rc;
}

static inline int gf_hw_reset(struct gf_dev *gf_dev, unsigned int delay_ms)
{
	if(gf_dev == NULL) {
		return -1;
	}
	gpio_direction_output(gf_dev->reset_gpio, 1);
	gpio_set_value(gf_dev->reset_gpio, 0);
	mdelay(3);
	gpio_set_value(gf_dev->reset_gpio, 1);
	mdelay(delay_ms);
	return 0;
}

static inline void gf_enable_irq(struct gf_dev *gf_dev)
{
	if (!(gf_dev->irq_enabled)) {
		enable_irq(gf_dev->irq);
		gf_dev->irq_enabled = 1;
	}
}

static inline void gf_disable_irq(struct gf_dev *gf_dev)
{
	if (gf_dev->irq_enabled) {
		gf_dev->irq_enabled = 0;
		disable_irq(gf_dev->irq);
	}
}

static inline irqreturn_t gf_irq(int irq, void *handle)
{
	char msg = GF_NET_EVENT_IRQ;
	__pm_wakeup_event(&fp_wakelock, WAKELOCK_HOLD_TIME);
	sendnlmsg(&msg);
	return IRQ_HANDLED;
}

static inline int irq_setup(struct gf_dev *gf_dev)
{
	int status;
	gf_dev->irq = gpio_to_irq(gf_dev->irq_gpio);
	status = request_threaded_irq(gf_dev->irq, NULL, gf_irq,
			IRQF_TRIGGER_RISING | IRQF_ONESHOT,
			"gf", gf_dev);

	if (status) {
		return status;
	}
	enable_irq_wake(gf_dev->irq);
	gf_dev->irq_enabled = 1;

	return status;
}

static long gf_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct gf_dev *gf_dev = &gf;
	struct gf_key gf_key;
	int retval = 0;
	u8 netlink_route = NETLINK_TEST;
	struct gf_ioc_chip_info info;

	if (_IOC_TYPE(cmd) != GF_IOC_MAGIC)
		return -ENODEV;

	if (_IOC_DIR(cmd) & _IOC_READ)
		retval = !access_ok(VERIFY_WRITE, (void __user *)arg, _IOC_SIZE(cmd));
	else if (_IOC_DIR(cmd) & _IOC_WRITE)
		retval = !access_ok(VERIFY_READ, (void __user *)arg, _IOC_SIZE(cmd));
	if (retval)
		return -EFAULT;

	switch (cmd) {
	case GF_IOC_INIT:
		if (copy_to_user((void __user *)arg, (void *)&netlink_route, sizeof(u8))) {
			retval = -EFAULT;
			break;
		}
		break;
	case GF_IOC_EXIT:
		break;
	case GF_IOC_DISABLE_IRQ:
		gf_disable_irq(gf_dev);
		break;
	case GF_IOC_ENABLE_IRQ:
		gf_enable_irq(gf_dev);
		break;
	case GF_IOC_RESET:
		gf_hw_reset(gf_dev, 0);
		break;
	case GF_IOC_ENABLE_POWER:
		if (gf_dev->device_available == 0)
			gf_power_on(gf_dev);
		gf_dev->device_available = 1;
		break;
	case GF_IOC_DISABLE_POWER:
		if (gf_dev->device_available == 1)
			gf_power_off(gf_dev);
		gf_dev->device_available = 0;
		break;
	case GF_IOC_ENTER_SLEEP_MODE:
		break;
	case GF_IOC_GET_FW_INFO:
		break;
	case GF_IOC_REMOVE:
		break;

	case GF_IOC_CHIP_INFO:
		if (copy_from_user(&info, (struct gf_ioc_chip_info *)arg, sizeof(struct gf_ioc_chip_info))) {
			retval = -EFAULT;
			break;
		}
		break;
	default:
		break;
	}

	return retval;
}

#ifdef CONFIG_COMPAT
static inline long gf_compat_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	return gf_ioctl(filp, cmd, (unsigned long)compat_ptr(arg));
}
#endif /*CONFIG_COMPAT*/


static inline int gf_open(struct inode *inode, struct file *filp)
{
	struct gf_dev *gf_dev = &gf;
	int status = -ENXIO;

	mutex_lock(&device_list_lock);

	list_for_each_entry(gf_dev, &device_list, device_entry) {
		if (gf_dev->devt == inode->i_rdev) {
			status = 0;
			break;
		}
	}

	if (status == 0) {
		if (status == 0) {
			gf_dev->users++;
			filp->private_data = gf_dev;
			nonseekable_open(inode, filp);
			gf_dev->device_available = 1;
		}
	}
	mutex_unlock(&device_list_lock);
	return status;
}

static inline int gf_release(struct inode *inode, struct file *filp)
{
	struct gf_dev *gf_dev = &gf;
	int status = 0;

	mutex_lock(&device_list_lock);
	gf_dev = filp->private_data;
	filp->private_data = NULL;
	gf_dev->users--;
	if (!gf_dev->users) {
		gf_disable_irq(gf_dev);
		gf_dev->device_available = 0;
		gf_power_off(gf_dev);
	}
	mutex_unlock(&device_list_lock);
	return status;
}

static const struct file_operations gf_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = gf_ioctl,
	.compat_ioctl = gf_compat_ioctl,
	.open = gf_open,
	.release = gf_release,
};

static inline ssize_t screen_state_get(struct device *device,
			     struct device_attribute *attribute,
			     char *buffer)
{
	struct gf_dev *gfDev = dev_get_drvdata(device);
	return scnprintf(buffer, PAGE_SIZE, "%i\n", gfDev->screen_state);
}

static DEVICE_ATTR(screen_state, 0400, screen_state_get, NULL);

static struct attribute *gf_attributes[] = {
	&dev_attr_screen_state.attr,
	NULL
};

static const struct attribute_group gf_attribute_group = {
	.attrs = gf_attributes,
};

static struct fp_underscreen_info fp_tpinfo ={0};
int opticalfp_irq_handler(struct fp_underscreen_info* tp_info)
{
	if (gf.spi == NULL) {
		return 0;
	}
	fp_tpinfo = *tp_info;
	if (fp_tpinfo.touch_state == 1) {
		fp_tpinfo.touch_state = GF_NET_EVENT_TP_TOUCHDOWN;
		sendnlmsg_tp(&fp_tpinfo,sizeof(fp_tpinfo));
	} else if (fp_tpinfo.touch_state == 0) {
		fp_tpinfo.touch_state = GF_NET_EVENT_TP_TOUCHUP;
		sendnlmsg_tp(&fp_tpinfo,sizeof(fp_tpinfo));
	}
	return 0;
}
EXPORT_SYMBOL(opticalfp_irq_handler);

int gf_opticalfp_irq_handler(int event)
{
	char msg = 0;
	if (gf.spi == NULL) {
		return 0;
	}
	if (event == 1) {
		msg = GF_NET_EVENT_TP_TOUCHDOWN;
		sendnlmsg(&msg);
	} else if (event == 0) {
		msg = GF_NET_EVENT_TP_TOUCHUP;
		sendnlmsg(&msg);
	}
	__pm_wakeup_event(&fp_wakelock, 10*HZ);

	return 0;
}
EXPORT_SYMBOL(gf_opticalfp_irq_handler);

static int goodix_fb_state_chg_callback(
	struct notifier_block *nb, unsigned long val, void *data)
{
	struct gf_dev *gf_dev;
	struct msm_drm_notifier *evdata = data;
	unsigned int blank;
	char msg = 0;

	if (val != MSM_DRM_EARLY_EVENT_BLANK &&
		val != MSM_DRM_ONSCREENFINGERPRINT_EVENT)
		return 0;

	if (evdata->id != MSM_DRM_PRIMARY_DISPLAY)
	    return 0;

	blank = *(int *)(evdata->data);

	if (val == MSM_DRM_ONSCREENFINGERPRINT_EVENT) {
		switch (blank) {
		case 0:
			msg = GF_NET_EVENT_UI_DISAPPEAR;
			sendnlmsg(&msg);
			break;
		case 1:
			msg = GF_NET_EVENT_UI_READY;
			sendnlmsg(&msg);
			break;
		default:
			break;
		}
		return 0;
	}

	gf_dev = container_of(nb, struct gf_dev, msm_drm_notif);
	if (evdata && evdata->data && val ==
		MSM_DRM_EARLY_EVENT_BLANK && gf_dev) {
		blank = *(int *)(evdata->data);
		switch (blank) {
		case MSM_DRM_BLANK_POWERDOWN:
			if (gf_dev->device_available == 1) {
				gf_dev->fb_black = 1;
				msg = GF_NET_EVENT_FB_BLACK;
				sendnlmsg(&msg);
			}
			gf_dev->screen_state = 0;
			sysfs_notify(&gf_dev->spi->dev.kobj,
				NULL, dev_attr_screen_state.attr.name);
			break;
		case MSM_DRM_BLANK_UNBLANK:
			if (gf_dev->device_available == 1) {
				gf_dev->fb_black = 0;
				msg = GF_NET_EVENT_FB_UNBLACK;
				sendnlmsg(&msg);
			}
			gf_dev->screen_state = 1;
			sysfs_notify(&gf_dev->spi->dev.kobj,
				NULL, dev_attr_screen_state.attr.name);
			break;
		default:
			break;
		}
	}
	return NOTIFY_OK;
}

static struct class *gf_class;
static int gf_probe(struct platform_device *pdev)
{
	struct gf_dev *gf_dev = &gf;
	int status = -EINVAL;
	unsigned long minor;
	int i;
	INIT_LIST_HEAD(&gf_dev->device_entry);
	gf_dev->spi = pdev;
	gf_dev->irq_gpio = -EINVAL;
	gf_dev->reset_gpio = -EINVAL;
	gf_dev->pwr_gpio = -EINVAL;
	gf_dev->device_available = 0;
	gf_dev->fb_black = 0;

	/* If we can allocate a minor number, hook up this device.
	 * Reusing minors is fine so long as udev or mdev is working.
	 */
	mutex_lock(&device_list_lock);
	minor = find_first_zero_bit(minors, N_SPI_MINORS);
	if (minor < N_SPI_MINORS) {
		struct device *dev;
		gf_dev->devt = MKDEV(SPIDEV_MAJOR, minor);
		dev = device_create(gf_class, &gf_dev->spi->dev, gf_dev->devt,
				gf_dev, GF_DEV_NAME);
		status = IS_ERR(dev) ? PTR_ERR(dev) : 0;
	} else {
		status = -ENODEV;
		mutex_unlock(&device_list_lock);
		goto error_hw;
	}

	if (status == 0) {
		set_bit(minor, minors);
		list_add(&gf_dev->device_entry, &device_list);
	} else {
		gf_dev->devt = 0;
	}
	mutex_unlock(&device_list_lock);
	status = gf_parse_dts(gf_dev);
	if (status)
		goto err_parse_dt;
	/*
	 * liuyan mv wakelock here
	 * it should before irq
	 */
	wakeup_source_init(&fp_wakelock, "fp_wakelock");
	status = irq_setup(gf_dev);
	if (status)
		goto err_irq;

	status = gf_pinctrl_init(gf_dev);
	if (status)
		goto err_irq;
	if (get_boot_mode() !=  MSM_BOOT_MODE__FACTORY) {
		status = pinctrl_select_state(gf_dev->gf_pinctrl,
			gf_dev->gpio_state_enable);
		if (status) {
			goto error_hw;
		}
	} else {
		status = pinctrl_select_state(gf_dev->gf_pinctrl,
			gf_dev->gpio_state_disable);
		if (status) {
			goto error_hw;
		}
	}
	if (status == 0) {
		gf_dev->input = input_allocate_device();
		if (gf_dev->input == NULL) {
			status = -ENOMEM;
			goto error_dev;
		}
		gf_dev->input->name = GF_INPUT_NAME;
		status = input_register_device(gf_dev->input);
		if (status) {
			goto error_input;
		}
	}

	gf_dev->msm_drm_notif.notifier_call = goodix_fb_state_chg_callback;
	status = msm_drm_register_client(&gf_dev->msm_drm_notif);
	platform_set_drvdata(pdev, gf_dev);
	status = sysfs_create_group(&gf_dev->spi->dev.kobj,
			&gf_attribute_group);
	if (status) {
		goto error_input;
	}
	return status;

error_input:
	if (gf_dev->input != NULL)
		input_free_device(gf_dev->input);
error_dev:
	if (gf_dev->devt != 0) {
		mutex_lock(&device_list_lock);
		list_del(&gf_dev->device_entry);
		device_destroy(gf_class, gf_dev->devt);
		clear_bit(MINOR(gf_dev->devt), minors);
		mutex_unlock(&device_list_lock);
	}
err_irq:
	gf_cleanup(gf_dev);
err_parse_dt:
error_hw:
	gf_dev->device_available = 0;

	return status;
}

static inline int gf_remove(struct platform_device *pdev)
{
	struct gf_dev *gf_dev = &gf;

	wakeup_source_trash(&fp_wakelock);
	if (msm_drm_unregister_client(&gf_dev->msm_drm_notif))
	if (gf_dev->input)
		input_unregister_device(gf_dev->input);
	input_free_device(gf_dev->input);
	mutex_lock(&device_list_lock);
	list_del(&gf_dev->device_entry);
	device_destroy(gf_class, gf_dev->devt);
	clear_bit(MINOR(gf_dev->devt), minors);
	mutex_unlock(&device_list_lock);
	return 0;
}

static struct of_device_id gx_match_table[] = {
	{ .compatible = GF_SPIDEV_NAME },
	{},
};

static struct platform_driver gf_driver = {
	.driver = {
		.name = GF_DEV_NAME,
		.owner = THIS_MODULE,
		.of_match_table = gx_match_table,
	},
	.probe = gf_probe,
	.remove = gf_remove,
};

static inline int __init gf_init(void)
{
	int status;

	/* Claim our 256 reserved device numbers.  Then register a class
	 * that will key udev/mdev to add/remove /dev nodes.  Last, register
	 * the driver which manages those device numbers.
	 */
	if ((fp_version != 0x03) && (fp_version != 0x04) && (fp_version != 0x07))
		return 0;
	BUILD_BUG_ON(N_SPI_MINORS > 256);
	status = register_chrdev(SPIDEV_MAJOR, CHRD_DRIVER_NAME, &gf_fops);
	if (status < 0) {
		return status;
	}
	SPIDEV_MAJOR = status;
	gf_class = class_create(THIS_MODULE, CLASS_NAME);
	if (IS_ERR(gf_class)) {
		unregister_chrdev(SPIDEV_MAJOR, gf_driver.driver.name);
		return PTR_ERR(gf_class);
	}
	status = platform_driver_register(&gf_driver);
	if (status < 0) {
		class_destroy(gf_class);
		unregister_chrdev(SPIDEV_MAJOR, gf_driver.driver.name);
	}
	netlink_init();
	return 0;
}
module_init(gf_init);

static inline void __exit gf_exit(void)
{
	netlink_exit();
	platform_driver_unregister(&gf_driver);
	class_destroy(gf_class);
	unregister_chrdev(SPIDEV_MAJOR, gf_driver.driver.name);
}
module_exit(gf_exit);

MODULE_AUTHOR("Jiangtao Yi, <yijiangtao@goodix.com>");
MODULE_AUTHOR("Jandy Gou, <gouqingsong@goodix.com>");
MODULE_DESCRIPTION("goodix fingerprint sensor device driver");
MODULE_LICENSE("GPL");
