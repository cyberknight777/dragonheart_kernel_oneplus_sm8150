/*
 * ChromeOS EC multi-function device
 *
 * Copyright (C) 2012 Google, Inc
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * The ChromeOS EC multi function device is used to mux all the requests
 * to the EC device for its multiple features: keyboard controller,
 * battery charging and regulator control, firmware update.
 */

#include <linux/of_platform.h>
#include <linux/interrupt.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/mfd/core.h>
#include <linux/mfd/cros_ec.h>
#include <linux/suspend.h>
#include <asm/unaligned.h>

#define CROS_EC_DEV_EC_INDEX 0
#define CROS_EC_DEV_PD_INDEX 1

static struct cros_ec_platform ec_p = {
	.ec_name = CROS_EC_DEV_NAME,
	.cmd_offset = EC_CMD_PASSTHRU_OFFSET(CROS_EC_DEV_EC_INDEX),
};

static struct cros_ec_platform ec_fp_p = {
	.ec_name = CROS_EC_DEV_FP_NAME,
	.cmd_offset = EC_CMD_PASSTHRU_OFFSET(CROS_EC_DEV_EC_INDEX),
};

static struct cros_ec_platform ec_tp_p = {
	.ec_name = CROS_EC_DEV_TP_NAME,
	.cmd_offset = EC_CMD_PASSTHRU_OFFSET(CROS_EC_DEV_EC_INDEX),
};

static struct cros_ec_platform pd_p = {
	.ec_name = CROS_EC_DEV_PD_NAME,
	.cmd_offset = EC_CMD_PASSTHRU_OFFSET(CROS_EC_DEV_PD_INDEX),
};

static const struct mfd_cell ec_cell = {
	.name = "cros-ec-ctl",
	.platform_data = &ec_p,
	.pdata_size = sizeof(ec_p),
};

static const struct mfd_cell ec_fp_cell = {
	.name = "cros-ec-ctl",
	.platform_data = &ec_fp_p,
	.pdata_size = sizeof(ec_fp_p),
};

static const struct mfd_cell ec_tp_cell = {
	.name = "cros-ec-ctl",
	.platform_data = &ec_tp_p,
	.pdata_size = sizeof(ec_tp_p),
};

static const struct mfd_cell ec_pd_cell = {
	.name = "cros-ec-ctl",
	.platform_data = &pd_p,
	.pdata_size = sizeof(pd_p),
};

static const struct mfd_cell ec_rtc_cell = {
	.name = "cros-ec-rtc",
};

static const struct mfd_cell ec_usb_pd_charger_cell = {
	.name = "cros-usb-pd-charger",
};

static irqreturn_t ec_irq_thread(int irq, void *data)
{
	struct cros_ec_device *ec_dev = data;
	bool wake_event = true;
	int ret;

	ret = cros_ec_get_next_event(ec_dev, &wake_event);

	/*
	 * Signal only if wake host events or any interrupt if
	 * cros_ec_get_next_event() returned an error (default value for
	 * wake_event is true)
	 */
	if (wake_event && device_may_wakeup(ec_dev->dev))
		pm_wakeup_event(ec_dev->dev, 0);

	if (ret > 0)
		blocking_notifier_call_chain(&ec_dev->event_notifier,
					     0, ec_dev);
	return IRQ_HANDLED;
}

static int cros_ec_sleep_event(struct cros_ec_device *ec_dev, u8 sleep_event)
{
	struct {
		struct cros_ec_command msg;
		struct ec_params_host_sleep_event req;
	} __packed buf;

	memset(&buf, 0, sizeof(buf));

	buf.req.sleep_event = sleep_event;

	buf.msg.command = EC_CMD_HOST_SLEEP_EVENT;
	buf.msg.version = 0;
	buf.msg.outsize = sizeof(buf.req);

	return cros_ec_cmd_xfer(ec_dev, &buf.msg);
}

static int cros_ec_check_features(struct cros_ec_device *ec_dev, int feature)
{
	struct cros_ec_command *msg;
	int ret;

	if (ec_dev->features[0] == -1U && ec_dev->features[1] == -1U) {
		/* features bitmap not read yet */

		msg = kmalloc(sizeof(*msg) + sizeof(ec_dev->features),
			      GFP_KERNEL);
		if (!msg)
			return -ENOMEM;

		msg->version = 0;
		msg->command = EC_CMD_GET_FEATURES + ec_p.cmd_offset;
		msg->insize = sizeof(ec_dev->features);
		msg->outsize = 0;

		ret = cros_ec_cmd_xfer(ec_dev, msg);
		if (ret < 0 || msg->result != EC_RES_SUCCESS) {
			dev_warn(ec_dev->dev, "cannot get EC features: %d/%d\n",
				 ret, msg->result);
			memset(ec_dev->features, 0, sizeof(ec_dev->features));
		}

		memcpy(ec_dev->features, msg->data, sizeof(ec_dev->features));

		dev_dbg(ec_dev->dev, "EC features %08x %08x\n",
			ec_dev->features[0], ec_dev->features[1]);

		kfree(msg);
	}

	return ec_dev->features[feature / 32] & EC_FEATURE_MASK_0(feature);
}

static void cros_ec_sensors_register(struct cros_ec_device *ec_dev)
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
	msg->command = EC_CMD_MOTION_SENSE_CMD + ec_p.cmd_offset;
	msg->outsize = sizeof(*params);
	msg->insize = sizeof(*resp);

	params = (struct ec_params_motion_sense *)msg->data;
	params->cmd = MOTIONSENSE_CMD_DUMP;

	ret = cros_ec_cmd_xfer(ec_dev, msg);
	if (ret < 0 || msg->result != EC_RES_SUCCESS) {
		dev_warn(ec_dev->dev, "cannot get EC sensor information: %d/%d\n",
			 ret, msg->result);
		goto error;
	}

	resp = (struct ec_response_motion_sense *)msg->data;
	sensor_num = resp->dump.sensor_count;
	/* Allocate 2 extra sensors in case lid angle or FIFO are needed */
	sensor_cells = kzalloc(sizeof(struct mfd_cell) * (sensor_num + 2),
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
		ret = cros_ec_cmd_xfer(ec_dev, msg);
		if (ret < 0 || msg->result != EC_RES_SUCCESS) {
			dev_warn(ec_dev->dev, "no info for EC sensor %d : %d/%d\n",
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
		default:
			dev_warn(ec_dev->dev, "unknown type %d\n",
				 resp->info.type);
			continue;
		}
		sensor_platforms[id].sensor_num = i;
		sensor_platforms[id].cmd_offset = ec_p.cmd_offset;
		sensor_cells[id].id = sensor_type[resp->info.type];
		sensor_cells[id].platform_data = &sensor_platforms[id];
		sensor_cells[id].pdata_size =
			sizeof(struct cros_ec_sensor_platform);

		sensor_type[resp->info.type]++;
		id++;
	}
	if (sensor_type[MOTIONSENSE_TYPE_ACCEL] >= 2) {
		sensor_platforms[id].sensor_num = sensor_num;

		sensor_cells[id].name = "cros-ec-angle";
		sensor_cells[id].id = 0;
		sensor_cells[id].platform_data = &sensor_platforms[id];
		sensor_cells[id].pdata_size =
			sizeof(struct cros_ec_sensor_platform);
		id++;
	}

	ret = mfd_add_devices(ec_dev->dev, PLATFORM_DEVID_AUTO, sensor_cells,
			      id, NULL, 0, NULL);
	if (ret)
		dev_err(ec_dev->dev, "failed to add EC sensors\n");

	kfree(sensor_platforms);
error_platforms:
	kfree(sensor_cells);
error:
	kfree(msg);
}

static void cros_ec_rtc_register(struct cros_ec_device *ec_dev)
{
	int ret;

	ret = mfd_add_devices(ec_dev->dev, PLATFORM_DEVID_AUTO, &ec_rtc_cell,
			      1, NULL, 0, NULL);
	if (ret)
		dev_err(ec_dev->dev, "failed to add EC RTC\n");
}

static void cros_ec_usb_pd_charger_register(struct cros_ec_device *ec_dev)
{
	int ret;

	ret = mfd_add_devices(ec_dev->dev, PLATFORM_DEVID_AUTO, &ec_usb_pd_charger_cell,
			      1, NULL, 0, NULL);
	if (ret)
		dev_err(ec_dev->dev, "failed to add usb-pd-charger\n");
}

#define CROS_EC_SENSOR_LEGACY_NUM 2
static struct mfd_cell cros_ec_accel_legacy_cells[CROS_EC_SENSOR_LEGACY_NUM];

static void cros_ec_accel_legacy_register(struct cros_ec_device *ec_dev)
{
	u8 status;
	int i, ret;
	struct cros_ec_sensor_platform
		sensor_platforms[CROS_EC_SENSOR_LEGACY_NUM];

	/*
	 * Check if EC supports direct memory reads and if EC has
	 * accelerometers.
	 */
	if (!ec_dev->cmd_readmem)
		return;

	ret = ec_dev->cmd_readmem(ec_dev, EC_MEMMAP_ACC_STATUS, 1, &status);
	if (ret < 0) {
		dev_warn(ec_dev->dev, "EC does not support direct reads.\n");
		return;
	}

	/* Check if EC has accelerometers. */
	if (!(status & EC_MEMMAP_ACC_STATUS_PRESENCE_BIT)) {
		dev_info(ec_dev->dev, "EC does not have accelerometers.\n");
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
	ret = mfd_add_devices(ec_dev->dev, PLATFORM_DEVID_AUTO,
			      cros_ec_accel_legacy_cells,
			      CROS_EC_SENSOR_LEGACY_NUM,
			      NULL, 0, NULL);
	if (ret)
		dev_err(ec_dev->dev, "failed to add EC sensors\n");
}

int cros_ec_register(struct cros_ec_device *ec_dev)
{
	const struct mfd_cell *cell = &ec_cell;
	struct device *dev = ec_dev->dev;
	int err = 0;

	BLOCKING_INIT_NOTIFIER_HEAD(&ec_dev->event_notifier);

	ec_dev->max_request = sizeof(struct ec_params_hello);
	ec_dev->max_response = sizeof(struct ec_response_get_protocol_info);
	ec_dev->max_passthru = 0;
	ec_dev->features[0] = -1U; /* Not cached yet */
	ec_dev->features[1] = -1U; /* Not cached yet */

	ec_dev->din = devm_kzalloc(dev, ec_dev->din_size, GFP_KERNEL);
	if (!ec_dev->din)
		return -ENOMEM;

	ec_dev->dout = devm_kzalloc(dev, ec_dev->dout_size, GFP_KERNEL);
	if (!ec_dev->dout)
		return -ENOMEM;

	mutex_init(&ec_dev->lock);

	err = cros_ec_query_all(ec_dev);
	if (err) {
		dev_err(dev, "Cannot identify the EC: error %d\n", err);
		return err;
	}

	if (ec_dev->irq) {
		err = request_threaded_irq(ec_dev->irq, NULL, ec_irq_thread,
					   IRQF_TRIGGER_LOW | IRQF_ONESHOT,
					   "chromeos-ec", ec_dev);
		if (err) {
			dev_err(dev, "Failed to request IRQ %d: %d",
				ec_dev->irq, err);
			return err;
		}
	}

	/* check whether this is actually a Fingerprint MCU rather than an EC */
	if (cros_ec_check_features(ec_dev, EC_FEATURE_FINGERPRINT)) {
		dev_info(dev, "Fingerprint MCU detected.\n");
		cell = &ec_fp_cell;
	}

	/* check whether this is actually a Touchpad MCU rather than an EC */
	if (cros_ec_check_features(ec_dev, EC_FEATURE_TOUCHPAD)) {
		dev_info(dev, "Touchpad MCU detected.\n");
		cell = &ec_tp_cell;
	}

	err = mfd_add_devices(ec_dev->dev, PLATFORM_DEVID_AUTO, cell, 1,
			      NULL, ec_dev->irq, NULL);
	if (err) {
		dev_err(dev,
			"Failed to register Embedded Controller subdevice %d\n",
			err);
		goto fail_mfd;
	}

	/* Check whether this EC is a sensor hub. */
	if (cros_ec_check_features(ec_dev, EC_FEATURE_MOTION_SENSE))
		cros_ec_sensors_register(ec_dev);
	else
		/* Workaroud for very old EC firmware */
		cros_ec_accel_legacy_register(ec_dev);

	/* Check whether this EC has RTC support */
	if (cros_ec_check_features(ec_dev, EC_FEATURE_RTC))
		cros_ec_rtc_register(ec_dev);

	/* Check whether this EC has the PD charger manager */
	if (cros_ec_check_features(ec_dev, EC_FEATURE_USB_PD))
		cros_ec_usb_pd_charger_register(ec_dev);

	if (ec_dev->max_passthru) {
		/*
		 * Register a PD device as well on top of this device.
		 * We make the following assumptions:
		 * - behind an EC, we have a pd
		 * - only one device added.
		 * - the EC is responsive at init time (it is not true for a
		 *   sensor hub.
		 */
		err = mfd_add_devices(ec_dev->dev, PLATFORM_DEVID_AUTO,
				      &ec_pd_cell, 1, NULL, ec_dev->irq, NULL);
		if (err) {
			dev_err(dev,
				"Failed to register Power Delivery subdevice %d\n",
				err);
			goto fail_mfd;
		}
	}

	if (IS_ENABLED(CONFIG_OF) && dev->of_node) {
		err = devm_of_platform_populate(dev);
		if (err) {
			mfd_remove_devices(dev);
			dev_err(dev, "Failed to register sub-devices\n");
			goto fail_mfd;
		}
	}

	/*
	 * Clear sleep event - this will fail harmlessly on platforms that
	 * don't implement the sleep event host command.
	 */
	err = cros_ec_sleep_event(ec_dev, 0);
	if (err < 0)
		dev_dbg(ec_dev->dev, "Error %d clearing sleep event to ec",
			err);

	dev_info(dev, "Chrome EC device registered\n");

	cros_ec_acpi_install_gpe_handler(dev);

	return 0;

fail_mfd:
	if (ec_dev->irq)
		free_irq(ec_dev->irq, ec_dev);
	return err;
}
EXPORT_SYMBOL(cros_ec_register);

int cros_ec_remove(struct cros_ec_device *ec_dev)
{
	mfd_remove_devices(ec_dev->dev);

	cros_ec_acpi_remove_gpe_handler();

	if (ec_dev->irq)
		free_irq(ec_dev->irq, ec_dev);

	return 0;
}
EXPORT_SYMBOL(cros_ec_remove);

#ifdef CONFIG_PM_SLEEP
int cros_ec_suspend(struct cros_ec_device *ec_dev)
{
	struct device *dev = ec_dev->dev;
	int ret;
	u8 sleep_event;

	if (!IS_ENABLED(CONFIG_ACPI) || pm_suspend_via_firmware()) {
		sleep_event = HOST_SLEEP_EVENT_S3_SUSPEND;
	} else {
		sleep_event = HOST_SLEEP_EVENT_S0IX_SUSPEND;

		/* Clearing the GPE status for any pending event */
		cros_ec_acpi_clear_gpe();
	}

	ret = cros_ec_sleep_event(ec_dev, sleep_event);
	if (ret < 0)
		dev_dbg(ec_dev->dev, "Error %d sending suspend event to ec",
			ret);

	if (device_may_wakeup(dev))
		ec_dev->wake_enabled = !enable_irq_wake(ec_dev->irq);

	disable_irq(ec_dev->irq);
	ec_dev->was_wake_device = ec_dev->wake_enabled;
	ec_dev->suspended = true;

	return 0;
}
EXPORT_SYMBOL(cros_ec_suspend);

static void cros_ec_drain_events(struct cros_ec_device *ec_dev)
{
	while (cros_ec_get_next_event(ec_dev, NULL) > 0)
		blocking_notifier_call_chain(&ec_dev->event_notifier,
					     1, ec_dev);
}

int cros_ec_resume(struct cros_ec_device *ec_dev)
{
	int ret;
	u8 sleep_event;

	ec_dev->suspended = false;
	enable_irq(ec_dev->irq);

	sleep_event = (!IS_ENABLED(CONFIG_ACPI) || pm_suspend_via_firmware()) ?
		      HOST_SLEEP_EVENT_S3_RESUME :
		      HOST_SLEEP_EVENT_S0IX_RESUME;

	ret = cros_ec_sleep_event(ec_dev, sleep_event);
	if (ret < 0)
		dev_dbg(ec_dev->dev, "Error %d sending resume event to ec",
			ret);

	/*
	 * In some cases, we need to distinguish between events that occur
	 * during suspend if the EC is not a wake source. For example,
	 * keypresses during suspend should be discarded if it does not wake
	 * the system.
	 *
	 * If the EC is not a wake source, drain the event queue and mark them
	 * as "queued during suspend".
	 */
	if (ec_dev->wake_enabled) {
		disable_irq_wake(ec_dev->irq);
		ec_dev->wake_enabled = 0;
	} else {
		cros_ec_drain_events(ec_dev);
	}

	return 0;
}
EXPORT_SYMBOL(cros_ec_resume);

#endif

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("ChromeOS EC core driver");
