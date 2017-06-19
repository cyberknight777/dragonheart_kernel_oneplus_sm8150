/*
 * cros_ec_sensors_ring - Driver for Chrome OS EC Sensor hub FIFO.
 *
 * Copyright (C) 2015 Google, Inc
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
 * This driver uses the cros-ec interface to communicate with the Chrome OS
 * EC about accelerometer data. Accelerometer access is presented through
 * iio sysfs.
 */

#include <linux/delay.h>
#include <linux/device.h>
#include <linux/iio/buffer.h>
#include <linux/iio/iio.h>
#include <linux/iio/kfifo_buf.h>
#include <linux/iio/trigger.h>
#include <linux/iio/triggered_buffer.h>
#include <linux/iio/trigger_consumer.h>
#include <linux/kernel.h>
#include <linux/mfd/cros_ec.h>
#include <linux/mfd/cros_ec_commands.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/platform_device.h>

#include "cros_ec_sensors_core.h"

#define DRV_NAME "cros-ec-ring"

/* The ring is a FIFO that return sensor information from
 * the single EC FIFO.
 * There are always 5 channels returned:
 * | ID | FLAG | X | Y | Z | Timestamp |
 * ID is the EC sensor id
 * FLAG are extra information provided by the EC.
 */

enum {
	CHANNEL_SENSOR_ID,
	CHANNEL_SENSOR_FLAG,
	CHANNEL_X,
	CHANNEL_Y,
	CHANNEL_Z,
	CHANNEL_TIMESTAMP,
	MAX_CHANNEL,
};

enum {
	LAST_TS,
	NEW_TS,
	ALL_TS
};

#define CROS_EC_SENSOR_MAX 16

struct cros_ec_fifo_info {
	struct ec_response_motion_sense_fifo_info info;
	uint16_t lost[CROS_EC_SENSOR_MAX];
};

struct cros_ec_sensors_ring_sample {
	uint8_t sensor_id;
	uint8_t flag;
	int16_t  vector[CROS_EC_SENSOR_MAX_AXIS];
	s64      timestamp;
} __packed;

/* State data for ec_sensors iio driver. */
struct cros_ec_sensors_ring_state {
	/* Shared by all sensors */
	struct cros_ec_sensors_core_state core;

	/* Notifier to kick to the interrupt */
	struct notifier_block notifier;

	/* Preprocessed ring to send to kfifo */
	struct cros_ec_sensors_ring_sample *ring;

	s64    fifo_timestamp[ALL_TS];
	struct cros_ec_fifo_info fifo_info;
};

static const struct iio_info ec_sensors_info = {
	.driver_module = THIS_MODULE,
};

static s64 cros_ec_get_time_ns(void)
{
	struct timespec ts;

	get_monotonic_boottime(&ts);
	return timespec_to_ns(&ts);
}

/*
 * cros_ec_ring_process_event: process one EC FIFO event
 *
 * Process one EC event, add it in the ring if necessary.
 *
 * Return true if out event has been populated.
 *
 * fifo_info: fifo information from the EC.
 * fifo_timestamp: timestamp at time of fifo_info collection.
 * current_timestamp: estimated current timestamp.
 * in: incoming FIFO event from EC
 * out: outgoing event to user space.
 */
bool cros_ec_ring_process_event(const struct cros_ec_fifo_info *fifo_info,
				const s64 fifo_timestamp,
				s64 *current_timestamp,
				struct ec_response_motion_sensor_data *in,
				struct cros_ec_sensors_ring_sample *out)
{
	int axis;
	s64 new_timestamp;

	if (in->flags & MOTIONSENSE_SENSOR_FLAG_TIMESTAMP) {
		new_timestamp = fifo_timestamp -
			((s64)fifo_info->info.timestamp * 1000) +
			((s64)in->timestamp * 1000);
		/*
		 * The timestamp can be stale if we had to use the fifo
		 * info timestamp.
		 */
		if (new_timestamp - *current_timestamp > 0)
			*current_timestamp = new_timestamp;
	}

	if (in->flags & MOTIONSENSE_SENSOR_FLAG_FLUSH) {
		out->sensor_id = in->sensor_num;
		out->timestamp = *current_timestamp;
		out->flag = in->flags;
		/*
		 * No other payload information provided with
		 * flush ack.
		 */
		return true;
	}
	if (in->flags & MOTIONSENSE_SENSOR_FLAG_TIMESTAMP)
		/* If we just have a timestamp, skip this entry. */
		return false;

	/* Regular sample */
	out->sensor_id = in->sensor_num;
	out->timestamp = *current_timestamp;
	out->flag = in->flags;
	for (axis = CROS_EC_SENSOR_X; axis < CROS_EC_SENSOR_MAX_AXIS; axis++)
		out->vector[axis] = in->data[axis];
	return true;
}

/*
 * cros_ec_ring_handler - the trigger handler function
 *
 * @state: device information.
 *
 * Called by the notifier, process the EC sensor FIFO queue.
 */
static void cros_ec_ring_handler(struct cros_ec_sensors_ring_state *state)
{
	struct iio_dev *indio_dev = state->core.indio_dev;
	struct cros_ec_fifo_info *fifo_info = &state->fifo_info;
	s64    fifo_timestamp, current_timestamp;
	int    i, j, number_data, ret;
	unsigned long sensor_mask = 0;
	struct ec_response_motion_sensor_data *in;
	struct cros_ec_sensors_ring_sample *out, *last_out;


	/* Get FIFO information */

	fifo_timestamp = state->fifo_timestamp[NEW_TS];
	/* Copy elements in the main fifo */
	if (fifo_info->info.total_lost) {
		/* Need to retrieve the number of lost vectors per sensor */
		state->core.param.cmd = MOTIONSENSE_CMD_FIFO_INFO;
		if (cros_ec_motion_send_host_cmd(&state->core, 0))
			goto ring_handler_end;
		memcpy(fifo_info, &state->core.resp->fifo_info,
		       sizeof(*fifo_info));
		fifo_timestamp = cros_ec_get_time_ns();
	}

	current_timestamp = state->fifo_timestamp[LAST_TS];
	out = state->ring;
	for (i = 0; i < fifo_info->info.count; i += number_data) {
		state->core.param.cmd = MOTIONSENSE_CMD_FIFO_READ;
		state->core.param.fifo_read.max_data_vector =
			fifo_info->info.count - i;
		ret = cros_ec_motion_send_host_cmd(&state->core,
			       sizeof(state->core.resp->fifo_read) +
			       state->core.param.fifo_read.max_data_vector *
			       sizeof(struct ec_response_motion_sensor_data));
		if (ret != EC_RES_SUCCESS) {
			dev_warn(&indio_dev->dev, "Fifo error: %d\n", ret);
			break;
		}
		number_data =
			state->core.resp->fifo_read.number_data;
		if (number_data == 0) {
			dev_dbg(&indio_dev->dev, "Unexpected empty FIFO\n");
			break;
		}

		for (in = state->core.resp->fifo_read.data, j = 0;
		     j < number_data; j++, in++) {
			BUG_ON(out >= state->ring + fifo_info->info.size);
			if (cros_ec_ring_process_event(
					fifo_info, fifo_timestamp,
					&current_timestamp, in, out)) {
				sensor_mask |= (1 << in->sensor_num);
				out++;
			}
		}
	}
	last_out = out;

	if (out == state->ring)
		/* Unexpected empty FIFO. */
		goto ring_handler_end;

	/*
	 * Check if current_timestamp is ahead of the last sample.
	 * Normally, the EC appends a timestamp after the last sample, but if
	 * the AP is slow to respond to the IRQ, the EC may have added new
	 * samples. Use the FIFO info timestamp as last timestamp then.
	 */
	if ((last_out-1)->timestamp == current_timestamp)
		current_timestamp = fifo_timestamp;

	/* check if buffer is set properly */
	if (!indio_dev->active_scan_mask ||
	    (bitmap_empty(indio_dev->active_scan_mask,
			  indio_dev->masklength)))
		goto ring_handler_end;

	/*
	 * calculate proper timestamps
	 *
	 * If there is a sample with a proper timestamp
	 *                        timestamp | count
	 * older_unprocess_out --> TS1      | 1
	 *                         TS1      | 2
	 * out -->                 TS1      | 3
	 * next_out -->            TS2      |
	 * We spread time for the samples [older_unprocess_out .. out]
	 * between TS1 and TS2: [TS1+1/4, TS1+2/4, TS1+3/4, TS2].
	 *
	 * If we reach the end of the samples, we compare with the
	 * current timestamp:
	 *
	 * older_unprocess_out --> TS1      | 1
	 *                         TS1      | 2
	 * out -->                 TS1      | 3
	 * We know have [TS1+1/3, TS1+2/3, current timestamp]
	 */
	for_each_set_bit(i, &sensor_mask, BITS_PER_LONG) {
		s64 older_timestamp;
		s64 timestamp;
		struct cros_ec_sensors_ring_sample *older_unprocess_out =
			state->ring;
		struct cros_ec_sensors_ring_sample *next_out;
		int count = 1;

		if (fifo_info->info.total_lost) {
			int lost = fifo_info->lost[i];

			if (lost)
				dev_warn(&indio_dev->dev,
					"Sensor %d: lost: %d out of %d\n", i,
					lost, fifo_info->info.total_lost);
		}

		for (out = state->ring; out < last_out; out = next_out) {
			s64 time_period;

			next_out = out + 1;
			if (out->sensor_id != i)
				continue;

			/* Timestamp to start with */
			older_timestamp = out->timestamp;

			/* find next sample */
			while (next_out < last_out && next_out->sensor_id != i)
				next_out++;

			if (next_out >= last_out) {
				timestamp = current_timestamp;
			} else {
				timestamp = next_out->timestamp;
				if (timestamp == older_timestamp) {
					count++;
					continue;
				}
			}

			/* The next sample has a new timestamp,
			 * spread the unprocessed samples */
			if (next_out < last_out)
				count++;
			time_period = div_s64(timestamp - older_timestamp,
					      count);

			for (; older_unprocess_out <= out;
					older_unprocess_out++) {
				if (older_unprocess_out->sensor_id != i)
					continue;
				older_timestamp += time_period;
				older_unprocess_out->timestamp =
					older_timestamp;
			}
			count = 1;
			/* The next_out sample has a valid timestamp, skip. */
			next_out++;
			older_unprocess_out = next_out;
		}
	}

	/* push the event into the kfifo */
	for (out = state->ring; out < last_out; out++)
		iio_push_to_buffers(indio_dev, (u8 *)out);

ring_handler_end:
	state->fifo_timestamp[LAST_TS] = current_timestamp;
}

static int cros_ec_ring_event(struct notifier_block *nb,
	unsigned long queued_during_suspend, void *_notify)
{
	struct cros_ec_sensors_ring_state *state;
	struct cros_ec_device *ec;

	state = container_of(nb, struct cros_ec_sensors_ring_state, notifier);
	ec = state->core.ec;

	if (ec->event_data.event_type != EC_MKBP_EVENT_SENSOR_FIFO)
		return NOTIFY_DONE;

	if (ec->event_size != sizeof(ec->event_data.data.sensor_fifo)) {
		dev_warn(ec->dev, "Invalid fifo info size\n");
		return NOTIFY_DONE;
	}

	if (queued_during_suspend)
		return NOTIFY_OK;

	memcpy(&state->fifo_info.info, &ec->event_data.data.sensor_fifo.info,
	       ec->event_size);
	state->fifo_timestamp[NEW_TS] = cros_ec_get_time_ns();
	cros_ec_ring_handler(state);
	return NOTIFY_OK;
}

/*
 * When the EC is suspending, we must stop sending interrupt,
 * we may use the same interrupt line for waking up the device.
 * Tell the EC to stop sending non-interrupt event on the iio ring.
 */
static int __maybe_unused cros_ec_ring_prepare(struct device *dev)
{
	struct platform_device *pdev = to_platform_device(dev);
	struct iio_dev *indio_dev = platform_get_drvdata(pdev);
	struct cros_ec_sensors_ring_state *state = iio_priv(indio_dev);

	state->core.param.cmd = MOTIONSENSE_CMD_FIFO_INT_ENABLE;
	state->core.param.fifo_int_enable.enable = 0;
	return cros_ec_motion_send_host_cmd(&state->core, 0);
}

static void __maybe_unused cros_ec_ring_complete(struct device *dev)
{
	struct platform_device *pdev = to_platform_device(dev);
	struct iio_dev *indio_dev = platform_get_drvdata(pdev);
	struct cros_ec_sensors_ring_state *state = iio_priv(indio_dev);

	state->core.param.cmd = MOTIONSENSE_CMD_FIFO_INT_ENABLE;
	state->core.param.fifo_int_enable.enable = 1;
	cros_ec_motion_send_host_cmd(&state->core, 0);
}

#define CROS_EC_RING_ID(_id, _name)		\
{						\
	.type = IIO_ACCEL,			\
	.scan_index = _id,			\
	.scan_type = {				\
		.sign = 'u',			\
		.realbits = 8,			\
		.storagebits = 8,		\
	},					\
	.extend_name = _name,			\
}

#define CROS_EC_RING_AXIS(_axis)		\
{						\
	.type = IIO_ACCEL,			\
	.modified = 1,				\
	.channel2 = IIO_MOD_##_axis,		\
	.scan_index = CHANNEL_##_axis,		\
	.scan_type = {				\
		.sign = 's',			\
		.realbits = 16,			\
		.storagebits = 16,		\
	},					\
	.extend_name = "ring",			\
}

static const struct iio_chan_spec cros_ec_ring_channels[] = {
	CROS_EC_RING_ID(CHANNEL_SENSOR_ID, "id"),
	CROS_EC_RING_ID(CHANNEL_SENSOR_FLAG, "flag"),
	CROS_EC_RING_AXIS(X),
	CROS_EC_RING_AXIS(Y),
	CROS_EC_RING_AXIS(Z),
	IIO_CHAN_SOFT_TIMESTAMP(CHANNEL_TIMESTAMP)
};

static int cros_ec_ring_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct cros_ec_dev *ec_dev = dev_get_drvdata(dev->parent);
	struct cros_ec_device *ec_device;
	struct iio_dev *indio_dev;
	struct iio_buffer *buffer;
	struct cros_ec_sensors_ring_state *state;
	int ret;

	if (!ec_dev || !ec_dev->ec_dev) {
		dev_warn(&pdev->dev, "No CROS EC device found.\n");
		return -EINVAL;
	}
	ec_device = ec_dev->ec_dev;

	indio_dev = devm_iio_device_alloc(&pdev->dev, sizeof(*state));
	if (!indio_dev)
		return -ENOMEM;

	platform_set_drvdata(pdev, indio_dev);

	ret = cros_ec_sensors_core_init(pdev, indio_dev, false);
	if (ret)
		return ret;

	state = iio_priv(indio_dev);
	/* Retrieve FIFO information */
	state->core.param.cmd = MOTIONSENSE_CMD_FIFO_INFO;
	/* If it fails, just assume the FIFO is not supported.
	 * For other errors, the other sensor drivers would have noticed
	 * already.
	 */
	if (cros_ec_motion_send_host_cmd(&state->core, 0))
		return -ENODEV;

	/* Allocate the full fifo.
	 * We need to copy the whole FIFO to set timestamps properly *
	 */
	state->ring = devm_kcalloc(&pdev->dev,
			state->core.resp->fifo_info.size,
			sizeof(*state->ring), GFP_KERNEL);
	if (!state->ring)
		return -ENOMEM;

	state->fifo_timestamp[LAST_TS] = cros_ec_get_time_ns();

	indio_dev->channels = cros_ec_ring_channels;
	indio_dev->num_channels = ARRAY_SIZE(cros_ec_ring_channels);
	indio_dev->info = &ec_sensors_info;
	indio_dev->modes = INDIO_BUFFER_SOFTWARE;

	buffer = devm_iio_kfifo_allocate(indio_dev->dev.parent);
	if (!buffer)
		return -ENOMEM;

	iio_device_attach_buffer(indio_dev, buffer);

	ret = devm_iio_device_register(indio_dev->dev.parent, indio_dev);
	if (ret < 0)
		return ret;

	/* register the notifier that will act as a top half interrupt. */
	state->notifier.notifier_call = cros_ec_ring_event;
	ret = blocking_notifier_chain_register(&ec_device->event_notifier,
					       &state->notifier);
	if (ret < 0) {
		dev_warn(&indio_dev->dev, "failed to register notifier\n");
		return ret;
	}
	state->core.param.cmd = MOTIONSENSE_CMD_FIFO_INT_ENABLE;
	state->core.param.fifo_int_enable.enable = 1;
	return cros_ec_motion_send_host_cmd(&state->core, 0);
}

static int cros_ec_ring_remove(struct platform_device *pdev)
{
	struct iio_dev *indio_dev = platform_get_drvdata(pdev);
	struct cros_ec_sensors_ring_state *state = iio_priv(indio_dev);
	struct cros_ec_device *ec = state->core.ec;

	state->core.param.cmd = MOTIONSENSE_CMD_FIFO_INT_ENABLE;
	state->core.param.fifo_int_enable.enable = 0;
	cros_ec_motion_send_host_cmd(&state->core, 0);

	blocking_notifier_chain_unregister(&ec->event_notifier,
					   &state->notifier);
	return 0;
}

#ifdef CONFIG_PM_SLEEP
const struct dev_pm_ops cros_ec_ring_pm_ops = {
	.prepare = cros_ec_ring_prepare,
	.complete = cros_ec_ring_complete
};
#else
const struct dev_pm_ops cros_ec_ring_pm_ops = { };
#endif

static struct platform_driver cros_ec_ring_platform_driver = {
	.driver = {
		.name	= DRV_NAME,
		.pm	= &cros_ec_ring_pm_ops,
	},
	.probe		= cros_ec_ring_probe,
	.remove		= cros_ec_ring_remove,
};
module_platform_driver(cros_ec_ring_platform_driver);

MODULE_DESCRIPTION("ChromeOS EC sensor hub ring driver");
MODULE_ALIAS("platform:" DRV_NAME);
MODULE_LICENSE("GPL v2");
