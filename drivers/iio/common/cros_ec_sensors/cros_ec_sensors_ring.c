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
#include <linux/iio/common/cros_ec_sensors_core.h>
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

#define DRV_NAME "cros-ec-ring"

/*
 * The ring is a FIFO that return sensor information from
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

struct __ec_todo_packed cros_ec_fifo_info {
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
	int    fifo_size;

	/* Used for timestamp spreading calculations when a batch shows up */
	s64 last_batch_timestamp[CROS_EC_SENSOR_MAX];
	s64 last_batch_len[CROS_EC_SENSOR_MAX];
};

static const struct iio_info ec_sensors_info = {
	.driver_module = THIS_MODULE,
};

static int cros_ec_ring_fifo_toggle(struct cros_ec_sensors_ring_state *state,
				    bool on)
{
	int i, ret;

	mutex_lock(&state->core.cmd_lock);
	for (i = 0; i < CROS_EC_SENSOR_MAX; i++)
		state->last_batch_len[i] = 0;
	state->core.param.cmd = MOTIONSENSE_CMD_FIFO_INT_ENABLE;
	state->core.param.fifo_int_enable.enable = on;
	ret = cros_ec_motion_send_host_cmd(&state->core, 0);
	mutex_unlock(&state->core.cmd_lock);
	return ret;
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
static bool cros_ec_ring_process_event(
				struct cros_ec_sensors_ring_state *state,
				const struct cros_ec_fifo_info *fifo_info,
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
		state->last_batch_len[out->sensor_id] = 0;
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
	struct cros_ec_sensors_ring_sample *batch_start, *next_batch_start;


	mutex_lock(&state->core.cmd_lock);
	/* Get FIFO information */
	fifo_timestamp = state->fifo_timestamp[NEW_TS];
	/* Copy elements in the main fifo */
	if (fifo_info->info.total_lost) {
		/* Need to retrieve the number of lost vectors per sensor */
		state->core.param.cmd = MOTIONSENSE_CMD_FIFO_INFO;
		if (cros_ec_motion_send_host_cmd(&state->core, 0)) {
			mutex_unlock(&state->core.cmd_lock);
			return;
		}
		memcpy(fifo_info, &state->core.resp->fifo_info,
		       sizeof(*fifo_info));
		fifo_timestamp = cros_ec_get_time_ns();
	}
	if (fifo_info->info.count > state->fifo_size ||
	    fifo_info->info.size != state->fifo_size) {
		dev_warn(&indio_dev->dev,
			 "Mismatch EC data: count %d, size %d - expected %d",
			 fifo_info->info.count, fifo_info->info.size,
			 state->fifo_size);
		mutex_unlock(&state->core.cmd_lock);
		return;
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
		} else if (number_data > fifo_info->info.count - i) {
			dev_warn(&indio_dev->dev,
				 "Invalid EC data: too many entry received: %d, expected %d",
				 number_data, fifo_info->info.count - i);
			break;
		} else if (out + number_data >
			   state->ring + fifo_info->info.count) {
			dev_warn(&indio_dev->dev,
				 "Too many samples: %d (%zd data) to %d entries for expected %d entries",
				 i, out - state->ring, i + number_data,
				 fifo_info->info.count);
			break;
		}
		for (in = state->core.resp->fifo_read.data, j = 0;
		     j < number_data; j++, in++) {
			if (cros_ec_ring_process_event(
					state, fifo_info, fifo_timestamp,
					&current_timestamp, in, out)) {
				sensor_mask |= (1 << in->sensor_num);
				out++;
			}
		}
	}
	mutex_unlock(&state->core.cmd_lock);
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

	/* Check if buffer is set properly. */
	if (!indio_dev->active_scan_mask ||
	    (bitmap_empty(indio_dev->active_scan_mask,
			  indio_dev->masklength)))
		goto ring_handler_end;

	/* Warn on lost samples. */
	for_each_set_bit(i, &sensor_mask, BITS_PER_LONG) {
		if (fifo_info->info.total_lost) {
			int lost = fifo_info->lost[i];

			if (lost) {
				dev_warn(&indio_dev->dev,
					"Sensor %d: lost: %d out of %d\n", i,
					lost, fifo_info->info.total_lost);
				state->last_batch_len[i] = 0;
			}
		}
	}

	/*
	 * Calculate proper timestamps.
	 *
	 * Sometimes the EC receives only one interrupt (hence timestamp) for
	 * a batch of samples. Only the first sample will have the correct
	 * timestamp. So we must interpolate the other samples.
	 * We use the previous batch timestamp and our current batch timestamp
	 * as a way to calculate period, then spread the samples evenly.
	 *
	 * s0 int, 0ms
	 * s1 int, 10ms
	 * s2 int, 20ms
	 * 30ms point goes by, no interrupt, previous one is still asserted
	 * downloading s2 and s3
	 * s3 sample, 20ms (incorrect timestamp)
	 * s4 int, 40ms
	 *
	 * The batches are [(s0), (s1), (s2, s3), (s4)]. Since the 3rd batch
	 * has 2 samples in them, we adjust the timestamp of s3.
	 * s2 - s1 = 10ms, so s3 must be s2 + 10ms => 20ms. If s1 would have
	 * been part of a bigger batch things would have gotten a little
	 * more complicated.
	 *
	 * Note: we also assume another sensor sample doesn't break up a batch
	 * in 2 or more partitions. Example, there can't ever be a sync sensor
	 * in between S2 and S3. This simplifies the following code.
	 */
	for (batch_start = state->ring; batch_start < last_out;
	     batch_start = next_batch_start) {
		/* for each batch (where all samples have the same timestamp) */
		int batch_len, sample_idx = 1;
		const int id = batch_start->sensor_id;
		struct cros_ec_sensors_ring_sample *batch_end = batch_start;
		struct cros_ec_sensors_ring_sample *s;
		const s64 batch_timestamp = batch_start->timestamp;
		s64 sample_period;

		/*
		 * Push first sample in the batch to the kfifo,
		 * it's guaranteed to be correct, rest come later.
		 */
		iio_push_to_buffers(indio_dev, (u8 *)batch_start);

		/* Find all samples have the same timestamp. */
		for (s = batch_start + 1; s < last_out; s++) {
			if (s->timestamp != batch_timestamp)
				break; /* we discovered the next batch */
			if (s->sensor_id != id)
				break; /* another sensor, surely next batch */
			batch_end = s;
		}
		batch_len = batch_end - batch_start + 1;

		if (batch_len == 1)
			goto done_with_this_batch;

		dev_dbg(&indio_dev->dev,
			"Adjusting samples, sensor %d last_batch @%lld (%lld samples) batch_timestamp=%lld => period=%lld\n",
			id, state->last_batch_timestamp[id],
			state->last_batch_len[id], batch_timestamp,
			sample_period);

		/* Can we calculate period? */
		if (state->last_batch_len[id] == 0) {
			dev_warn(&indio_dev->dev, "Sensor %d: lost %d samples when spreading\n",
				 id, batch_len - 1);
			goto done_with_this_batch;
			/*
			 * Note: we're dropping the rest of the samples in
			 * this batch since we have no idea where they're
			 * supposed to go without a period calculation.
			 */
		}

		sample_period = div_s64(batch_timestamp -
			state->last_batch_timestamp[id],
			state->last_batch_len[id]);

		/* Adjust timestamps of the samples then push them to kfifo. */
		for (s = batch_start + 1; s <= batch_end; s++) {
			s->timestamp = batch_timestamp +
				sample_period * sample_idx;
			sample_idx++;

			iio_push_to_buffers(indio_dev, (u8 *)s);
		}

done_with_this_batch:
		state->last_batch_timestamp[id] = batch_timestamp;
		state->last_batch_len[id] = batch_len;
		next_batch_start = batch_end + 1;
	}

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

	state->fifo_info.info = ec->event_data.data.sensor_fifo.info;
	state->fifo_timestamp[NEW_TS] = ec->last_event_time;
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

	return cros_ec_ring_fifo_toggle(iio_priv(indio_dev), false);
}

static void __maybe_unused cros_ec_ring_complete(struct device *dev)
{
	struct platform_device *pdev = to_platform_device(dev);
	struct iio_dev *indio_dev = platform_get_drvdata(pdev);

	cros_ec_ring_fifo_toggle(iio_priv(indio_dev), true);
}

/*
 * Once we are ready to receive data, enable the interrupt
 * that allow EC to indicate events are available.
 */
static int cros_ec_ring_postenable(struct iio_dev *indio_dev)
{
	return cros_ec_ring_fifo_toggle(iio_priv(indio_dev), true);
}

static int cros_ec_ring_predisable(struct iio_dev *indio_dev)
{
	return cros_ec_ring_fifo_toggle(iio_priv(indio_dev), false);
}

static const struct iio_buffer_setup_ops cros_ec_ring_buffer_ops = {
	.postenable = cros_ec_ring_postenable,
	.predisable = cros_ec_ring_predisable,
};

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
	/*
	 * Disable the ring in case it was left enabled previously.
	 */
	ret = cros_ec_ring_fifo_toggle(state, false);
	if (ret)
		return ret;

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
	state->fifo_size = state->core.resp->fifo_info.size;
	state->ring = devm_kcalloc(&pdev->dev, state->fifo_size,
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
	indio_dev->setup_ops = &cros_ec_ring_buffer_ops;

	ret = devm_iio_device_register(indio_dev->dev.parent, indio_dev);
	if (ret < 0)
		return ret;

	/* register the notifier that will act as a top half interrupt. */
	state->notifier.notifier_call = cros_ec_ring_event;
	ret = blocking_notifier_chain_register(&ec_device->event_notifier,
					       &state->notifier);
	if (ret < 0) {
		dev_warn(&indio_dev->dev, "failed to register notifier\n");
	}
	return ret;
}

static int cros_ec_ring_remove(struct platform_device *pdev)
{
	struct iio_dev *indio_dev = platform_get_drvdata(pdev);
	struct cros_ec_sensors_ring_state *state = iio_priv(indio_dev);
	struct cros_ec_device *ec = state->core.ec;

	/*
	 * Disable the ring, prevent EC interrupt to the AP for nothing.
	 */
	cros_ec_ring_fifo_toggle(state, false);
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
