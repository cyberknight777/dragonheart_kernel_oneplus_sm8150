/*
 * drivers/input/touchscreen/wake_gestures.c
 *
 *
 * Copyright (c) 2013 Dennis Rassmann <showp1984@gmail.com>
 * Copyright (c) 2013-19 Aaron Segaert <asegaert@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/err.h>
#include <linux/wake_gestures.h>
#include <linux/slab.h>
#include <linux/workqueue.h>
#include <linux/input.h>
#include <linux/hrtimer.h>

/* Tunables */
#define WG_DEBUG		0
#define WG_DEFAULT		0
#define DT2W_DEFAULT		0
#define S2W_DEFAULT		0
#define S2S_DEFAULT		0
#define WG_PWRKEY_DUR		60

/* 7 PRO */
#define SWEEP_Y_MAX		3120
#define SWEEP_X_MAX		1440
#define SWEEP_EDGE		130
#define SWEEP_Y_LIMIT		SWEEP_Y_MAX-SWEEP_EDGE
#define SWEEP_X_LIMIT		SWEEP_X_MAX-SWEEP_EDGE
#define SWEEP_X_B1		480
#define SWEEP_X_B2		940
#define SWEEP_X_START		720
#define SWEEP_X_FINAL		360
#define SWEEP_Y_START		1000
#define SWEEP_Y_NEXT		260
#define DT2W_FEATHER		200
#define DT2W_TIME		500

/* 7 */
#define SWEEP_Y_MAX_OP7		2340
#define SWEEP_X_MAX_OP7		1080
#define SWEEP_EDGE_OP7		90
#define SWEEP_Y_LIMIT_OP7	SWEEP_Y_MAX_OP7-SWEEP_EDGE_OP7
#define SWEEP_X_LIMIT_OP7	SWEEP_X_MAX_OP7-SWEEP_EDGE_OP7
#define SWEEP_X_B1_OP7		350
#define SWEEP_X_B2_OP7		600
#define SWEEP_Y_START_OP7	800
#define SWEEP_X_START_OP7	530
#define SWEEP_X_FINAL_OP7	260
#define SWEEP_Y_NEXT_OP7	150

/* Wake Gestures */
#define SWEEP_TIMEOUT		320
#define TRIGGER_TIMEOUT		500
#define WAKE_GESTURE		0x0b

#define WAKE_GESTURES_ENABLED	1

#define LOGTAG			"WG"
#define OP7PRO			1
#define OP7			2
#define OP7T			3

#if (WAKE_GESTURES_ENABLED)
int gestures_switch = WG_DEFAULT;
static struct input_dev *gesture_dev;
#endif

/* Resources */
int s2w_switch = S2W_DEFAULT;
int dt2w_switch = DT2W_DEFAULT;
bool wg_switch = 0;
bool wg_switch_temp;
bool wg_changed = false;
static int s2s_switch = S2S_DEFAULT;
static int touch_x = 0, touch_y = 0;
static bool touch_x_called = false, touch_y_called = false;
static bool exec_countx = true, exec_county = true, exec_count = true;
static bool barrierx[2] = {false, false}, barriery[2] = {false, false};
static int firstx = 0, firsty = 0;
static unsigned long firstx_time = 0, firsty_time = 0;
static unsigned long pwrtrigger_time[2] = {0, 0};
static unsigned long long tap_time_pre = 0;
static int touch_nr = 0, x_pre = 0, y_pre = 0;
static bool touch_cnt = true;
int wake_vibrate = true;
static int sleep_vibrate = false;

static unsigned int sweep_y_limit = SWEEP_Y_LIMIT;
static unsigned int sweep_x_limit = SWEEP_X_LIMIT;
static unsigned int sweep_x_b1 = SWEEP_X_B1;
static unsigned int sweep_x_b2 = SWEEP_X_B2;
static unsigned int sweep_y_start = SWEEP_Y_START;
static unsigned int sweep_x_start = SWEEP_X_START;
static unsigned int sweep_x_final = SWEEP_X_FINAL;
static unsigned int sweep_y_next = SWEEP_Y_NEXT;
static unsigned int sweep_x_max = SWEEP_X_MAX;
static unsigned int sweep_edge = SWEEP_EDGE;

static struct input_dev * wake_dev;
static DEFINE_MUTEX(pwrkeyworklock);
static struct workqueue_struct *s2w_input_wq;
static struct workqueue_struct *dt2w_input_wq;
static struct work_struct s2w_input_work;
static struct work_struct dt2w_input_work;

//get hardware type
static int hw_version = OP7PRO;
static int __init get_model(char *cmdline_model)
{
	if (strstr(cmdline_model, "18857")) {
		sweep_y_limit = SWEEP_Y_LIMIT_OP7;
		sweep_x_limit = SWEEP_X_LIMIT_OP7;
		sweep_x_b1 = SWEEP_X_B1_OP7;
		sweep_x_b2 = SWEEP_X_B2_OP7;
		sweep_y_start = SWEEP_Y_START_OP7;
		sweep_x_start = SWEEP_X_START_OP7;
		sweep_x_final = SWEEP_X_FINAL_OP7;
		sweep_y_next = SWEEP_Y_NEXT_OP7;
		sweep_x_max = SWEEP_X_MAX_OP7;
		sweep_edge = SWEEP_EDGE_OP7;
		hw_version = OP7;
	} else if (strstr(cmdline_model, "18865")) {
		sweep_y_limit = SWEEP_Y_LIMIT_OP7;
		sweep_x_limit = SWEEP_X_LIMIT_OP7;
		sweep_x_b1 = SWEEP_X_B1_OP7;
		sweep_x_b2 = SWEEP_X_B2_OP7;
		sweep_y_start = SWEEP_Y_START_OP7;
		sweep_x_start = SWEEP_X_START_OP7;
		sweep_x_final = SWEEP_X_FINAL_OP7;
		sweep_y_next = SWEEP_Y_NEXT_OP7;
		sweep_x_max = SWEEP_X_MAX_OP7;
		sweep_edge = SWEEP_EDGE_OP7;
		hw_version = OP7T;
	}

	return 0;
}
__setup("androidboot.project_name=", get_model);

static bool is_suspended(void)
{
	return scr_suspended();
}

/* Wake Gestures */
#if (WAKE_GESTURES_ENABLED)
static void report_gesture(int gest)
{
	pwrtrigger_time[1] = pwrtrigger_time[0];
	pwrtrigger_time[0] = ktime_to_ms(ktime_get());	

	if (pwrtrigger_time[0] - pwrtrigger_time[1] < TRIGGER_TIMEOUT)
		return;

	input_report_rel(gesture_dev, WAKE_GESTURE, gest);
	input_sync(gesture_dev);
}
#endif

/* PowerKey work func */
static void wake_presspwr(struct work_struct * wake_presspwr_work) {
	if (!mutex_trylock(&pwrkeyworklock))
		return;

	if ((wake_vibrate && is_suspended()) ||
		(sleep_vibrate && !is_suspended()))
		set_vibrate();

	input_event(wake_dev, EV_KEY, KEY_POWER, 1);
	input_event(wake_dev, EV_SYN, 0, 0);
	msleep(WG_PWRKEY_DUR);
	input_event(wake_dev, EV_KEY, KEY_POWER, 0);
	input_event(wake_dev, EV_SYN, 0, 0);
	msleep(WG_PWRKEY_DUR);
	mutex_unlock(&pwrkeyworklock);

	return;
}
static DECLARE_WORK(wake_presspwr_work, wake_presspwr);

/* PowerKey trigger */
static void wake_pwrtrigger(void) {
	pwrtrigger_time[1] = pwrtrigger_time[0];
	pwrtrigger_time[0] = ktime_to_ms(ktime_get());
	
	if (pwrtrigger_time[0] - pwrtrigger_time[1] < TRIGGER_TIMEOUT)
		return;

	schedule_work(&wake_presspwr_work);

        return;
}


/* Doubletap2wake */

static void doubletap2wake_reset(void) {
	exec_count = true;
	touch_nr = 0;
	tap_time_pre = 0;
	x_pre = 0;
	y_pre = 0;
}

static unsigned int calc_feather(int coord, int prev_coord) {
	int calc_coord = 0;
	calc_coord = coord-prev_coord;
	if (calc_coord < 0)
		calc_coord = calc_coord * (-1);
	return calc_coord;
}

/* init a new touch */
static void new_touch(int x, int y) {
	tap_time_pre = ktime_to_ms(ktime_get());
	x_pre = x;
	y_pre = y;
	touch_nr++;
}

/* Doubletap2wake main function */
static void detect_doubletap2wake(int x, int y, bool st)
{
        bool single_touch = st;
#if WG_DEBUG
        pr_info(LOGTAG"x,y(%4d,%4d) tap_time_pre:%llu\n",
                x, y, tap_time_pre);
#endif
	if (x < sweep_edge || x > sweep_x_limit)
		return;
	if (y < sweep_edge || y > sweep_y_limit)
		return;

	if ((single_touch) && (dt2w_switch) && (exec_count) && (touch_cnt)) {
		touch_cnt = false;
		if (touch_nr == 0) {
			new_touch(x, y);
		} else if (touch_nr == 1) {
			if ((calc_feather(x, x_pre) < DT2W_FEATHER) &&
			    (calc_feather(y, y_pre) < DT2W_FEATHER) &&
			    ((ktime_to_ms(ktime_get())-tap_time_pre) < DT2W_TIME))
				touch_nr++;
			else {
				doubletap2wake_reset();
				new_touch(x, y);
			}
		} else {
			doubletap2wake_reset();
			new_touch(x, y);
		}
		if ((touch_nr > 1)) {
			exec_count = false;
#if (WAKE_GESTURES_ENABLED)
			if (gestures_switch) {
				report_gesture(5);
			} else {
#endif
				wake_pwrtrigger();
#if (WAKE_GESTURES_ENABLED)
			}
#endif
			doubletap2wake_reset();
		}
	}
}


/* Sweep2wake/Sweep2sleep */
static void sweep2wake_reset(void) {

	exec_countx = true;
	barrierx[0] = false;
	barrierx[1] = false;
	firstx = 0;
	firstx_time = 0;

	exec_county = true;
	barriery[0] = false;
	barriery[1] = false;
	firsty = 0;
	firsty_time = 0;
}

/* Sweep2wake main functions*/
static void detect_sweep2wake_v(int x, int y, bool st)
{
	int prevy = 0, nexty = 0;
        bool single_touch = st;

	if (firsty == 0) {
		firsty = y;
		firsty_time = ktime_to_ms(ktime_get());
	}

#if WG_DEBUG
        pr_info(LOGTAG"s2w vert  x,y(%4d,%4d) single:%s\n",
                x, y, (single_touch) ? "true" : "false");
#endif

	//sweep up
	if (firsty > sweep_y_start && single_touch && s2w_switch & SWEEP_UP) {
		prevy = firsty;
		nexty = prevy - sweep_y_next;
		if (barriery[0] == true || (y < prevy && y > nexty)) {
			prevy = nexty;
			nexty -= sweep_y_next;
			barriery[0] = true;
			if (barriery[1] == true || (y < prevy && y > nexty)) {
				prevy = nexty;
				barriery[1] = true;
				if (y < prevy) {
					if (y < (nexty - sweep_y_next)) {
						if (exec_county && (ktime_to_ms(ktime_get()) - firsty_time < SWEEP_TIMEOUT)) {
#if (WAKE_GESTURES_ENABLED)
							if (gestures_switch) {
								report_gesture(3);
							} else {
#endif
								wake_pwrtrigger();
#if (WAKE_GESTURES_ENABLED)
							}		
#endif								
							exec_county = false;
						}
					}
				}
			}
		}
	//sweep down
	} else if (firsty <= sweep_y_start && single_touch && s2w_switch & SWEEP_DOWN) {
		prevy = firsty;
		nexty = prevy + sweep_y_next;
		if (barriery[0] == true || (y > prevy && y < nexty)) {
			prevy = nexty;
			nexty += sweep_y_next;
			barriery[0] = true;
			if (barriery[1] == true || (y > prevy && y < nexty)) {
				prevy = nexty;
				barriery[1] = true;
				if (y > prevy) {
					if (y > (nexty + sweep_y_next)) {
						if (exec_county && (ktime_to_ms(ktime_get()) - firsty_time < SWEEP_TIMEOUT)) {
#if (WAKE_GESTURES_ENABLED)
							if (gestures_switch) {
								report_gesture(4);
							} else {
#endif
								wake_pwrtrigger();
#if (WAKE_GESTURES_ENABLED)
							}								
#endif
							exec_county = false;
						}
					}
				}
			}
		}
	}
	
}

static void detect_sweep2wake_h(int x, int y, bool st, bool scr_suspended)
{
        int prevx = 0, nextx = 0;
        bool single_touch = st;

	if (!scr_suspended && y < sweep_y_limit) {
		sweep2wake_reset();
		return;
	}

	if (x < 0)
		return;

	if (firstx == 0) {
		firstx = x;
		firstx_time = ktime_to_ms(ktime_get());
	}

#if WG_DEBUG
        pr_info(LOGTAG"s2w Horz x,y(%4d,%4d) wake:%s\n",
                x, y, (scr_suspended) ? "true" : "false");
#endif

	//left->right
	if (firstx < sweep_x_start && single_touch &&
			((scr_suspended && (s2w_switch & SWEEP_RIGHT)) ||
			(!scr_suspended && (s2s_switch & SWEEP_RIGHT)))) {
		prevx = 0;
		nextx = sweep_x_b1;
		if ((barrierx[0] == true) ||
		   ((x > prevx) && (x < nextx))) {
			prevx = nextx;
			nextx = sweep_x_b2;
			barrierx[0] = true;
			if ((barrierx[1] == true) ||
			   ((x > prevx) && (x < nextx))) {
				prevx = nextx;
				barrierx[1] = true;
				if (x > prevx) {
					if (x > (sweep_x_max - sweep_x_final)) {
						if (exec_countx && (ktime_to_ms(ktime_get()) - firstx_time < SWEEP_TIMEOUT)) {
#if (WAKE_GESTURES_ENABLED)
							if (gestures_switch && scr_suspended) {
								report_gesture(1);
							} else {
#endif
								wake_pwrtrigger();
#if (WAKE_GESTURES_ENABLED)
							}
#endif							
							exec_countx = false;
						}
					}
				}
			}
		}
	//right->left
	} else if (firstx >= sweep_x_start && single_touch &&
			((scr_suspended && (s2w_switch & SWEEP_LEFT)) ||
			(!scr_suspended && (s2s_switch & SWEEP_LEFT)))) {
		prevx = sweep_x_max;
		nextx = SWEEP_X_B2;
		if ((barrierx[0] == true) ||
		   ((x < prevx) && (x > nextx))) {
			prevx = nextx;
			nextx = sweep_x_b1;
			barrierx[0] = true;
			if ((barrierx[1] == true) ||
			   ((x < prevx) && (x > nextx))) {
				prevx = nextx;
				barrierx[1] = true;
				if (x < prevx) {
					if (x < sweep_x_final) {
						if (exec_countx) {
#if (WAKE_GESTURES_ENABLED)
							if (gestures_switch && scr_suspended) {
								report_gesture(2);
							} else {
#endif
								wake_pwrtrigger();
#if (WAKE_GESTURES_ENABLED)
							}		
#endif							
							exec_countx = false;
						}
					}
				}
			}
		}
	}
}

static void s2w_input_callback(struct work_struct *unused)
{
	detect_sweep2wake_h(touch_x, touch_y, true, is_suspended());
	if (is_suspended())
		detect_sweep2wake_v(touch_x, touch_y, true);

	return;
}

static void dt2w_input_callback(struct work_struct *unused)
{

	if (is_suspended() && dt2w_switch)
		detect_doubletap2wake(touch_x, touch_y, true);
	return;
}

static void wg_input_event(struct input_handle *handle, unsigned int type,
				unsigned int code, int value)
{
	if (is_suspended() && code == ABS_MT_POSITION_X) {
		value -= 5000;
	}
	
#if WG_DEBUG
	pr_info("wg: code: %s|%u, val: %i\n",
		((code==ABS_MT_POSITION_X) ? "X" :
		(code==ABS_MT_POSITION_Y) ? "Y" :
		(code==ABS_MT_TRACKING_ID) ? "ID" :
		"undef"), code, value);
#endif

	if (code == ABS_MT_SLOT) {
		sweep2wake_reset();
		doubletap2wake_reset();
		return;
	}

	if (code == ABS_MT_TRACKING_ID && value == -1) {
		sweep2wake_reset();
		touch_cnt = true;
		queue_work_on(0, dt2w_input_wq, &dt2w_input_work);
		return;
	}

	if (code == ABS_MT_POSITION_X) {
		touch_x = value;
		touch_x_called = true;
	}

	if (code == ABS_MT_POSITION_Y) {
		touch_y = value;
		touch_y_called = true;
	}

	if (touch_x_called && touch_y_called) {
		touch_x_called = false;
		touch_y_called = false;
		queue_work_on(0, s2w_input_wq, &s2w_input_work);
	} else if (!is_suspended() && touch_x_called && !touch_y_called) {
		touch_x_called = false;
		touch_y_called = false;
		queue_work_on(0, s2w_input_wq, &s2w_input_work);
	}
}

static int input_dev_filter(struct input_dev *dev) {
	if (strstr(dev->name, "touchpanel")) {
		return 0;
	} else {
		return 1;
	}
}

static int wg_input_connect(struct input_handler *handler,
				struct input_dev *dev, const struct input_device_id *id) {
	struct input_handle *handle;
	int error;

	if (input_dev_filter(dev))
		return -ENODEV;

	handle = kzalloc(sizeof(struct input_handle), GFP_KERNEL);
	if (!handle)
		return -ENOMEM;

	handle->dev = dev;
	handle->handler = handler;
	handle->name = "wg";

	error = input_register_handle(handle);
	if (error)
		goto err2;

	error = input_open_device(handle);
	if (error)
		goto err1;

	return 0;
err1:
	input_unregister_handle(handle);
err2:
	kfree(handle);
	return error;
}

static void wg_input_disconnect(struct input_handle *handle) {
	input_close_device(handle);
	input_unregister_handle(handle);
	kfree(handle);
}

static const struct input_device_id wg_ids[] = {
	{ .driver_info = 1 },
	{ },
};

static struct input_handler wg_input_handler = {
	.event		= wg_input_event,
	.connect	= wg_input_connect,
	.disconnect	= wg_input_disconnect,
	.name		= "wg_inputreq",
	.id_table	= wg_ids,
};

static void wake_gesture_changed(void)
{
	wg_switch_temp = (s2w_switch || dt2w_switch);
	if (!is_suspended())
		wg_switch = wg_switch_temp;
	else
		wg_changed = true;
}

/*
 * SYSFS stuff below here
 */
static ssize_t sweep2wake_show(struct kobject *kobj, struct kobj_attribute *attr,
		      char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%d\n", s2w_switch);
}

static ssize_t sweep2wake_store(struct kobject *kobj, struct kobj_attribute *attr,
		       const char *buf, size_t count)
{
	int ret, val;
	
	ret = kstrtoint(buf, 0, &val);
	if (ret < 0)
		return ret;

	if (val < 0 || val > 15)
		val = 0;
		
	s2w_switch = val;

	wake_gesture_changed();

	return count;
}

static struct kobj_attribute sweep2wake_attribute =
	__ATTR(sweep2wake, 0664, sweep2wake_show, sweep2wake_store);

static ssize_t sweep2sleep_show(struct kobject *kobj, struct kobj_attribute *attr,
		      char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%d\n", s2s_switch);
}

static ssize_t sweep2sleep_store(struct kobject *kobj, struct kobj_attribute *attr,
		       const char *buf, size_t count)
{
	int ret, val;
	
	ret = kstrtoint(buf, 0, &val);
	if (ret < 0)
		return ret;

	if (val < 0 || val > 3)
		val = 0;

	s2s_switch = val;			
				
	return count;
}

static struct kobj_attribute sweep2sleep_attribute =
	__ATTR(sweep2sleep, 0664, sweep2sleep_show, sweep2sleep_store);

static ssize_t doubletap2wake_show(struct kobject *kobj, struct kobj_attribute *attr,
		      char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%d\n", dt2w_switch);
}

static ssize_t doubletap2wake_store(struct kobject *kobj, struct kobj_attribute *attr,
		       const char *buf, size_t count)
{
	int ret, val;
	
	ret = kstrtoint(buf, 0, &val);
	if (ret < 0)
		return ret;

	if (val < 0 || val > 1)
		val = 0;

	dt2w_switch = val;	

	wake_gesture_changed();

	return count;
}

static struct kobj_attribute doubletap2wake_attribute =
	__ATTR(doubletap2wake, 0664, doubletap2wake_show, doubletap2wake_store);
	
static ssize_t wake_gestures_show(struct kobject *kobj, struct kobj_attribute *attr,
		      char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%d\n", gestures_switch);
}

static ssize_t wake_gestures_store(struct kobject *kobj, struct kobj_attribute *attr,
		       const char *buf, size_t count)
{
	int ret, val;

	ret = kstrtoint(buf, 0, &val);
	if (ret < 0)
		return ret;

	if (val < 0 || val > 1)
		val = 0;

	gestures_switch = val;
	
	return count;
}

static struct kobj_attribute wake_gestures_attribute =
	__ATTR(wake_gestures, 0664, wake_gestures_show, wake_gestures_store);

static ssize_t wake_vibrate_show(struct kobject *kobj, struct kobj_attribute *attr,
		      char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%d\n", wake_vibrate);
}

static ssize_t wake_vibrate_store(struct kobject *kobj, struct kobj_attribute *attr,
		       const char *buf, size_t count)
{
	int ret, val;

	ret = kstrtoint(buf, 0, &val);
	if (ret < 0)
		return ret;

	if (val < 0 || val > 1)
		val = 1;

	wake_vibrate = val;

	return count;
}

static struct kobj_attribute wake_vibrate_attribute =
	__ATTR(wake_vibrate, 0664, wake_vibrate_show, wake_vibrate_store);

static ssize_t sleep_vibrate_show(struct kobject *kobj, struct kobj_attribute *attr,
		      char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%d\n", sleep_vibrate);
}

static ssize_t sleep_vibrate_store(struct kobject *kobj, struct kobj_attribute *attr,
		       const char *buf, size_t count)
{
	int ret, val;

	ret = kstrtoint(buf, 0, &val);
	if (ret < 0)
		return ret;

	if (val < 0 || val > 1)
		val = 1;

	sleep_vibrate = val;

	return count;
}

static struct kobj_attribute sleep_vibrate_attribute =
	__ATTR(sleep_vibrate, 0664, sleep_vibrate_show, sleep_vibrate_store);

static struct attribute *attrs[] = {
	&sweep2sleep_attribute.attr,
	&sweep2wake_attribute.attr,
	&doubletap2wake_attribute.attr,
	&wake_gestures_attribute.attr,
	&wake_vibrate_attribute.attr,
	&sleep_vibrate_attribute.attr,
	NULL,
};

static struct attribute_group attr_group = {
	.attrs = attrs,
};

static struct attribute *op7_attrs[] = {
	&sweep2sleep_attribute.attr,
	&sweep2wake_attribute.attr,
	&doubletap2wake_attribute.attr,
	&wake_gestures_attribute.attr,
	NULL,
};

static struct attribute_group op7_attr_group = {
	.attrs = op7_attrs,
};

static struct kobject *android_touch_kobj;

/*
 * INIT / EXIT stuff below here
 */

static int __init wake_gestures_init(void)
{
	int rc = 0;

	pr_info("start wake gestures\n");

	wake_dev = input_allocate_device();
	if (!wake_dev) {
		pr_err("Failed to allocate wake_dev\n");
		goto err_alloc_dev;
	}

	input_set_capability(wake_dev, EV_KEY, KEY_POWER);
	wake_dev->name = "wg_pwrkey";
	wake_dev->phys = "wg_pwrkey/input0";

	rc = input_register_device(wake_dev);
	if (rc) {
		pr_err("%s: input_register_device err=%d\n", __func__, rc);
		goto err_input_dev;
	}

	rc = input_register_handler(&wg_input_handler);
	if (rc)
		pr_err("%s: Failed to register wg_input_handler\n", __func__);

	s2w_input_wq = create_workqueue("s2wiwq");
	if (!s2w_input_wq) {
		pr_err("%s: Failed to create s2wiwq workqueue\n", __func__);
		return -EFAULT;
	}
	INIT_WORK(&s2w_input_work, s2w_input_callback);
		
	dt2w_input_wq = create_workqueue("dt2wiwq");
	if (!dt2w_input_wq) {
		pr_err("%s: Failed to create dt2wiwq workqueue\n", __func__);
		return -EFAULT;
	}
	INIT_WORK(&dt2w_input_work, dt2w_input_callback);
		
#if (WAKE_GESTURES_ENABLED)
	gesture_dev = input_allocate_device();
	if (!gesture_dev) {
		pr_err("Failed to allocate gesture_dev\n");
		goto err_alloc_dev;
	}
	
	gesture_dev->name = "wake_gesture";
	gesture_dev->phys = "wake_gesture/input0";
	input_set_capability(gesture_dev, EV_REL, WAKE_GESTURE);

	rc = input_register_device(gesture_dev);
	if (rc) {
		pr_err("%s: input_register_device err=%d\n", __func__, rc);
		goto err_gesture_dev;
	}
#endif

	android_touch_kobj = kobject_create_and_add("android_touch", NULL);
	if (!android_touch_kobj) {
		pr_info("fail!!!!\n");
		return -ENOMEM;
	}
	if (hw_version == OP7) {
		wake_vibrate = 0;
		rc = sysfs_create_group(android_touch_kobj, &op7_attr_group);
	} else {
		rc = sysfs_create_group(android_touch_kobj, &attr_group);
	}
	if (rc)
		pr_warn("%s: sysfs_create_group failed\n", __func__);

	wg_switch_temp = (s2w_switch || dt2w_switch);

	return 0;

err_gesture_dev:
	input_free_device(gesture_dev);
err_input_dev:
	input_free_device(wake_dev);
err_alloc_dev:

	wg_switch_temp = (s2w_switch || dt2w_switch);

	return 0;
}

static void __exit wake_gestures_exit(void)
{
	kobject_del(android_touch_kobj);
	input_unregister_handler(&wg_input_handler);
	destroy_workqueue(s2w_input_wq);
	destroy_workqueue(dt2w_input_wq);
	input_unregister_device(wake_dev);
	input_free_device(wake_dev);
#if (WAKE_GESTURES_ENABLED)	
	input_unregister_device(gesture_dev);
	input_free_device(gesture_dev);
#endif

	return;
}

module_init(wake_gestures_init);
module_exit(wake_gestures_exit);


