/*
 * Copyright 2018 Advanced Micro Devices, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * Authors: AMD
 *
 */

#include <linux/debugfs.h>

#include "dc.h"
#include "dc_link.h"

#include "amdgpu.h"
#include "amdgpu_dm.h"
#include "amdgpu_dm_debugfs.h"

static ssize_t dp_link_rate_debugfs_read(struct file *f, char __user *buf,
				 size_t size, loff_t *pos)
{
	/* TODO: create method to read link rate */
	return 1;
}

static ssize_t dp_link_rate_debugfs_write(struct file *f, const char __user *buf,
				 size_t size, loff_t *pos)
{
	/* TODO: create method to write link rate */
	return 1;
}

static ssize_t dp_lane_count_debugfs_read(struct file *f, char __user *buf,
				 size_t size, loff_t *pos)
{
	/* TODO: create method to read lane count */
	return 1;
}

static ssize_t dp_lane_count_debugfs_write(struct file *f, const char __user *buf,
				 size_t size, loff_t *pos)
{
	/* TODO: create method to write lane count */
	return 1;
}

static ssize_t dp_voltage_swing_debugfs_read(struct file *f, char __user *buf,
				 size_t size, loff_t *pos)
{
	/* TODO: create method to read voltage swing */
	return 1;
}

static ssize_t dp_voltage_swing_debugfs_write(struct file *f, const char __user *buf,
				 size_t size, loff_t *pos)
{
	/* TODO: create method to write voltage swing */
	return 1;
}

static ssize_t dp_pre_emphasis_debugfs_read(struct file *f, char __user *buf,
				 size_t size, loff_t *pos)
{
	/* TODO: create method to read pre-emphasis */
	return 1;
}

static ssize_t dp_pre_emphasis_debugfs_write(struct file *f, const char __user *buf,
				 size_t size, loff_t *pos)
{
	/* TODO: create method to write pre-emphasis */
	return 1;
}

/* function description
 *
 * set PHY layer or Link layer test pattern
 * PHY test pattern is used for PHY SI check.
 * Link layer test will not affect PHY SI.
 *
 * Reset Test Pattern:
 * 0 = DP_TEST_PATTERN_VIDEO_MODE
 *
 * PHY test pattern supported:
 * 1 = DP_TEST_PATTERN_D102
 * 2 = DP_TEST_PATTERN_SYMBOL_ERROR
 * 3 = DP_TEST_PATTERN_PRBS7
 * 4 = DP_TEST_PATTERN_80BIT_CUSTOM
 * 5 = DP_TEST_PATTERN_CP2520_1
 * 6 = DP_TEST_PATTERN_CP2520_2 = DP_TEST_PATTERN_HBR2_COMPLIANCE_EYE
 * 7 = DP_TEST_PATTERN_CP2520_3
 *
 * DP PHY Link Training Patterns
 * 8 = DP_TEST_PATTERN_TRAINING_PATTERN1
 * 9 = DP_TEST_PATTERN_TRAINING_PATTERN2
 * a = DP_TEST_PATTERN_TRAINING_PATTERN3
 * b = DP_TEST_PATTERN_TRAINING_PATTERN4
 *
 * DP Link Layer Test pattern
 * c = DP_TEST_PATTERN_COLOR_SQUARES
 * d = DP_TEST_PATTERN_COLOR_SQUARES_CEA
 * e = DP_TEST_PATTERN_VERTICAL_BARS
 * f = DP_TEST_PATTERN_HORIZONTAL_BARS
 * 10= DP_TEST_PATTERN_COLOR_RAMP
 *
 * debugfs phy_test_pattern is located at /syskernel/debug/dri/0/DP-x
 *
 * --- set test pattern
 * echo <test pattern #> > test_pattern
 *
 * If test pattern # is not supported, NO HW programming will be done.
 * for DP_TEST_PATTERN_80BIT_CUSTOM, it needs extra 10 bytes of data
 * for the user pattern. input 10 bytes data are separated by space
 *
 * echo 0x4 0x11 0x22 0x33 0x44 0x55 0x66 0x77 0x88 0x99 0xaa > test_pattern
 *
 * --- reset test pattern
 * echo 0 > test_pattern
 *
 * --- HPD detection is disabled when set PHY test pattern
 *
 * when PHY test pattern (pattern # within [1,7]) is set, HPD pin of HW ASIC
 * is disable. User could unplug DP display from DP connected and plug scope to
 * check test pattern PHY SI.
 * If there is need unplug scope and plug DP display back, do steps below:
 * echo 0 > phy_test_pattern
 * unplug scope
 * plug DP display.
 *
 * "echo 0 > phy_test_pattern" will re-enable HPD pin again so that video sw
 * driver could detect "unplug scope" and "plug DP display"
 */
static ssize_t dp_phy_test_pattern_debugfs_write(struct file *f, const char __user *buf,
				 size_t size, loff_t *pos)
{
	struct amdgpu_dm_connector *connector = file_inode(f)->i_private;
	struct dc_link *link = connector->dc_link;
	char *wr_buf = NULL;
	char *wr_buf_ptr = NULL;
	uint32_t wr_buf_size = 100;
	int r;
	int bytes_from_user;
	char *sub_str;
	uint8_t param_index = 0;
	long param[11];
	const char delimiter[3] = {' ', '\n', '\0'};
	enum dp_test_pattern test_pattern = DP_TEST_PATTERN_UNSUPPORTED;
	bool disable_hpd = false;
	bool valid_test_pattern = false;
	uint8_t custom_pattern[10] = {0};
	struct dc_link_settings prefer_link_settings = {LANE_COUNT_UNKNOWN,
			LINK_RATE_UNKNOWN, LINK_SPREAD_DISABLED};
	struct dc_link_settings cur_link_settings = {LANE_COUNT_UNKNOWN,
			LINK_RATE_UNKNOWN, LINK_SPREAD_DISABLED};
	struct link_training_settings link_training_settings;
	int i;

	if (size == 0)
		return 0;

	wr_buf = kcalloc(wr_buf_size, sizeof(char), GFP_KERNEL);
	if (!wr_buf)
		return 0;
	wr_buf_ptr = wr_buf;

	r = copy_from_user(wr_buf_ptr, buf, wr_buf_size);

	/* r is bytes not be copied */
	if (r >= wr_buf_size) {
		kfree(wr_buf);
		DRM_DEBUG_DRIVER("user data not be read\n");
		return 0;
	}

	bytes_from_user = wr_buf_size - r;

	while (isspace(*wr_buf_ptr))
		wr_buf_ptr++;

	while ((*wr_buf_ptr != '\0') && (param_index < 1)) {
		sub_str = strsep(&wr_buf_ptr, delimiter);
		r = kstrtol(sub_str, 16, &param[param_index]);

		if (r)
			DRM_DEBUG_DRIVER("string to int convert error code: %d\n", r);

		param_index++;
		while (isspace(*wr_buf_ptr))
			wr_buf_ptr++;

		/* DP_TEST_PATTERN_80BIT_CUSTOM need extra 80 bits
		 * whci are 10 bytes separte by space
		 */
		if (param[0] != 0x4)
			break;
	}

	test_pattern = param[0];

	switch (test_pattern) {
	case DP_TEST_PATTERN_VIDEO_MODE:
	case DP_TEST_PATTERN_COLOR_SQUARES:
	case DP_TEST_PATTERN_COLOR_SQUARES_CEA:
	case DP_TEST_PATTERN_VERTICAL_BARS:
	case DP_TEST_PATTERN_HORIZONTAL_BARS:
	case DP_TEST_PATTERN_COLOR_RAMP:
		valid_test_pattern = true;
		break;

	case DP_TEST_PATTERN_D102:
	case DP_TEST_PATTERN_SYMBOL_ERROR:
	case DP_TEST_PATTERN_PRBS7:
	case DP_TEST_PATTERN_80BIT_CUSTOM:
	case DP_TEST_PATTERN_HBR2_COMPLIANCE_EYE:
	case DP_TEST_PATTERN_TRAINING_PATTERN4:
		disable_hpd = true;
		valid_test_pattern = true;
		break;

	default:
		valid_test_pattern = false;
		test_pattern = DP_TEST_PATTERN_UNSUPPORTED;
		break;
	}

	if (!valid_test_pattern) {
		kfree(wr_buf);
		DRM_DEBUG_DRIVER("Invalid Test Pattern Parameters\n");
		return bytes_from_user;
	}

	if (test_pattern == DP_TEST_PATTERN_80BIT_CUSTOM) {
		for (i = 0; i < 10; i++)
			custom_pattern[i] = (uint8_t) param[i + 1];
	}

	/* Usage: set DP physical test pattern using debugfs with normal DP
	 * panel. Then plug out DP panel and connect a scope to measure
	 * For normal video mode and test pattern generated from CRCT,
	 * they are visibile to user. So do not disable HPD.
	 * Video Mode is also set to clear the test pattern, so enable HPD
	 * because it might have been disabled after a test pattern was set.
	 * AUX depends on HPD * sequence dependent, do not move!
	 */
	if (!disable_hpd)
		dc_link_enable_hpd(link);

	prefer_link_settings.lane_count = link->verified_link_cap.lane_count;
	prefer_link_settings.link_rate = link->verified_link_cap.link_rate;
	prefer_link_settings.link_spread = link->verified_link_cap.link_spread;

	cur_link_settings.lane_count = link->cur_link_settings.lane_count;
	cur_link_settings.link_rate = link->cur_link_settings.link_rate;
	cur_link_settings.link_spread = link->cur_link_settings.link_spread;

	link_training_settings.link_settings = cur_link_settings;


	if (test_pattern != DP_TEST_PATTERN_VIDEO_MODE) {
		if (prefer_link_settings.lane_count != LANE_COUNT_UNKNOWN &&
			prefer_link_settings.link_rate !=  LINK_RATE_UNKNOWN &&
			(prefer_link_settings.lane_count != cur_link_settings.lane_count ||
			prefer_link_settings.link_rate != cur_link_settings.link_rate))
			link_training_settings.link_settings = prefer_link_settings;
	}

	for (i = 0; i < (unsigned int)(link_training_settings.link_settings.lane_count); i++)
		link_training_settings.lane_settings[i] = link->cur_lane_setting;

	dc_link_set_test_pattern(
		link,
		test_pattern,
		&link_training_settings,
		custom_pattern,
		10);

	/* Usage: Set DP physical test pattern using AMDDP with normal DP panel
	 * Then plug out DP panel and connect a scope to measure DP PHY signal.
	 * Need disable interrupt to avoid SW driver disable DP output. This is
	 * done after the test pattern is set.
	 */
	if (valid_test_pattern && disable_hpd)
		dc_link_disable_hpd(link);

	kfree(wr_buf);

	return bytes_from_user;
}

static const struct file_operations dp_link_rate_fops = {
	.owner = THIS_MODULE,
	.read = dp_link_rate_debugfs_read,
	.write = dp_link_rate_debugfs_write,
	.llseek = default_llseek
};

static const struct file_operations dp_lane_count_fops = {
	.owner = THIS_MODULE,
	.read = dp_lane_count_debugfs_read,
	.write = dp_lane_count_debugfs_write,
	.llseek = default_llseek
};

static const struct file_operations dp_voltage_swing_fops = {
	.owner = THIS_MODULE,
	.read = dp_voltage_swing_debugfs_read,
	.write = dp_voltage_swing_debugfs_write,
	.llseek = default_llseek
};

static const struct file_operations dp_pre_emphasis_fops = {
	.owner = THIS_MODULE,
	.read = dp_pre_emphasis_debugfs_read,
	.write = dp_pre_emphasis_debugfs_write,
	.llseek = default_llseek
};

static const struct file_operations dp_phy_test_pattern_fops = {
	.owner = THIS_MODULE,
	.write = dp_phy_test_pattern_debugfs_write,
	.llseek = default_llseek
};

static const struct {
	char *name;
	const struct file_operations *fops;
} dp_debugfs_entries[] = {
		{"link_rate", &dp_link_rate_fops},
		{"lane_count", &dp_lane_count_fops},
		{"voltage_swing", &dp_voltage_swing_fops},
		{"pre_emphasis", &dp_pre_emphasis_fops},
		{"test_pattern", &dp_phy_test_pattern_fops}
};

int connector_debugfs_init(struct amdgpu_dm_connector *connector)
{
	int i;
	struct dentry *ent, *dir = connector->base.debugfs_entry;

	if (connector->base.connector_type == DRM_MODE_CONNECTOR_DisplayPort) {
		for (i = 0; i < ARRAY_SIZE(dp_debugfs_entries); i++) {
			ent = debugfs_create_file(dp_debugfs_entries[i].name,
						  0644,
						  dir,
						  connector,
						  dp_debugfs_entries[i].fops);
			if (IS_ERR(ent))
				return PTR_ERR(ent);
		}
	}

	return 0;
}

