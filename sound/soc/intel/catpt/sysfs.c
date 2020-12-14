// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright(c) 2020 Intel Corporation. All rights reserved.
//
// Author: Cezary Rojewski <cezary.rojewski@intel.com>
//

#include <linux/pm_runtime.h>
#include "core.h"

static ssize_t fw_version_show(struct device *dev,
			       struct device_attribute *attr, char *buf)
{
	struct catpt_dev *cdev = dev_get_drvdata(dev);
	struct catpt_fw_version version;
	int ret;

	pm_runtime_get_sync(cdev->dev);

	ret = catpt_ipc_get_fw_version(cdev, &version);

	pm_runtime_mark_last_busy(cdev->dev);
	pm_runtime_put_autosuspend(cdev->dev);

	if (ret)
		return CATPT_IPC_ERROR(ret);

	return sprintf(buf, "%d.%d.%d.%d\n", version.type, version.major,
		       version.minor, version.build);
}
static DEVICE_ATTR_RO(fw_version);

static ssize_t fw_info_show(struct device *dev,
			    struct device_attribute *attr, char *buf)
{
	struct catpt_dev *cdev = dev_get_drvdata(dev);

	return sprintf(buf, "%s\n", cdev->ipc.config.fw_info);
}
static DEVICE_ATTR_RO(fw_info);

int catpt_sysfs_create(struct catpt_dev *cdev)
{
	int ret;

	ret = sysfs_create_file(&cdev->dev->kobj, &dev_attr_fw_version.attr);
	if (ret)
		return ret;

	ret = sysfs_create_file(&cdev->dev->kobj, &dev_attr_fw_info.attr);
	if (ret) {
		sysfs_remove_file(&cdev->dev->kobj, &dev_attr_fw_version.attr);
		return ret;
	}

	return 0;
}

void catpt_sysfs_remove(struct catpt_dev *cdev)
{
	sysfs_remove_file(&cdev->dev->kobj, &dev_attr_fw_info.attr);
	sysfs_remove_file(&cdev->dev->kobj, &dev_attr_fw_version.attr);
}
