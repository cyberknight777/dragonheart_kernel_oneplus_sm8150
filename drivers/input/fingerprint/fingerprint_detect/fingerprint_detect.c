
#include <linux/delay.h>
#include <linux/gpio.h>
#include <linux/kernel.h>
#include <linux/platform_device.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_gpio.h>

#include "fingerprint_detect.h"
int fp_version;

static inline ssize_t sensor_version_get(struct device *device,
			     struct device_attribute *attribute,
			     char *buffer)
{
	struct fingerprint_detect_data *fp_detect = dev_get_drvdata(device);
	return scnprintf(buffer, PAGE_SIZE, "%i\n", fp_detect->sensor_version);
}

static DEVICE_ATTR(sensor_version, S_IRUSR, sensor_version_get, NULL);

static struct attribute *attributes[] = {
	&dev_attr_sensor_version.attr,
	NULL
};

static const struct attribute_group attribute_group = {
	.attrs = attributes,
};

static inline int fp_pinctrl_init(struct fingerprint_detect_data *fp_dev)
{
	int ret = 0;
	struct device *dev = fp_dev->dev;

	fp_dev->fp_pinctrl = devm_pinctrl_get(dev);
	if (IS_ERR_OR_NULL(fp_dev->fp_pinctrl)) {
		dev_err(dev, "Target does not use pinctrl\n");
		ret = PTR_ERR(fp_dev->fp_pinctrl);
		goto err;
	}

	fp_dev->id_state_init =
		pinctrl_lookup_state(fp_dev->fp_pinctrl, "fp_id_init");
	if (IS_ERR_OR_NULL(fp_dev->id_state_init)) {
		dev_err(dev, "Cannot get id active pinstate\n");
		ret = PTR_ERR(fp_dev->id_state_init);
		goto err;
	}

	ret = pinctrl_select_state(fp_dev->fp_pinctrl, fp_dev->id_state_init);
	if (ret) {
		dev_err(dev, "can not set %s pins\n", "fp_id_init");
		goto err;
	}

	return ret;

err:
	fp_dev->fp_pinctrl = NULL;
	fp_dev->id_state_init = NULL;
	return ret;
}

static inline int fingerprint_detect_probe(struct platform_device *pdev)
{
	int rc = 0;
	struct device *dev = &pdev->dev;
	struct device_node *np = dev->of_node;

	struct fingerprint_detect_data *fp_detect =
		devm_kzalloc(dev, sizeof(*fp_detect),
			GFP_KERNEL);
	if (!fp_detect) {
		rc = -ENOMEM;
		goto exit;
	}

	fp_detect->dev = dev;
	dev_set_drvdata(dev, fp_detect);

	if (!np) {
		dev_err(dev, "no of node found\n");
		rc = -EINVAL;
		goto exit;
	}

	rc = fp_pinctrl_init(fp_detect);
		if (rc)
		goto exit;

	rc = sysfs_create_group(&dev->kobj, &attribute_group);
	if (rc) {
		dev_err(dev, "could not create sysfs\n");
		goto exit;
	}

	if (of_property_read_bool(fp_detect->dev->of_node, "oneplus,goodix9608"))
		fp_detect->sensor_version = 0x07;
	else
		fp_detect->sensor_version = 0x04;

	fp_version = fp_detect->sensor_version;
exit:
	return rc;
}


static const struct of_device_id fingerprint_detect_of_match[] = {
	{ .compatible = "oneplus,fpdetect", },
	{}
};
MODULE_DEVICE_TABLE(op, fingerprint_detect_of_match);

static struct platform_driver fingerprint_detect_driver = {
	.driver = {
		.name		= "fingerprint_detect",
		.owner		= THIS_MODULE,
		.of_match_table = fingerprint_detect_of_match,
	},
	.probe = fingerprint_detect_probe,
};
module_platform_driver(fingerprint_detect_driver);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("yale liu");
MODULE_DESCRIPTION("Fingerprint detect device driver.");
