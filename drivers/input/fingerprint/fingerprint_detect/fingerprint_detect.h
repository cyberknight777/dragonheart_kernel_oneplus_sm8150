#ifndef __FINGERPRINT_DETECT_H_
#define __FINGERPRINT_DETECT_H_

struct fingerprint_detect_data {
	struct device *dev;
	struct pinctrl         *fp_pinctrl;
	struct pinctrl_state   *id_state_init;
	int sensor_version;
};
extern int fp_version;
#endif

