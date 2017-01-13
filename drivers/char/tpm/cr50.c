/*
 * Copyright 2016 Google Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

/*
 * This file contains common code for devices with Cr50 firmware.
 */

#include <linux/suspend.h>
#include "cr50.h"

/* Command code for Cr50 vendor-specific extensions (vendor bit set). */
#define TPM2_CC_VENDOR_CR50 (BIT(29) | 0)

/* Subcommand codes for Cr50 vendor commands. */
#define CR50_CC_CONTROL_DEEP_SLEEP 22

struct cr50_command_header {
	struct tpm_input_header common;
	__be16 sub_command;
} __packed;

#define CR50_COMMAND_HEADER(sub_cc, len) \
{ \
	.common = { \
		.tag = cpu_to_be16(TPM2_ST_NO_SESSIONS), \
		.ordinal = cpu_to_be32(TPM2_CC_VENDOR_CR50), \
		.length = cpu_to_be32(len) \
	}, \
	.sub_command = cpu_to_be16(sub_cc) \
}

struct cr50_control_deep_sleep_cmd {
	struct cr50_command_header header;
	u8 enable;
} __packed;

int cr50_control_deep_sleep(struct tpm_chip *chip, bool enable)
{
	struct cr50_control_deep_sleep_cmd cmd = {
		.header = CR50_COMMAND_HEADER(CR50_CC_CONTROL_DEEP_SLEEP,
				sizeof(struct cr50_control_deep_sleep_cmd)),
		.enable = enable ? 1 : 0
	};

	return tpm_transmit_cmd(chip, NULL, &cmd, sizeof(cmd), 0, 0,
				enable ?
					"enabling deep-sleep" :
					"disabling deep-sleep");
}
EXPORT_SYMBOL(cr50_control_deep_sleep);

#ifdef CONFIG_PM_SLEEP
int cr50_resume(struct device *dev)
{
	struct tpm_chip *chip = dev_get_drvdata(dev);

	/* Disable deep-sleep, ignore if command failed. */
	cr50_control_deep_sleep(chip, 0);

	if (pm_suspend_via_firmware())
		return tpm_pm_resume(dev);
	else
		return 0;
}
EXPORT_SYMBOL(cr50_resume);

int cr50_suspend(struct device *dev)
{
	struct tpm_chip *chip = dev_get_drvdata(dev);

	/*
	 * - Enable deep-sleep and call tpm_pm_suspend, which sends
	 *   TPM2_Shutdown(STATE), if suspended by firmware. Firmware will
	 *   re-initialize tpm on resume. Ignore if enabling deep-sleep failed.
	 * - Disable deep-sleep otherwise. Abort suspend if command failed:
	 *   can't allow deep-sleep if tpm is not re-initialized on resume.
	 *   [Aborting on failed commands currently disabled - see TODO below]
	 */
	if (pm_suspend_via_firmware()) {
		cr50_control_deep_sleep(chip, 1);
		return tpm_pm_suspend(dev);
	} else {
		/*
		 * TODO(http://crosbug.com/p/59007): stop ignoring errors
		 * from tpm when the control-deep-sleep command is implemented
		 * on the tpm side.
		 */
		cr50_control_deep_sleep(chip, 0);
		return 0;
	}
}
EXPORT_SYMBOL(cr50_suspend);
#endif /* CONFIG_PM_SLEEP */
