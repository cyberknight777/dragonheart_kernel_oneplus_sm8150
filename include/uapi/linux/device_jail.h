/*
 * Device jail user interface.
 *
 * Copyright (C) 2016 Google, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef _UAPI_LINUX_DEVICE_JAIL_H
#define _UAPI_LINUX_DEVICE_JAIL_H

#include <linux/types.h>
#include <linux/magic.h>

/* Control device ioctls */

struct jail_control_add_dev {
	const char __user *path;	/* input */
	__u32 devnum;			/* output */
};

#define JAIL_CONTROL_ADD_DEVICE		_IOWR('C', 0, struct jail_control_add_dev)
#define JAIL_CONTROL_REMOVE_DEVICE	_IOW('C', 1, __u32)

/* Request device responses */

enum jail_request_result {
	JAIL_REQUEST_ALLOW,
	JAIL_REQUEST_ALLOW_WITH_LOCKDOWN,
	JAIL_REQUEST_ALLOW_WITH_DETACH,
	JAIL_REQUEST_DENY,
};

#endif /* _UAPI_LINUX_DEVICE_JAIL_H */
