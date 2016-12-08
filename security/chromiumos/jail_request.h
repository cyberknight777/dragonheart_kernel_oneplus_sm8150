/*
 * Interface for requesting from userspace what level of access should
 * be granted to certain devices.
 *
 * Copyright (C) 2016 Google, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef _SECURITY_CHROMIUMOS_JAIL_REQUEST_H
#define _SECURITY_CHROMIUMOS_JAIL_REQUEST_H

#include <uapi/linux/device_jail.h>

/**
 * Asks userspace for the level of access to provide for the given path.
 */
enum jail_request_result request_access(const char *path);

/**
 * Set up and tear down the jail-request miscdevice.
 */
int jail_request_setup(void);
void jail_request_teardown(void);

#endif /* _SECURITY_CHROMIUMOS_JAIL_REQUEST_H */
