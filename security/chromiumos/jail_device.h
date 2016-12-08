/*
 * Interface for creating device jails.
 *
 * Copyright 2017 Google, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef _SECURITY_CHROMIUMOS_JAIL_DEVICE_H
#define _SECURITY_CHROMIUMOS_JAIL_DEVICE_H

/**
 * Instantiates a jail for the device at |path|.
 *
 * Either returns 0 and sets |*dev| with the device number of the
 * new device, or returns -1 and sets errno. If errno is EEXIST,
 * |*dev| will still be set, but no new device will be created.
 */
int add_jail_device(const char *path, dev_t *new_devt);

/**
 * Removes a jail with the given device number.
 */
int remove_jail_device(dev_t devt);

/**
 * Sets up the jail device subsystem. Registers a device class and
 * range of minor numbers.
 */
int jail_device_setup(void);

/**
 * Tears down the jail device subsystem. Destroys all jails, unregisters
 * the device class, and returns the range of minor numbers.
 */
void jail_device_teardown(void);

#endif /* _SECURITY_CHROMIUMOS_JAIL_DEVICE_H */
