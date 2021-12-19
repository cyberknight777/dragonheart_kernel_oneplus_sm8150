// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020 Vlad Adumitroaie <celtare21@gmail.com>.
 *               2021 Vwool0xE9 <z1281552865@gmail.com>
 */

#define pr_fmt(fmt) "userland_worker: " fmt

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kmod.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/security.h>
#include <linux/delay.h>
#include <linux/userland.h>

#include "../security/selinux/include/security.h"

#define STANDARD_SIZE 4
#define MAX_CHAR 128
#define DELAY 500
#define LONG_DELAY 10000

static char** argv;

static struct delayed_work userland_work;

static void free_memory(char** argv, int size)
{
	int i;

	for (i = 0; i < size; i++)
		kfree(argv[i]);
	kfree(argv);
}

static char** alloc_memory(int size)
{
	char** argv;
	int i;

	argv = kmalloc(size * sizeof(char*), GFP_KERNEL);
	if (!argv) {
		pr_err("Couldn't allocate memory!");
		return NULL;
	}

	for (i = 0; i < size; i++) {
		argv[i] = kmalloc(MAX_CHAR * sizeof(char), GFP_KERNEL);
		if (!argv[i]) {
			pr_err("Couldn't allocate memory!");
			kfree(argv);
			return NULL;
		}
	}

	return argv;
}

static int use_userspace(char** argv)
{
	static char* envp[] = {
		"SHELL=/bin/sh",
		"HOME=/",
		"USER=shell",
		"TERM=xterm-256color",
		"PATH=/product/bin:/apex/com.android.runtime/bin:/apex/com.android.art/bin:/system_ext/bin:/system/bin:/system/xbin:/odm/bin:/vendor/bin:/vendor/xbin",
		"DISPLAY=:0",
		NULL
	};

	return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
}

static inline int linux_write(const char* prop, const char* value, bool resetprop)
{
	int ret;

	strcpy(argv[0], resetprop ? "/data/local/tmp/resetprop_static" : "/system/bin/setprop");
	strcpy(argv[1], prop);
	strcpy(argv[2], value);
	argv[3] = NULL;

	ret = use_userspace(argv);
	if (!ret)
		pr_info("%s set succesfully!", prop);
	else
		pr_err("Couldn't set %s! %d", prop, ret);

	return ret;
}

static inline int linux_sh(const char* command)
{
	int ret;

	strcpy(argv[0], "/system/bin/sh");
	strcpy(argv[1], "-c");
	strcpy(argv[2], command);
	argv[3] = NULL;

	ret = use_userspace(argv);
	if (!ret)
		pr_info("%s called succesfully!", command);
	else
		pr_err("Couldn't call %s! %d", command, ret);

	return ret;
}

static inline int linux_test(const char* path)
{
	strcpy(argv[0], "/system/bin/test");
	strcpy(argv[1], "-f");
	strcpy(argv[2], path);
	argv[3] = NULL;

	return use_userspace(argv);
}

static void vbswap_help(void)
{
	linux_sh("/system/bin/echo 4294967296 > /sys/devices/virtual/block/vbswap0/disksize");
	linux_sh("/vendor/bin/mkswap /dev/block/vbswap0");
	linux_sh("/system/bin/swapon /dev/block/vbswap0");
}

//Thanks to @gotenksIN for finding OOS left these out of init.oem.rc
//event9 is prox, event11 is brightness.
static void fix_sensors(void) {
	linux_sh("/system/bin/chmod 666 /dev/input/event9");
	linux_sh("/system/bin/chmod 666 /dev/input/event11");
}

static void dalvikvm_set(void) {
	struct sysinfo i;
	si_meminfo(&i);
	if (i.totalram > 8192ull * 1024 * 1024) {
		// from - phone-xhdpi-12288-dalvik-heap.mk
		linux_write("dalvik.vm.heapstartsize", "24m", false);
		linux_write("dalvik.vm.heapgrowthlimit", "384m", false);
		linux_write("dalvik.vm.heaptargetutilization", "0.42", false);
		linux_write("dalvik.vm.heapmaxfree", "56m", false);
	} else if (i.totalram > 6144ull * 1024 * 1024) {
		// from - phone-xhdpi-8192-dalvik-heap.mk
		linux_write("dalvik.vm.heapstartsize", "24m", false);
		linux_write("dalvik.vm.heapgrowthlimit", "256m", false);
		linux_write("dalvik.vm.heaptargetutilization", "0.46", false);
		linux_write("dalvik.vm.heapmaxfree", "48m", false);
	} else {
		// from - phone-xhdpi-6144-dalvik-heap.mk
		linux_write("dalvik.vm.heapstartsize", "16m", false);
		linux_write("dalvik.vm.heapgrowthlimit", "256m", false);
		linux_write("dalvik.vm.heaptargetutilization", "0.5", false);
		linux_write("dalvik.vm.heapmaxfree", "32m", false);
	}
	linux_write("dalvik.vm.heapsize", "512m", false);
	linux_write("dalvik.vm.heapminfree", "8m", false);

}

static void set_kernel_module_params(void) {
  return 0;
}

static void userland_worker(struct work_struct *work)
{
	bool is_enforcing;

	argv = alloc_memory(STANDARD_SIZE);
	if (!argv) {
		pr_err("Couldn't allocate memory!");
		return;
	}

	is_enforcing = get_enforce_value();
	if (is_enforcing) {
		pr_info("Going permissive");
		set_selinux(0);
	}

	vbswap_help();

	msleep(DELAY);

	dalvikvm_set();

	set_kernel_module_params();

	fix_sensors();

	if (is_enforcing) {
		pr_info("Going enforcing");
		set_selinux(1);
	}

	free_memory(argv, STANDARD_SIZE);
}

static int __init userland_worker_entry(void)
{
	INIT_DELAYED_WORK(&userland_work, userland_worker);
	queue_delayed_work(system_power_efficient_wq,
			&userland_work, DELAY);

	return 0;
}

module_init(userland_worker_entry);
