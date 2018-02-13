/*
 * Linux Security Module for Chromium OS
 *
 * Copyright 2011 Google Inc. All Rights Reserved
 *
 * Authors:
 *      Stephan Uphoff  <ups@google.com>
 *      Kees Cook       <keescook@chromium.org>
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#define pr_fmt(fmt) "Chromium OS LSM: " fmt

#include <linux/module.h>
#include <linux/security.h>
#include <linux/lsm_hooks.h>
#include <linux/sched.h>	/* current and other task related stuff */
#include <linux/namei.h>	/* for nameidata_get_total_link_count */
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/mount.h>
#include <linux/path.h>

#include "inode_mark.h"
#include "utils.h"

static int chromiumos_security_sb_mount(const char *dev_name,
					const struct path *path,
					const char *type, unsigned long flags,
					void *data)
{
#ifdef CONFIG_SECURITY_CHROMIUMOS_NO_SYMLINK_MOUNT
	if (nameidata_get_total_link_count()) {
		char *cmdline;
		char *pathbuf;
		char *pathlog;

		cmdline = printable_cmdline(current);
		/* We add 11 spaces for ' (deleted)' to be appended */
		pathbuf = kmalloc(PATH_MAX + 11, GFP_KERNEL);
		if (pathbuf) {
			pathlog = d_path(path, pathbuf, PATH_MAX + 11);
			if (IS_ERR(pathlog))
				pathlog = "<too_long>";
		} else
			pathlog = "<no_memory>";
		pr_notice("Mount path with symlinks prohibited - "
			"pid=%d cmdline=%s dev=%s type=%s path=%s\n",
			task_pid_nr(current), cmdline, dev_name, type, pathlog);
		kfree(pathbuf);
		kfree(cmdline);
		return -ELOOP;
	}
#endif

	return 0;
}

static int chromiumos_security_inode_follow_link(struct dentry *dentry,
						 struct inode *inode, bool rcu)
{
	static char accessed_path[PATH_MAX];
	enum chromiumos_inode_security_policy policy;

	policy = chromiumos_get_inode_security_policy(
		dentry,
		CHROMIUMOS_SYMLINK_TRAVERSAL);

	/*
	 * Emit a warning in cases of blocked symlink traversal attempts. These
	 * will show up in kernel warning reports collected by the crash
	 * reporter, so we have some insight on spurious failures that need
	 * addressing.
	 */
	WARN(policy == CHROMIUMOS_INODE_POLICY_BLOCK,
	     "Blocked symlink traversal for path %x:%x:%s (see https://goo.gl/8xICW6 for context and rationale)\n",
	     MAJOR(dentry->d_sb->s_dev), MINOR(dentry->d_sb->s_dev),
	     dentry_path(dentry, accessed_path, PATH_MAX));

	return policy == CHROMIUMOS_INODE_POLICY_BLOCK ? -EACCES : 0;
}

static int chromiumos_security_file_open(
	struct file *file,
	const struct cred *cred)
{
	static char accessed_path[PATH_MAX];
	enum chromiumos_inode_security_policy policy;
	struct dentry *dentry = file->f_path.dentry;

	/* Returns 0 if file is not a FIFO */
	if (!S_ISFIFO(file->f_inode->i_mode))
		return 0;

	policy = chromiumos_get_inode_security_policy(
		dentry,
		CHROMIUMOS_FIFO_ACCESS);

	/*
	 * Emit a warning in cases of blocked fifo access attempts. These will
	 * show up in kernel warning reports collected by the crash reporter,
	 * so we have some insight on spurious failures that need addressing.
	 */
	WARN(policy == CHROMIUMOS_INODE_POLICY_BLOCK,
	     "Blocked fifo access for path %x:%x:%s\n (see https://goo.gl/8xICW6 for context and rationale)\n",
	     MAJOR(dentry->d_sb->s_dev), MINOR(dentry->d_sb->s_dev),
	     dentry_path(dentry, accessed_path, PATH_MAX));

	return policy == CHROMIUMOS_INODE_POLICY_BLOCK ? -EACCES : 0;
}

static struct security_hook_list chromiumos_security_hooks[] = {
	LSM_HOOK_INIT(sb_mount, chromiumos_security_sb_mount),
	LSM_HOOK_INIT(inode_follow_link, chromiumos_security_inode_follow_link),
	LSM_HOOK_INIT(file_open, chromiumos_security_file_open),
};

static int __init chromiumos_security_init(void)
{
	security_add_hooks(chromiumos_security_hooks,
			   ARRAY_SIZE(chromiumos_security_hooks), "chromiumos");

	pr_info("enabled");

	return 0;
}
security_initcall(chromiumos_security_init);
