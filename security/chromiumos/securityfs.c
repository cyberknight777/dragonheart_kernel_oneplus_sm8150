/*
 * Linux Security Module for Chromium OS
 *
 * Copyright 2016 Google Inc. All Rights Reserved
 *
 * Authors:
 *      Mattias Nissler <mnissler@chromium.org>
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

#include <linux/capability.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/security.h>
#include <linux/string.h>
#include <linux/uaccess.h>

#include "inode_mark.h"

static struct dentry *chromiumos_dir;
static struct dentry *chromiumos_symlink_policy_dir;

struct chromiumos_symlink_file_entry {
	const char *name;
	int (*handle_write)(struct chromiumos_symlink_file_entry *,
			    struct dentry *);
	enum chromiumos_symlink_traversal_policy traversal_policy;
	struct dentry *dentry;
};

static int chromiumos_symlink_file_policy_write(
	struct chromiumos_symlink_file_entry *file_entry, struct dentry *dentry)
{
	return chromiumos_update_symlink_traversal_policy(
		dentry->d_inode, file_entry->traversal_policy);
}

static int chromiumos_symlink_file_flush_write(
	struct chromiumos_symlink_file_entry *file_entry, struct dentry *dentry)
{
	return chromiumos_flush_symlink_traversal_policy(dentry->d_sb);
}

static struct chromiumos_symlink_file_entry chromiumos_symlink_files[] = {
	{.name = "block",
	 .handle_write = chromiumos_symlink_file_policy_write,
	 .traversal_policy = CHROMIUMOS_SYMLINK_TRAVERSAL_BLOCK},
	{.name = "allow",
	 .handle_write = chromiumos_symlink_file_policy_write,
	 .traversal_policy = CHROMIUMOS_SYMLINK_TRAVERSAL_ALLOW},
	{.name = "reset",
	 .handle_write = chromiumos_symlink_file_policy_write,
	 .traversal_policy = CHROMIUMOS_SYMLINK_TRAVERSAL_INHERIT},
	{.name = "flush",
	 .handle_write = &chromiumos_symlink_file_flush_write},
};

static int chromiumos_resolve_path(const char __user *buf, size_t len,
				   struct path *path)
{
	char *filename = NULL;
	char *canonical_buf = NULL;
	char *canonical;
	int ret;

	if (len + 1 > PATH_MAX)
		return -EINVAL;

	/*
	 * Copy the path to a kernel buffer. We can't use user_path_at()
	 * since it expects a zero-terminated path, which we generally don't
	 * have here.
	 */
	filename = kzalloc(len + 1, GFP_KERNEL);
	if (!filename)
		return -ENOMEM;

	if (copy_from_user(filename, buf, len)) {
		ret = -EFAULT;
		goto out;
	}

	ret = kern_path(filename, 0, path);
	if (ret)
		goto out;

	/*
	 * Make sure the path is canonical, i.e. it didn't contain symlinks. To
	 * check this we convert |path| back to an absolute path (within the
	 * global root) and compare the resulting path name with the passed-in
	 * |filename|. This is stricter than needed (i.e. consecutive slashes
	 * don't get ignored), but that's fine for our purposes.
	 */
	canonical_buf = kzalloc(len + 1, GFP_KERNEL);
	if (!canonical_buf) {
		ret = -ENOMEM;
		goto out;
	}

	canonical = d_absolute_path(path, canonical_buf, len + 1);
	if (IS_ERR(canonical)) {
		ret = PTR_ERR(canonical);

		/* Buffer too short implies |filename| wasn't canonical. */
		if (ret == -ENAMETOOLONG)
			ret = -EMLINK;

		goto out;
	}

	ret = strcmp(filename, canonical) ? -EMLINK : 0;

out:
	kfree(canonical_buf);
	if (ret < 0)
		path_put(path);
	kfree(filename);
	return ret;
}

static ssize_t chromiumos_symlink_file_write(struct file *file,
					     const char __user *buf, size_t len,
					     loff_t *ppos)
{
	struct chromiumos_symlink_file_entry *file_entry =
		file->f_inode->i_private;
	struct path path = {};
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (*ppos != 0)
		return -EINVAL;

	ret = chromiumos_resolve_path(buf, len, &path);
	if (ret)
		return ret;

	ret = file_entry->handle_write(file_entry, path.dentry);
	path_put(&path);
	return ret < 0 ? ret : len;
}

static const struct file_operations chromiumos_symlink_file_fops = {
	.write = chromiumos_symlink_file_write,
};

static void chromiumos_shutdown_securityfs(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(chromiumos_symlink_files); ++i) {
		struct chromiumos_symlink_file_entry *entry =
			&chromiumos_symlink_files[i];
		securityfs_remove(entry->dentry);
		entry->dentry = NULL;
	}

	securityfs_remove(chromiumos_symlink_policy_dir);
	chromiumos_symlink_policy_dir = NULL;

	securityfs_remove(chromiumos_dir);
	chromiumos_dir = NULL;
}

static int chromiumos_init_securityfs(void)
{
	int i;
	int ret;

	chromiumos_dir = securityfs_create_dir("chromiumos", NULL);
	if (!chromiumos_dir) {
		ret = PTR_ERR(chromiumos_dir);
		goto error;
	}

	chromiumos_symlink_policy_dir =
		securityfs_create_dir("symlink_policy", chromiumos_dir);
	if (!chromiumos_symlink_policy_dir) {
		ret = PTR_ERR(chromiumos_symlink_policy_dir);
		goto error;
	}

	for (i = 0; i < ARRAY_SIZE(chromiumos_symlink_files); ++i) {
		struct chromiumos_symlink_file_entry *entry =
			&chromiumos_symlink_files[i];
		entry->dentry = securityfs_create_file(
			entry->name, S_IWUSR, chromiumos_symlink_policy_dir,
			entry, &chromiumos_symlink_file_fops);
		if (IS_ERR(entry->dentry)) {
			ret = PTR_ERR(entry->dentry);
			goto error;
		}
	}

	return 0;

error:
	chromiumos_shutdown_securityfs();
	return ret;
}
fs_initcall(chromiumos_init_securityfs);
