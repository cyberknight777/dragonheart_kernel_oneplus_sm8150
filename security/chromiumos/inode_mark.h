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

/* Indicates symlink traversal policy. */
enum chromiumos_symlink_traversal_policy {
	CHROMIUMOS_SYMLINK_TRAVERSAL_INHERIT, /* Inherit from parent dir */
	CHROMIUMOS_SYMLINK_TRAVERSAL_ALLOW,
	CHROMIUMOS_SYMLINK_TRAVERSAL_BLOCK,
};

extern int chromiumos_update_symlink_traversal_policy(
	struct inode *inode, enum chromiumos_symlink_traversal_policy policy);
int chromiumos_flush_symlink_traversal_policy(struct super_block *sb);

extern enum chromiumos_symlink_traversal_policy
chromiumos_get_symlink_traversal_policy(struct dentry *dentry);
