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

#include <asm/syscall.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/hashtable.h>
#include <linux/lsm_hooks.h>
#include <linux/module.h>
#include <linux/mount.h>
#include <linux/namei.h>	/* for nameidata_get_total_link_count */
#include <linux/path.h>
#include <linux/ptrace.h>
#include <linux/sched/task_stack.h>
#include <linux/sched.h>	/* current and other task related stuff */
#include <linux/security.h>

#include "inode_mark.h"
#include "process_management.h"
#include "utils.h"

#define NUM_BITS 8 // 128 buckets in hash table

static DEFINE_HASHTABLE(process_setuid_policy_hashtable, NUM_BITS);

/*
 * Bool signifying whether to disable fixups for process management related
 * routines in the kernel (setuid, setgid, kill). Default value is false. Can
 * be overridden by 'disable_process_management_policies' flag. Static vars get
 * initialized to 0/false since in BSS.
 **/
static bool disable_process_management_policies;

/* Disable process management policies if flag passed */
static int set_disable_process_management_policies(char *str)
{
	disable_process_management_policies = true;
	return 1;
}
__setup("disable_process_management_policies=",
	set_disable_process_management_policies);

/*
 * Hash table entry to store process management policy signifying that 'parent'
 * user can use 'child' user for process management (for now that just means
 * 'parent' can set*uid() to 'child'). Will be adding exceptions for set*gid()
 * and kill() in the future.
 */
struct entry {
	struct hlist_node next;
	struct hlist_node dlist; /* for deletion cleanup */
	uint64_t parent_kuid;
	uint64_t child_kuid;
};

#if defined(CONFIG_SECURITY_CHROMIUMOS_NO_UNPRIVILEGED_UNSAFE_MOUNTS) || \
	defined(CONFIG_SECURITY_CHROMIUMOS_NO_SYMLINK_MOUNT)
static void report(const char *origin, const struct path *path, char *operation)
{
	char *alloced = NULL, *cmdline;
	char *pathname; /* Pointer to either static string or "alloced". */

	if (!path)
		pathname = "<unknown>";
	else {
		/* We will allow 11 spaces for ' (deleted)' to be appended */
		alloced = pathname = kmalloc(PATH_MAX+11, GFP_KERNEL);
		if (!pathname)
			pathname = "<no_memory>";
		else {
			pathname = d_path(path, pathname, PATH_MAX+11);
			if (IS_ERR(pathname))
				pathname = "<too_long>";
			else {
				pathname = printable(pathname, PATH_MAX+11);
				kfree(alloced);
				alloced = pathname;
			}
		}
	}

	cmdline = printable_cmdline(current);

	pr_notice("%s %s obj=%s pid=%d cmdline=%s\n", origin,
		  operation, pathname, task_pid_nr(current), cmdline);

	kfree(cmdline);
	kfree(alloced);
}
#endif

static int chromiumos_security_sb_mount(const char *dev_name,
					const struct path *path,
					const char *type, unsigned long flags,
					void *data)
{
#ifdef CONFIG_SECURITY_CHROMIUMOS_NO_SYMLINK_MOUNT
	if (nameidata_get_total_link_count()) {
		report("sb_mount", path, "Mount path with symlinks prohibited");
		pr_notice("sb_mount dev=%s type=%s flags=%#lx\n",
			  dev_name, type, flags);
		return -ELOOP;
	}
#endif

#ifdef CONFIG_SECURITY_CHROMIUMOS_NO_UNPRIVILEGED_UNSAFE_MOUNTS
	if ((!(flags & (MS_BIND | MS_MOVE | MS_SHARED | MS_PRIVATE | MS_SLAVE |
			MS_UNBINDABLE)) ||
	     ((flags & MS_REMOUNT) && (flags & MS_BIND))) &&
	    !capable(CAP_SYS_ADMIN)) {
		int required_mnt_flags = MNT_NOEXEC | MNT_NOSUID | MNT_NODEV;

		if (flags & MS_REMOUNT) {
			/*
			 * If this is a remount, we only require that the
			 * requested flags are a superset of the original mount
			 * flags.
			 */
			required_mnt_flags &= path->mnt->mnt_flags;
		}
		/*
		 * The three flags we are interested in disallowing in
		 * unprivileged user namespaces (MS_NOEXEC, MS_NOSUID, MS_NODEV)
		 * cannot be modified when doing a bind-mount. The kernel
		 * attempts to dispatch calls to do_mount() within
		 * fs/namespace.c in the following order:
		 *
		 * * If the MS_REMOUNT flag is present, it calls do_remount().
		 *   When MS_BIND is also present, it only allows to modify the
		 *   per-mount flags, which are copied into
		 *   |required_mnt_flags|.  Otherwise it bails in the absence of
		 *   the CAP_SYS_ADMIN in the init ns.
		 * * If the MS_BIND flag is present, the only other flag checked
		 *   is MS_REC.
		 * * If any of the mount propagation flags are present
		 *   (MS_SHARED, MS_PRIVATE, MS_SLAVE, MS_UNBINDABLE),
		 *   flags_to_propagation_type() filters out any additional
		 *   flags.
		 * * If MS_MOVE flag is present, all other flags are ignored.
		 */
		if ((required_mnt_flags & MNT_NOEXEC) && !(flags & MS_NOEXEC)) {
			report("sb_mount", path,
			       "Mounting a filesystem with 'exec' flag requires CAP_SYS_ADMIN in init ns");
			pr_notice("sb_mount dev=%s type=%s flags=%#lx\n",
				  dev_name, type, flags);
			return -EPERM;
		}
		if ((required_mnt_flags & MNT_NOSUID) && !(flags & MS_NOSUID)) {
			report("sb_mount", path,
			       "Mounting a filesystem with 'suid' flag requires CAP_SYS_ADMIN in init ns");
			pr_notice("sb_mount dev=%s type=%s flags=%#lx\n",
				  dev_name, type, flags);
			return -EPERM;
		}
		if ((required_mnt_flags & MNT_NODEV) && !(flags & MS_NODEV) &&
		    strcmp(type, "devpts")) {
			report("sb_mount", path,
			       "Mounting a filesystem with 'dev' flag requires CAP_SYS_ADMIN in init ns");
			pr_notice("sb_mount dev=%s type=%s flags=%#lx\n",
				  dev_name, type, flags);
			return -EPERM;
		}
	}
#endif

	return 0;
}

static DEFINE_SPINLOCK(process_setuid_policy_hashtable_spinlock);

static int chromiumos_security_inode_follow_link(struct dentry *dentry,
						 struct inode *inode, bool rcu)
{
	static char accessed_path[PATH_MAX];
	enum chromiumos_inode_security_policy policy;

	policy = chromiumos_get_inode_security_policy(
		dentry, inode,
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
		dentry, dentry->d_inode,
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

bool chromiumos_check_setuid_policy_hashtable_key(kuid_t parent)
{
	struct entry *entry;

	rcu_read_lock();
	hash_for_each_possible_rcu(process_setuid_policy_hashtable,
				   entry, next, __kuid_val(parent)) {
		if (entry->parent_kuid == __kuid_val(parent)) {
			rcu_read_unlock();
			return true;
		}
	}
	rcu_read_unlock();

	/*
	 * Using RCU, its possible that a policy gets added in between the time
	 * we check above and when we return false here. This is fine, since
	 * policy updates only happen during system startup, well before
	 * sandboxed system services start running and the policies need to be
	 * queried.
	 */
	return false;
}

bool chromiumos_check_setuid_policy_hashtable_key_value(kuid_t parent,
							kuid_t child)
{
	struct entry *entry;

	rcu_read_lock();
	hash_for_each_possible_rcu(process_setuid_policy_hashtable,
				   entry, next, __kuid_val(parent)) {
		if (entry->parent_kuid == __kuid_val(parent) &&
		    entry->child_kuid == __kuid_val(child)) {
			rcu_read_unlock();
			return true;
		}
	}
	rcu_read_unlock();

	/*
	 * Using RCU, its possible that a policy gets added in between the time
	 * we check above and when we return false here. This is fine, since
	 * policy updates only happen during system startup, well before
	 * sandboxed system services start running and the policies need to be
	 * queried.
	 */
	return false;
}

bool setuid_syscall(int num)
{
#ifdef CONFIG_X86_64
	if (!(num == __NR_setreuid ||
	      num == __NR_setuid ||
	      num == __NR_setresuid ||
	      num == __NR_setfsuid))
		return false;
#elif defined CONFIG_ARM64
	if (!(num == __NR_compat_setuid ||
	      num == __NR_compat_setreuid ||
	      num == __NR_compat_setfsuid ||
	      num == __NR_compat_setresuid ||
	      num == __NR_compat_setreuid32 ||
	      num == __NR_compat_setresuid32 ||
	      num == __NR_compat_setuid32 ||
	      num == __NR_compat_setfsuid32))
		return false;
#else /* CONFIG_ARM */
	if (!(num == __NR_setreuid32 ||
	      num == __NR_setuid32 ||
	      num == __NR_setresuid32 ||
	      num == __NR_setfsuid32))
		return false;
#endif
	return true;
}

int chromiumos_security_capable(const struct cred *cred,
				struct user_namespace *ns,
				int cap,
				int audit)
{
	/* The current->mm check will fail if this is a kernel thread. */
	if (!disable_process_management_policies &&
	    cap == CAP_SETUID &&
	    current->mm &&
	    chromiumos_check_setuid_policy_hashtable_key(cred->uid)) {
		// syscall_get_nr can theoretically return 0 or -1, but that
		// would signify that the syscall is being aborted due to a
		// signal, so we don't need to check for this case here.
		if (!(setuid_syscall(syscall_get_nr(current,
						    current_pt_regs()))))
			// Deny if we're not in a set*uid() syscall to avoid
			// giving powers gated by CAP_SETUID that are related
			// to functionality other than calling set*uid() (e.g.
			// allowing user to set up userns uid mappings).
			return -1;
	}
	return 0;
}

/*
 * Emit a warning when no entry found in whitelist. These will show up in
 * kernel warning reports collected by the crash reporter, so we have some
 * insight regarding failures that need addressing.
 */
void chromiumos_setuid_policy_warning(kuid_t parent, kuid_t child)
{
	WARN(1,
	     "UID %u is restricted to using certain whitelisted UIDs for process management, and %u is not in the whitelist.\n",
	     __kuid_val(parent),
	     __kuid_val(child));
}

int chromiumos_check_uid_transition(kuid_t parent, kuid_t child)
{
	if (chromiumos_check_setuid_policy_hashtable_key_value(parent, child))
		return 0;
	chromiumos_setuid_policy_warning(parent, child);
	return -1;
}

/*
 * Check whether there is either an exception for user under old cred struct to
 * use user under new cred struct, or the UID transition is allowed (by Linux
 * set*uid rules) even without CAP_SETUID.
 */
int chromiumos_security_task_fix_setuid(struct cred *new,
					const struct cred *old, int flags)
{

	/*
	 * Do nothing if feature is turned off by kernel compile flag or there
	 * are no setuid restrictions for this UID.
	 */
	if (disable_process_management_policies ||
	    !chromiumos_check_setuid_policy_hashtable_key(old->uid))
		return 0;

	switch (flags) {
	case LSM_SETID_RE:
		/*
		 * Users for which setuid restrictions exist can only set the
		 * real UID to the real UID or the effective UID, unless an
		 * explicit whitelist policy allows the transition.
		 */
		if (!uid_eq(old->uid, new->uid) &&
			!uid_eq(old->euid, new->uid)) {
			return chromiumos_check_uid_transition(old->uid,
								new->uid);
		}
		/*
		 * Users for which setuid restrictions exist can only set the
		 * effective UID to the real UID, the effective UID, or the
		 * saved set-UID, unless an explicit whitelist policy allows
		 * the transition.
		 */
		if (!uid_eq(old->uid, new->euid) &&
			!uid_eq(old->euid, new->euid) &&
			!uid_eq(old->suid, new->euid)) {
			return chromiumos_check_uid_transition(old->euid,
								new->euid);
		}
		break;
	case LSM_SETID_ID:
		/*
		 * Users for which setuid restrictions exist cannot change the
		 * real UID or saved set-UID unless an explicit whitelist
		 * policy allows the transition.
		 */
		if (!uid_eq(old->uid, new->uid)) {
			return chromiumos_check_uid_transition(old->uid,
								new->uid);
		}
		if (!uid_eq(old->suid, new->suid)) {
			return chromiumos_check_uid_transition(old->suid,
								new->suid);
		}
		break;
	case LSM_SETID_RES:
		/*
		 * Users for which setuid restrictions exist cannot change the
		 * real UID, effective UID, or saved set-UID to anything but
		 * one of: the current real UID, the current effective UID or
		 * the current saved set-user-ID unless an explicit whitelist
		 * policy allows the transition.
		 */
		if (!uid_eq(new->uid, old->uid) &&
			!uid_eq(new->uid, old->euid) &&
			!uid_eq(new->uid, old->suid)) {
			return chromiumos_check_uid_transition(old->uid,
								new->uid);
		}
		if (!uid_eq(new->euid, old->uid) &&
			!uid_eq(new->euid, old->euid) &&
			!uid_eq(new->euid, old->suid)) {
			return chromiumos_check_uid_transition(old->euid,
								new->euid);
		}
		if (!uid_eq(new->suid, old->uid) &&
			!uid_eq(new->suid, old->euid) &&
			!uid_eq(new->suid, old->suid)) {
			return chromiumos_check_uid_transition(old->suid,
								new->suid);
		}
		break;
	case LSM_SETID_FS:
		/*
		 * Users for which setuid restrictions exist cannot change the
		 * filesystem UID to anything but one of: the current real UID,
		 * the current effective UID or the current saved set-UID
		 * unless an explicit whitelist policy allows the transition.
		 */
		if (!uid_eq(new->fsuid, old->uid)  &&
			!uid_eq(new->fsuid, old->euid)  &&
			!uid_eq(new->fsuid, old->suid) &&
			!uid_eq(new->fsuid, old->fsuid)) {
			return chromiumos_check_uid_transition(old->fsuid,
								new->fsuid);
		}
		break;
	}
	return 0;
}

static struct security_hook_list chromiumos_security_hooks[] = {
	LSM_HOOK_INIT(sb_mount, chromiumos_security_sb_mount),
	LSM_HOOK_INIT(inode_follow_link, chromiumos_security_inode_follow_link),
	LSM_HOOK_INIT(file_open, chromiumos_security_file_open),
	LSM_HOOK_INIT(capable, chromiumos_security_capable),
	LSM_HOOK_INIT(task_fix_setuid, chromiumos_security_task_fix_setuid),
};

/* Add process management policy to hash table */
int chromiumos_add_process_management_entry(kuid_t parent, kuid_t child)
{
	struct entry *new;

	/* Return if entry already exists */
	if (chromiumos_check_setuid_policy_hashtable_key_value(parent,
							       child))
		return 0;

	new = kzalloc(sizeof(struct entry), GFP_KERNEL);
	if (!new)
		return -ENOMEM;
	new->parent_kuid = __kuid_val(parent);
	new->child_kuid = __kuid_val(child);
	spin_lock(&process_setuid_policy_hashtable_spinlock);
	hash_add_rcu(process_setuid_policy_hashtable,
		     &new->next,
		     __kuid_val(parent));
	spin_unlock(&process_setuid_policy_hashtable_spinlock);
	return 0;
}

void chromiumos_flush_process_management_entries(void)
{
	struct entry *entry;
	struct hlist_node *hlist_node;
	unsigned int bkt_loop_cursor;
	HLIST_HEAD(free_list);

	/*
	 * Could probably use hash_for_each_rcu here instead, but this should
	 * be fine as well.
	 */
	hash_for_each_safe(process_setuid_policy_hashtable, bkt_loop_cursor,
			   hlist_node, entry, next) {
		spin_lock(&process_setuid_policy_hashtable_spinlock);
		hash_del_rcu(&entry->next);
		spin_unlock(&process_setuid_policy_hashtable_spinlock);
		hlist_add_head(&entry->dlist, &free_list);
	}
	synchronize_rcu();
	hlist_for_each_entry_safe(entry, hlist_node, &free_list, dlist)
		kfree(entry);
}

static int __init chromiumos_security_init(void)
{
	security_add_hooks(chromiumos_security_hooks,
			   ARRAY_SIZE(chromiumos_security_hooks), "chromiumos");

	pr_info("enabled");

	return 0;
}
security_initcall(chromiumos_security_init);
