/*
 * Chromium OS alt-syscall tables
 *
 * Copyright (C) 2015 Google, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/alt-syscall.h>
#include <linux/compat.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/prctl.h>
#include <linux/sched/types.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/timex.h>

#include <asm/unistd.h>

static int allow_devmode_syscalls;

#ifdef CONFIG_SYSCTL
static int zero;
static int one = 1;

static struct ctl_path chromiumos_sysctl_path[] = {
	{ .procname = "kernel", },
	{ .procname = "chromiumos", },
	{ .procname = "alt_syscall", },
	{ }
};

static struct ctl_table chromiumos_sysctl_table[] = {
	{
		.procname       = "allow_devmode_syscalls",
		.data           = &allow_devmode_syscalls,
		.maxlen         = sizeof(int),
		.mode           = 0644,
		.proc_handler   = proc_dointvec_minmax,
		.extra1         = &zero,
		.extra2         = &one,
	},
	{ }
};
#endif

struct syscall_whitelist_entry {
	unsigned int nr;
	sys_call_ptr_t alt;
};

struct syscall_whitelist {
	const char *name;
	const struct syscall_whitelist_entry *whitelist;
	unsigned int nr_whitelist;
#ifdef CONFIG_COMPAT
	const struct syscall_whitelist_entry *compat_whitelist;
	unsigned int nr_compat_whitelist;
#endif
	bool permissive;
};

static struct alt_sys_call_table default_table;

/* Intercept and log blocked syscalls. */
static asmlinkage long block_syscall(void)
{
	struct task_struct *task = current;
	struct pt_regs *regs = task_pt_regs(task);

	pr_warn("[%d] %s: blocked syscall %d\n", task_pid_nr(task),
		task->comm, syscall_get_nr(task, regs));

	return -ENOSYS;
}

typedef asmlinkage long (*raw_sys_call_ptr_t)(unsigned long, unsigned long,
					      unsigned long, unsigned long,
					      unsigned long, unsigned long);

/*
 * In permissive mode, warn that the syscall was blocked, but still allow
 * it to go through.  Note that since we don't have an easy way to map from
 * syscall to number of arguments, we pass the maximum (6).
 */
static long do_syscall(raw_sys_call_ptr_t fn)
{
	struct task_struct *task = current;
	struct pt_regs *regs = task_pt_regs(task);
	unsigned long args[6];

	syscall_get_arguments(task, regs, 0, ARRAY_SIZE(args), args);

	return fn(args[0], args[1], args[2], args[3], args[4], args[5]);
}

static asmlinkage long warn_syscall(void)
{
	struct task_struct *task = current;
	struct pt_regs *regs = task_pt_regs(task);
	int nr = syscall_get_nr(task, regs);
	raw_sys_call_ptr_t fn = (raw_sys_call_ptr_t)default_table.table[nr];

	pr_warn_ratelimited("[%d] %s: syscall %d not whitelisted\n",
			    task_pid_nr(task), task->comm, nr);

	return do_syscall(fn);
}

#ifdef CONFIG_COMPAT
static asmlinkage long warn_compat_syscall(void)
{
	struct task_struct *task = current;
	struct pt_regs *regs = task_pt_regs(task);
	int nr = syscall_get_nr(task, regs);
	raw_sys_call_ptr_t fn = (raw_sys_call_ptr_t)default_table.compat_table[nr];

	pr_warn_ratelimited("[%d] %s: compat syscall %d not whitelisted\n",
			    task_pid_nr(task), task->comm, nr);

	return do_syscall(fn);
}
#endif

/*
 * If an alt_syscall table allows prctl(), override it to prevent a process
 * from changing its syscall table.
 */
static asmlinkage long alt_sys_prctl(int option, unsigned long arg2,
				     unsigned long arg3, unsigned long arg4,
				     unsigned long arg5)
{
	if (option == PR_ALT_SYSCALL &&
	    arg2 == PR_ALT_SYSCALL_SET_SYSCALL_TABLE)
		return -EPERM;

	return sys_prctl(option, arg2, arg3, arg4, arg5);
}

#ifdef CONFIG_COMPAT
#define SYSCALL_WHITELIST_COMPAT(x)					\
	.compat_whitelist = x ## _compat_whitelist,			\
	.nr_compat_whitelist = ARRAY_SIZE(x ## _compat_whitelist),
#else
#define SYSCALL_WHITELIST_COMPAT(x)
#endif

#define SYSCALL_WHITELIST(x)						\
	{								\
		.name = #x,						\
		.whitelist = x ## _whitelist,				\
		.nr_whitelist = ARRAY_SIZE(x ## _whitelist),		\
		SYSCALL_WHITELIST_COMPAT(x)				\
	}

#define PERMISSIVE_SYSCALL_WHITELIST(x)					\
	{								\
		.name = #x "_permissive",				\
		.permissive = true,					\
		.whitelist = x ## _whitelist,				\
		.nr_whitelist = ARRAY_SIZE(x ## _whitelist),		\
		SYSCALL_WHITELIST_COMPAT(x)				\
	}

#ifdef CONFIG_COMPAT
#ifdef CONFIG_X86_64
#define __NR_compat_access	__NR_ia32_access
#define __NR_compat_adjtimex	__NR_ia32_adjtimex
#define __NR_compat_brk	__NR_ia32_brk
#define __NR_compat_capget	__NR_ia32_capget
#define __NR_compat_capset	__NR_ia32_capset
#define __NR_compat_chdir	__NR_ia32_chdir
#define __NR_compat_chmod	__NR_ia32_chmod
#define __NR_compat_clock_adjtime	__NR_ia32_clock_adjtime
#define __NR_compat_clock_getres	__NR_ia32_clock_getres
#define __NR_compat_clock_gettime	__NR_ia32_clock_gettime
#define __NR_compat_clock_nanosleep	__NR_ia32_clock_nanosleep
#define __NR_compat_clock_settime	__NR_ia32_clock_settime
#define __NR_compat_clone	__NR_ia32_clone
#define __NR_compat_close	__NR_ia32_close
#define __NR_compat_creat	__NR_ia32_creat
#define __NR_compat_dup	__NR_ia32_dup
#define __NR_compat_dup2	__NR_ia32_dup2
#define __NR_compat_dup3	__NR_ia32_dup3
#define __NR_compat_epoll_create	__NR_ia32_epoll_create
#define __NR_compat_epoll_create1	__NR_ia32_epoll_create1
#define __NR_compat_epoll_ctl	__NR_ia32_epoll_ctl
#define __NR_compat_epoll_wait	__NR_ia32_epoll_wait
#define __NR_compat_epoll_pwait	__NR_ia32_epoll_pwait
#define __NR_compat_eventfd	__NR_ia32_eventfd
#define __NR_compat_eventfd2	__NR_ia32_eventfd2
#define __NR_compat_execve	__NR_ia32_execve
#define __NR_compat_exit	__NR_ia32_exit
#define __NR_compat_exit_group	__NR_ia32_exit_group
#define __NR_compat_faccessat	__NR_ia32_faccessat
#define __NR_compat_fallocate	__NR_ia32_fallocate
#define __NR_compat_fchdir	__NR_ia32_fchdir
#define __NR_compat_fchmod	__NR_ia32_fchmod
#define __NR_compat_fchmodat	__NR_ia32_fchmodat
#define __NR_compat_fchown	__NR_ia32_fchown
#define __NR_compat_fchownat	__NR_ia32_fchownat
#define __NR_compat_fcntl	__NR_ia32_fcntl
#define __NR_compat_fdatasync	__NR_ia32_fdatasync
#define __NR_compat_fgetxattr	__NR_ia32_fgetxattr
#define __NR_compat_flistxattr	__NR_ia32_flistxattr
#define __NR_compat_flock	__NR_ia32_flock
#define __NR_compat_fork	__NR_ia32_fork
#define __NR_compat_fremovexattr	__NR_ia32_fremovexattr
#define __NR_compat_fsetxattr	__NR_ia32_fsetxattr
#define __NR_compat_fstat	__NR_ia32_fstat
#define __NR_compat_fstatfs	__NR_ia32_fstatfs
#define __NR_compat_fsync	__NR_ia32_fsync
#define __NR_compat_ftruncate	__NR_ia32_ftruncate
#define __NR_compat_futex	__NR_ia32_futex
#define __NR_compat_futimesat	__NR_ia32_futimesat
#define __NR_compat_getcpu	__NR_ia32_getcpu
#define __NR_compat_getcwd	__NR_ia32_getcwd
#define __NR_compat_getdents	__NR_ia32_getdents
#define __NR_compat_getdents64	__NR_ia32_getdents64
#define __NR_compat_getegid	__NR_ia32_getegid
#define __NR_compat_geteuid	__NR_ia32_geteuid
#define __NR_compat_getgid	__NR_ia32_getgid
#define __NR_compat_getgroups32	__NR_ia32_getgroups32
#define __NR_compat_getpgid	__NR_ia32_getpgid
#define __NR_compat_getpgrp	__NR_ia32_getpgrp
#define __NR_compat_getpid	__NR_ia32_getpid
#define __NR_compat_getppid	__NR_ia32_getppid
#define __NR_compat_getpriority	__NR_ia32_getpriority
#define __NR_compat_getresgid	__NR_ia32_getresgid
#define __NR_compat_getrandom	__NR_ia32_getrandom
#define __NR_compat_getresuid	__NR_ia32_getresuid
#define __NR_compat_getrlimit	__NR_ia32_getrlimit
#define __NR_compat_getrusage	__NR_ia32_getrusage
#define __NR_compat_getsid	__NR_ia32_getsid
#define __NR_compat_gettid	__NR_ia32_gettid
#define __NR_compat_gettimeofday	__NR_ia32_gettimeofday
#define __NR_compat_getuid	__NR_ia32_getuid
#define __NR_compat_getxattr	__NR_ia32_getxattr
#define __NR_compat_inotify_add_watch	__NR_ia32_inotify_add_watch
#define __NR_compat_inotify_init	__NR_ia32_inotify_init
#define __NR_compat_inotify_init1	__NR_ia32_inotify_init1
#define __NR_compat_inotify_rm_watch	__NR_ia32_inotify_rm_watch
#define __NR_compat_ioctl	__NR_ia32_ioctl
#define __NR_compat_io_destroy	__NR_ia32_io_destroy
#define __NR_compat_io_setup	__NR_ia32_io_setup
#define __NR_compat_io_submit	__NR_ia32_io_submit
#define __NR_compat_ioprio_set	__NR_ia32_ioprio_set
#define __NR_compat_kill	__NR_ia32_kill
#define __NR_compat_lgetxattr	__NR_ia32_lgetxattr
#define __NR_compat_link	__NR_ia32_link
#define __NR_compat_linkat	__NR_ia32_linkat
#define __NR_compat_listxattr	__NR_ia32_listxattr
#define __NR_compat_llistxattr	__NR_ia32_llistxattr
#define __NR_compat_lremovexattr	__NR_ia32_lremovexattr
#define __NR_compat_lseek	__NR_ia32_lseek
#define __NR_compat_lsetxattr	__NR_ia32_lsetxattr
#define __NR_compat_lstat	__NR_ia32_lstat
#define __NR_compat_madvise	__NR_ia32_madvise
#define __NR_compat_memfd_create	__NR_ia32_memfd_create
#define __NR_compat_mincore	__NR_ia32_mincore
#define __NR_compat_mkdir	__NR_ia32_mkdir
#define __NR_compat_mkdirat	__NR_ia32_mkdirat
#define __NR_compat_mknod	__NR_ia32_mknod
#define __NR_compat_mknodat	__NR_ia32_mknodat
#define __NR_compat_mlock	__NR_ia32_mlock
#define __NR_compat_munlock	__NR_ia32_munlock
#define __NR_compat_mlockall	__NR_ia32_mlockall
#define __NR_compat_munlockall	__NR_ia32_munlockall
#define __NR_compat_modify_ldt	__NR_ia32_modify_ldt
#define __NR_compat_mount	__NR_ia32_mount
#define __NR_compat_mprotect	__NR_ia32_mprotect
#define __NR_compat_mremap	__NR_ia32_mremap
#define __NR_compat_msync	__NR_ia32_msync
#define __NR_compat_munmap	__NR_ia32_munmap
#define __NR_compat_name_to_handle_at	__NR_ia32_name_to_handle_at
#define __NR_compat_nanosleep	__NR_ia32_nanosleep
#define __NR_compat_open	__NR_ia32_open
#define __NR_compat_open_by_handle_at	__NR_ia32_open_by_handle_at
#define __NR_compat_openat	__NR_ia32_openat
#define __NR_compat_perf_event_open	__NR_ia32_perf_event_open
#define __NR_compat_personality	__NR_ia32_personality
#define __NR_compat_pipe	__NR_ia32_pipe
#define __NR_compat_pipe2	__NR_ia32_pipe2
#define __NR_compat_poll	__NR_ia32_poll
#define __NR_compat_ppoll	__NR_ia32_ppoll
#define __NR_compat_prctl	__NR_ia32_prctl
#define __NR_compat_pread64	__NR_ia32_pread64
#define __NR_compat_preadv	__NR_ia32_preadv
#define __NR_compat_prlimit64	__NR_ia32_prlimit64
#define __NR_compat_process_vm_readv	__NR_ia32_process_vm_readv
#define __NR_compat_process_vm_writev	__NR_ia32_process_vm_writev
#define __NR_compat_pselect6	__NR_ia32_pselect6
#define __NR_compat_ptrace	__NR_ia32_ptrace
#define __NR_compat_pwrite64	__NR_ia32_pwrite64
#define __NR_compat_pwritev	__NR_ia32_pwritev
#define __NR_compat_read	__NR_ia32_read
#define __NR_compat_readahead	__NR_ia32_readahead
#define __NR_compat_readv	__NR_ia32_readv
#define __NR_compat_readlink	__NR_ia32_readlink
#define __NR_compat_readlinkat	__NR_ia32_readlinkat
#define __NR_compat_recvmmsg	__NR_ia32_recvmmsg
#define __NR_compat_remap_file_pages	__NR_ia32_remap_file_pages
#define __NR_compat_removexattr	__NR_ia32_removexattr
#define __NR_compat_rename	__NR_ia32_rename
#define __NR_compat_renameat	__NR_ia32_renameat
#define __NR_compat_restart_syscall	__NR_ia32_restart_syscall
#define __NR_compat_rmdir	__NR_ia32_rmdir
#define __NR_compat_rt_sigaction	__NR_ia32_rt_sigaction
#define __NR_compat_rt_sigpending	__NR_ia32_rt_sigpending
#define __NR_compat_rt_sigprocmask	__NR_ia32_rt_sigprocmask
#define __NR_compat_rt_sigqueueinfo	__NR_ia32_rt_sigqueueinfo
#define __NR_compat_rt_sigreturn	__NR_ia32_rt_sigreturn
#define __NR_compat_rt_sigsuspend	__NR_ia32_rt_sigsuspend
#define __NR_compat_rt_sigtimedwait	__NR_ia32_rt_sigtimedwait
#define __NR_compat_rt_tgsigqueueinfo	__NR_ia32_rt_tgsigqueueinfo
#define __NR_compat_sched_get_priority_max	__NR_ia32_sched_get_priority_max
#define __NR_compat_sched_get_priority_min	__NR_ia32_sched_get_priority_min
#define __NR_compat_sched_getaffinity	__NR_ia32_sched_getaffinity
#define __NR_compat_sched_getparam	__NR_ia32_sched_getparam
#define __NR_compat_sched_getscheduler	__NR_ia32_sched_getscheduler
#define __NR_compat_sched_setaffinity	__NR_ia32_sched_setaffinity
#define __NR_compat_sched_setparam	__NR_ia32_sched_setparam
#define __NR_compat_sched_setscheduler	__NR_ia32_sched_setscheduler
#define __NR_compat_sched_yield	__NR_ia32_sched_yield
#define __NR_compat_seccomp	__NR_ia32_seccomp
#define __NR_compat_sendfile	__NR_ia32_sendfile
#define __NR_compat_sendfile64	__NR_ia32_sendfile64
#define __NR_compat_sendmmsg	__NR_ia32_sendmmsg
#define __NR_compat_set_robust_list	__NR_ia32_set_robust_list
#define __NR_compat_set_tid_address	__NR_ia32_set_tid_address
#define __NR_compat_set_thread_area	__NR_ia32_set_thread_area
#define __NR_compat_setdomainname	__NR_ia32_setdomainname
#define __NR_compat_setgid	__NR_ia32_setgid
#define __NR_compat_setgroups	__NR_ia32_setgroups
#define __NR_compat_setitimer	__NR_ia32_setitimer
#define __NR_compat_setns	__NR_ia32_setns
#define __NR_compat_setpgid	__NR_ia32_setpgid
#define __NR_compat_setpriority	__NR_ia32_setpriority
#define __NR_compat_setregid	__NR_ia32_setregid
#define __NR_compat_setresgid	__NR_ia32_setresgid
#define __NR_compat_setresuid	__NR_ia32_setresuid
#define __NR_compat_setrlimit	__NR_ia32_setrlimit
#define __NR_compat_setsid	__NR_ia32_setsid
#define __NR_compat_settimeofday	__NR_ia32_settimeofday
#define __NR_compat_setuid	__NR_ia32_setuid
#define __NR_compat_setxattr	__NR_ia32_setxattr
#define __NR_compat_signalfd4	__NR_ia32_signalfd4
#define __NR_compat_sigaltstack	__NR_ia32_sigaltstack
#define __NR_compat_socketcall	__NR_ia32_socketcall
#define __NR_compat_splice	__NR_ia32_splice
#define __NR_compat_stat	__NR_ia32_stat
#define __NR_compat_statfs	__NR_ia32_statfs
#define __NR_compat_symlink	__NR_ia32_symlink
#define __NR_compat_symlinkat	__NR_ia32_symlinkat
#define __NR_compat_sync_file_range	__NR_ia32_sync_file_range
#define __NR_compat_syncfs	__NR_ia32_syncfs
#define __NR_compat_sysinfo	__NR_ia32_sysinfo
#define __NR_compat_syslog	__NR_ia32_syslog
#define __NR_compat_tee		__NR_ia32_tee
#define __NR_compat_tgkill	__NR_ia32_tgkill
#define __NR_compat_tkill	__NR_ia32_tkill
#define __NR_compat_time	__NR_ia32_time
#define __NR_compat_timer_create	__NR_ia32_timer_create
#define __NR_compat_timer_delete	__NR_ia32_timer_delete
#define __NR_compat_timer_getoverrun	__NR_ia32_timer_getoverrun
#define __NR_compat_timer_gettime	__NR_ia32_timer_gettime
#define __NR_compat_timer_settime	__NR_ia32_timer_settime
#define __NR_compat_timerfd_create	__NR_ia32_timerfd_create
#define __NR_compat_timerfd_gettime	__NR_ia32_timerfd_gettime
#define __NR_compat_timerfd_settime	__NR_ia32_timerfd_settime
#define __NR_compat_times		__NR_ia32_times
#define __NR_compat_truncate	__NR_ia32_truncate
#define __NR_compat_umask	__NR_ia32_umask
#define __NR_compat_umount2	__NR_ia32_umount2
#define __NR_compat_uname	__NR_ia32_uname
#define __NR_compat_unlink	__NR_ia32_unlink
#define __NR_compat_unlinkat	__NR_ia32_unlinkat
#define __NR_compat_unshare	__NR_ia32_unshare
#define __NR_compat_ustat	__NR_ia32_ustat
#define __NR_compat_utimensat	__NR_ia32_utimensat
#define __NR_compat_utimes	__NR_ia32_utimes
#define __NR_compat_vfork	__NR_ia32_vfork
#define __NR_compat_vmsplice	__NR_ia32_vmsplice
#define __NR_compat_wait4	__NR_ia32_wait4
#define __NR_compat_waitid	__NR_ia32_waitid
#define __NR_compat_waitpid	__NR_ia32_waitpid
#define __NR_compat_write	__NR_ia32_write
#define __NR_compat_writev	__NR_ia32_writev
#define __NR_compat_chown32	__NR_ia32_chown32
#define __NR_compat_fadvise64	__NR_ia32_fadvise64
#define __NR_compat_fadvise64_64	__NR_ia32_fadvise64_64
#define __NR_compat_fchown32	__NR_ia32_fchown32
#define __NR_compat_fcntl64	__NR_ia32_fcntl64
#define __NR_compat_fstat64	__NR_ia32_fstat64
#define __NR_compat_fstatat64	__NR_ia32_fstatat64
#define __NR_compat_fstatfs64	__NR_ia32_fstatfs64
#define __NR_compat_ftruncate64	__NR_ia32_ftruncate64
#define __NR_compat_getegid32	__NR_ia32_getegid32
#define __NR_compat_geteuid32	__NR_ia32_geteuid32
#define __NR_compat_getgid32	__NR_ia32_getgid32
#define __NR_compat_getresgid32	__NR_ia32_getresgid32
#define __NR_compat_getresuid32	__NR_ia32_getresuid32
#define __NR_compat_getuid32	__NR_ia32_getuid32
#define __NR_compat_lchown32	__NR_ia32_lchown32
#define __NR_compat_lstat64	__NR_ia32_lstat64
#define __NR_compat_mmap2	__NR_ia32_mmap2
#define __NR_compat__newselect	__NR_ia32__newselect
#define __NR_compat__llseek	__NR_ia32__llseek
#define __NR_compat_sigaction	__NR_ia32_sigaction
#define __NR_compat_sigpending	__NR_ia32_sigpending
#define __NR_compat_sigprocmask	__NR_ia32_sigprocmask
#define __NR_compat_sigreturn	__NR_ia32_sigreturn
#define __NR_compat_sigsuspend	__NR_ia32_sigsuspend
#define __NR_compat_setgid32	__NR_ia32_setgid32
#define __NR_compat_setgroups32	__NR_ia32_setgroups32
#define __NR_compat_setregid32	__NR_ia32_setregid32
#define __NR_compat_setresgid32	__NR_ia32_setresgid32
#define __NR_compat_setresuid32	__NR_ia32_setresuid32
#define __NR_compat_setreuid32	__NR_ia32_setreuid32
#define __NR_compat_setuid32	__NR_ia32_setuid32
#define __NR_compat_stat64	__NR_ia32_stat64
#define __NR_compat_statfs64	__NR_ia32_statfs64
#define __NR_compat_truncate64	__NR_ia32_truncate64
#define __NR_compat_ugetrlimit	__NR_ia32_ugetrlimit
#endif
#endif

#define SYSCALL_ENTRY_ALT(name, func)					\
	{								\
		.nr = __NR_ ## name,					\
		.alt = (sys_call_ptr_t)func,				\
	}
#define SYSCALL_ENTRY(name) SYSCALL_ENTRY_ALT(name, NULL)
#define COMPAT_SYSCALL_ENTRY_ALT(name, func)				\
	{								\
		.nr = __NR_compat_ ## name,				\
		.alt = (sys_call_ptr_t)func,				\
	}
#define COMPAT_SYSCALL_ENTRY(name) COMPAT_SYSCALL_ENTRY_ALT(name, NULL)

static struct syscall_whitelist_entry read_write_test_whitelist[] = {
	SYSCALL_ENTRY(exit),
	SYSCALL_ENTRY(openat),
	SYSCALL_ENTRY(close),
	SYSCALL_ENTRY(read),
	SYSCALL_ENTRY(write),
	SYSCALL_ENTRY_ALT(prctl, alt_sys_prctl),

	/* open(2) is deprecated and not wired up on ARM64. */
#ifndef CONFIG_ARM64
	SYSCALL_ENTRY(open),
#endif
};

/*
 * Syscall overrides for android.
 */

/* Thread priority used by Android. */
#define ANDROID_PRIORITY_FOREGROUND     -2
#define ANDROID_PRIORITY_DISPLAY        -4
#define ANDROID_PRIORITY_URGENT_DISPLAY -8
#define ANDROID_PRIORITY_AUDIO         -16
#define ANDROID_PRIORITY_URGENT_AUDIO  -19
#define ANDROID_PRIORITY_HIGHEST       -20

/* Reduced priority when running inside container. */
#define CONTAINER_PRIORITY_FOREGROUND     -1
#define CONTAINER_PRIORITY_DISPLAY        -2
#define CONTAINER_PRIORITY_URGENT_DISPLAY -4
#define CONTAINER_PRIORITY_AUDIO          -8
#define CONTAINER_PRIORITY_URGENT_AUDIO   -9
#define CONTAINER_PRIORITY_HIGHEST       -10

/*
 * Reflect the priority adjustment done by android_setpriority.
 * Note that the prio returned by getpriority has been offset by 20.
 * (returns 40..1 instead of -20..19)
 */
static asmlinkage long android_getpriority(int which, int who)
{
	long prio, nice;

	prio = sys_getpriority(which, who);
	if (prio <= 20)
		return prio;

	nice = -(prio - 20);
	switch (nice) {
	case CONTAINER_PRIORITY_FOREGROUND:
		nice = ANDROID_PRIORITY_FOREGROUND;
		break;
	case CONTAINER_PRIORITY_DISPLAY:
		nice = ANDROID_PRIORITY_DISPLAY;
		break;
	case CONTAINER_PRIORITY_URGENT_DISPLAY:
		nice = ANDROID_PRIORITY_URGENT_DISPLAY;
		break;
	case CONTAINER_PRIORITY_AUDIO:
		nice = ANDROID_PRIORITY_AUDIO;
		break;
	case CONTAINER_PRIORITY_URGENT_AUDIO:
		nice = ANDROID_PRIORITY_URGENT_AUDIO;
		break;
	case CONTAINER_PRIORITY_HIGHEST:
		nice = ANDROID_PRIORITY_HIGHEST;
		break;
	}

	return -nice + 20;
}

/* Make sure nothing sets a nice value more favorable than -10. */
static asmlinkage long android_setpriority(int which, int who, int niceval)
{
	if (niceval < 0) {
		if (niceval < -20)
			niceval = -20;
		niceval = niceval / 2;
	}
	return sys_setpriority(which, who, niceval);
}

static asmlinkage long
do_android_sched_setscheduler(pid_t pid, int policy,
			      struct sched_param __user *param)
{
	struct sched_param lparam;
	struct task_struct *p;
	long retval;

	if (!param || pid < 0)
		return -EINVAL;
	if (copy_from_user(&lparam, param, sizeof(struct sched_param)))
		return -EFAULT;

	rcu_read_lock();
	retval = -ESRCH;
	p = pid ? find_task_by_vpid(pid) : current;
	if (p != NULL) {
		const struct cred *cred = current_cred();
		kuid_t android_root_uid, android_system_uid;

		/*
		 * Allow root(0) and system(1000) processes to set RT scheduler.
		 *
		 * The system_server process run under system provides
		 * SchedulingPolicyService which is used by audioflinger and
		 * other services to boost their threads, so allow it to set RT
		 * scheduler for other threads.
		 */
		android_root_uid = make_kuid(cred->user_ns, 0);
		android_system_uid = make_kuid(cred->user_ns, 1000);
		if ((uid_eq(cred->euid, android_root_uid) ||
		     uid_eq(cred->euid, android_system_uid)) &&
		    ns_capable(cred->user_ns, CAP_SYS_NICE))
			retval = sched_setscheduler_nocheck(p, policy, &lparam);
		else
			retval = sched_setscheduler(p, policy, &lparam);
	}
	rcu_read_unlock();

	return retval;
}

static asmlinkage long
android_sched_setscheduler(pid_t pid, int policy,
			   struct sched_param __user *param)
{
	/* negative values for policy are not valid */
	if (policy < 0)
		return -EINVAL;
	return do_android_sched_setscheduler(pid, policy, param);
}

/*
 * sched_setparam() passes in -1 for its policy, to let the functions
 * it calls know not to change it.
 */
#define SETPARAM_POLICY -1

static asmlinkage long android_sched_setparam(pid_t pid,
					      struct sched_param __user *param)
{
	return do_android_sched_setscheduler(pid, SETPARAM_POLICY, param);
}

static asmlinkage long
android_perf_event_open(struct perf_event_attr __user *attr_uptr,
			pid_t pid, int cpu, int group_fd, unsigned long flags)
{
	if (!allow_devmode_syscalls)
		return -EACCES;

	return sys_perf_event_open(attr_uptr, pid, cpu, group_fd, flags);
}

static asmlinkage long android_adjtimex(struct timex __user *buf)
{
	struct timex kbuf;

	/* adjtimex() is allowed only for read. */
	if (copy_from_user(&kbuf, buf, sizeof(struct timex)))
		return -EFAULT;
	if (kbuf.modes != 0)
		return -EPERM;
	return sys_adjtimex(buf);
}

static asmlinkage long android_clock_adjtime(const clockid_t which_clock,
					     struct timex __user *buf)
{
	struct timex kbuf;

	/* clock_adjtime() is allowed only for read. */
	if (copy_from_user(&kbuf, buf, sizeof(struct timex)))
		return -EFAULT;
	if (kbuf.modes != 0)
		return -EPERM;
	return sys_clock_adjtime(which_clock, buf);
}

static asmlinkage long android_getcpu(unsigned __user *cpu,
				      unsigned __user *node,
				      struct getcpu_cache __user *tcache)
{
	if (node || tcache)
		return -EPERM;
	return sys_getcpu(cpu, node, tcache);
}

static struct syscall_whitelist_entry android_whitelist[] = {
	SYSCALL_ENTRY_ALT(adjtimex, android_adjtimex),
	SYSCALL_ENTRY(brk),
	SYSCALL_ENTRY(capget),
	SYSCALL_ENTRY(capset),
	SYSCALL_ENTRY(chdir),
	SYSCALL_ENTRY_ALT(clock_adjtime, android_clock_adjtime),
	SYSCALL_ENTRY(clock_getres),
	SYSCALL_ENTRY(clock_gettime),
	SYSCALL_ENTRY(clock_nanosleep),
	SYSCALL_ENTRY(clock_settime),
	SYSCALL_ENTRY(clone),
	SYSCALL_ENTRY(close),
	SYSCALL_ENTRY(dup),
	SYSCALL_ENTRY(dup3),
	SYSCALL_ENTRY(epoll_create1),
	SYSCALL_ENTRY(epoll_ctl),
	SYSCALL_ENTRY(epoll_pwait),
	SYSCALL_ENTRY(eventfd2),
	SYSCALL_ENTRY(execve),
	SYSCALL_ENTRY(exit),
	SYSCALL_ENTRY(exit_group),
	SYSCALL_ENTRY(faccessat),
	SYSCALL_ENTRY(fallocate),
	SYSCALL_ENTRY(fchdir),
	SYSCALL_ENTRY(fchmod),
	SYSCALL_ENTRY(fchmodat),
	SYSCALL_ENTRY(fchownat),
	SYSCALL_ENTRY(fcntl),
	SYSCALL_ENTRY(fdatasync),
	SYSCALL_ENTRY(fgetxattr),
	SYSCALL_ENTRY(flistxattr),
	SYSCALL_ENTRY(flock),
	SYSCALL_ENTRY(fremovexattr),
	SYSCALL_ENTRY(fsetxattr),
	SYSCALL_ENTRY(fstat),
	SYSCALL_ENTRY(fstatfs),
	SYSCALL_ENTRY(fsync),
	SYSCALL_ENTRY(ftruncate),
	SYSCALL_ENTRY(futex),
	SYSCALL_ENTRY_ALT(getcpu, android_getcpu),
	SYSCALL_ENTRY(getcwd),
	SYSCALL_ENTRY(getdents64),
	SYSCALL_ENTRY(getpgid),
	SYSCALL_ENTRY(getpid),
	SYSCALL_ENTRY(getppid),
	SYSCALL_ENTRY_ALT(getpriority, android_getpriority),
	SYSCALL_ENTRY(getrandom),
	SYSCALL_ENTRY(getrlimit),
	SYSCALL_ENTRY(getrusage),
	SYSCALL_ENTRY(getsid),
	SYSCALL_ENTRY(gettid),
	SYSCALL_ENTRY(gettimeofday),
	SYSCALL_ENTRY(getxattr),
	SYSCALL_ENTRY(inotify_add_watch),
	SYSCALL_ENTRY(inotify_init1),
	SYSCALL_ENTRY(inotify_rm_watch),
	SYSCALL_ENTRY(ioctl),
	SYSCALL_ENTRY(io_destroy),
	SYSCALL_ENTRY(io_setup),
	SYSCALL_ENTRY(io_submit),
	SYSCALL_ENTRY(ioprio_set),
	SYSCALL_ENTRY(kill),
	SYSCALL_ENTRY(lgetxattr),
	SYSCALL_ENTRY(linkat),
	SYSCALL_ENTRY(listxattr),
	SYSCALL_ENTRY(llistxattr),
	SYSCALL_ENTRY(lremovexattr),
	SYSCALL_ENTRY(lseek),
	SYSCALL_ENTRY(lsetxattr),
	SYSCALL_ENTRY(madvise),
	SYSCALL_ENTRY(memfd_create),
	SYSCALL_ENTRY(mincore),
	SYSCALL_ENTRY(mkdirat),
	SYSCALL_ENTRY(mknodat),
	SYSCALL_ENTRY(mlock),
	SYSCALL_ENTRY(mlockall),
	SYSCALL_ENTRY(munlock),
	SYSCALL_ENTRY(munlockall),
	SYSCALL_ENTRY(mount),
	SYSCALL_ENTRY(mprotect),
	SYSCALL_ENTRY(mremap),
	SYSCALL_ENTRY(msync),
	SYSCALL_ENTRY(munmap),
	SYSCALL_ENTRY(name_to_handle_at),
	SYSCALL_ENTRY(nanosleep),
	SYSCALL_ENTRY(open_by_handle_at),
	SYSCALL_ENTRY(openat),
	SYSCALL_ENTRY_ALT(perf_event_open, android_perf_event_open),
	SYSCALL_ENTRY(personality),
	SYSCALL_ENTRY(pipe2),
	SYSCALL_ENTRY(ppoll),
	SYSCALL_ENTRY_ALT(prctl, alt_sys_prctl),
	SYSCALL_ENTRY(pread64),
	SYSCALL_ENTRY(preadv),
	SYSCALL_ENTRY(prlimit64),
	SYSCALL_ENTRY(process_vm_readv),
	SYSCALL_ENTRY(process_vm_writev),
	SYSCALL_ENTRY(pselect6),
	SYSCALL_ENTRY(ptrace),
	SYSCALL_ENTRY(pwrite64),
	SYSCALL_ENTRY(pwritev),
	SYSCALL_ENTRY(read),
	SYSCALL_ENTRY(readahead),
	SYSCALL_ENTRY(readv),
	SYSCALL_ENTRY(readlinkat),
	SYSCALL_ENTRY(recvmmsg),
	SYSCALL_ENTRY(remap_file_pages),
	SYSCALL_ENTRY(removexattr),
	SYSCALL_ENTRY(renameat),
	SYSCALL_ENTRY(restart_syscall),
	SYSCALL_ENTRY(rt_sigaction),
	SYSCALL_ENTRY(rt_sigpending),
	SYSCALL_ENTRY(rt_sigprocmask),
	SYSCALL_ENTRY(rt_sigqueueinfo),
	SYSCALL_ENTRY(rt_sigreturn),
	SYSCALL_ENTRY(rt_sigsuspend),
	SYSCALL_ENTRY(rt_sigtimedwait),
	SYSCALL_ENTRY(rt_tgsigqueueinfo),
	SYSCALL_ENTRY(sched_get_priority_max),
	SYSCALL_ENTRY(sched_get_priority_min),
	SYSCALL_ENTRY(sched_getaffinity),
	SYSCALL_ENTRY(sched_getparam),
	SYSCALL_ENTRY(sched_getscheduler),
	SYSCALL_ENTRY(sched_setaffinity),
	SYSCALL_ENTRY_ALT(sched_setparam, android_sched_setparam),
	SYSCALL_ENTRY_ALT(sched_setscheduler, android_sched_setscheduler),
	SYSCALL_ENTRY(sched_yield),
	SYSCALL_ENTRY(seccomp),
	SYSCALL_ENTRY(sendfile),
	SYSCALL_ENTRY(sendmmsg),
	SYSCALL_ENTRY(set_robust_list),
	SYSCALL_ENTRY(set_tid_address),
	SYSCALL_ENTRY(setdomainname),
	SYSCALL_ENTRY(setitimer),
	SYSCALL_ENTRY(setns),
	SYSCALL_ENTRY(setpgid),
	SYSCALL_ENTRY_ALT(setpriority, android_setpriority),
	SYSCALL_ENTRY(setrlimit),
	SYSCALL_ENTRY(setsid),
	SYSCALL_ENTRY(settimeofday),
	SYSCALL_ENTRY(setxattr),
	SYSCALL_ENTRY(signalfd4),
	SYSCALL_ENTRY(sigaltstack),
	SYSCALL_ENTRY(splice),
	SYSCALL_ENTRY(statfs),
	SYSCALL_ENTRY(symlinkat),
	SYSCALL_ENTRY(sysinfo),
	SYSCALL_ENTRY(syslog),
	SYSCALL_ENTRY(syncfs),
	SYSCALL_ENTRY(tee),
	SYSCALL_ENTRY(tgkill),
	SYSCALL_ENTRY(tkill),
	SYSCALL_ENTRY(timer_create),
	SYSCALL_ENTRY(timer_delete),
	SYSCALL_ENTRY(timer_gettime),
	SYSCALL_ENTRY(timer_getoverrun),
	SYSCALL_ENTRY(timer_settime),
	SYSCALL_ENTRY(timerfd_create),
	SYSCALL_ENTRY(timerfd_gettime),
	SYSCALL_ENTRY(timerfd_settime),
	SYSCALL_ENTRY(times),
	SYSCALL_ENTRY(truncate),
	SYSCALL_ENTRY(umask),
	SYSCALL_ENTRY(umount2),
	SYSCALL_ENTRY(uname),
	SYSCALL_ENTRY(unlinkat),
	SYSCALL_ENTRY(unshare),
	SYSCALL_ENTRY(utimensat),
	SYSCALL_ENTRY(vmsplice),
	SYSCALL_ENTRY(wait4),
	SYSCALL_ENTRY(waitid),
	SYSCALL_ENTRY(write),
	SYSCALL_ENTRY(writev),

	/*
	 * Deprecated syscalls which are not wired up on new architectures
	 * such as ARM64.
	 */
#ifndef CONFIG_ARM64
	SYSCALL_ENTRY(access),
	SYSCALL_ENTRY(chmod),
	SYSCALL_ENTRY(open),
	SYSCALL_ENTRY(creat),
	SYSCALL_ENTRY(dup2),
	SYSCALL_ENTRY(epoll_create),
	SYSCALL_ENTRY(epoll_wait),
	SYSCALL_ENTRY(eventfd),
	SYSCALL_ENTRY(fork),
	SYSCALL_ENTRY(futimesat),
	SYSCALL_ENTRY(getdents),
	SYSCALL_ENTRY(getpgrp),
	SYSCALL_ENTRY(inotify_init),
	SYSCALL_ENTRY(link),
	SYSCALL_ENTRY(lstat),
	SYSCALL_ENTRY(mkdir),
	SYSCALL_ENTRY(mknod),
	SYSCALL_ENTRY(pipe),
	SYSCALL_ENTRY(poll),
	SYSCALL_ENTRY(readlink),
	SYSCALL_ENTRY(rename),
	SYSCALL_ENTRY(rmdir),
	SYSCALL_ENTRY(stat),
	SYSCALL_ENTRY(symlink),
	SYSCALL_ENTRY(time),
	SYSCALL_ENTRY(unlink),
	SYSCALL_ENTRY(ustat),
	SYSCALL_ENTRY(utimes),
	SYSCALL_ENTRY(vfork),
#endif

	/*
	 * waitpid(2) is deprecated on most architectures, but still exists
	 * on IA32.
	 */
#ifdef CONFIG_X86_32
	SYSCALL_ENTRY(waitpid),
#endif

	/* IA32 uses the common socketcall(2) entrypoint for socket calls. */
#ifdef CONFIG_X86_32
	SYSCALL_ENTRY(socketcall),
#else
	SYSCALL_ENTRY(accept),
	SYSCALL_ENTRY(accept4),
	SYSCALL_ENTRY(bind),
	SYSCALL_ENTRY(connect),
	SYSCALL_ENTRY(getpeername),
	SYSCALL_ENTRY(getsockname),
	SYSCALL_ENTRY(getsockopt),
	SYSCALL_ENTRY(listen),
	SYSCALL_ENTRY(recvfrom),
	SYSCALL_ENTRY(recvmsg),
	SYSCALL_ENTRY(sendmsg),
	SYSCALL_ENTRY(sendto),
	SYSCALL_ENTRY(setsockopt),
	SYSCALL_ENTRY(shutdown),
	SYSCALL_ENTRY(socket),
	SYSCALL_ENTRY(socketpair),
	/*
	 * recv(2)/send(2) are officially deprecated, but their entry-points
	 * still exist on ARM.
	 */
#ifdef CONFIG_ARM
	SYSCALL_ENTRY(recv),
	SYSCALL_ENTRY(send),
#endif
#endif

	/*
	 * posix_fadvise(2) and sync_file_range(2) have ARM-specific wrappers
	 * to deal with register alignment.
	 */
#ifdef CONFIG_ARM
	SYSCALL_ENTRY(arm_fadvise64_64),
	SYSCALL_ENTRY(sync_file_range2),
#else
#ifdef CONFIG_X86_32
	SYSCALL_ENTRY(fadvise64_64),
#endif
	SYSCALL_ENTRY(fadvise64),
	SYSCALL_ENTRY(sync_file_range),
#endif

	/* 64-bit only syscalls. */
#if defined(CONFIG_X86_64) || defined(CONFIG_ARM64)
	SYSCALL_ENTRY(fchown),
	SYSCALL_ENTRY(getegid),
	SYSCALL_ENTRY(geteuid),
	SYSCALL_ENTRY(getgid),
	SYSCALL_ENTRY(getgroups),
	SYSCALL_ENTRY(getresgid),
	SYSCALL_ENTRY(getresuid),
	SYSCALL_ENTRY(getuid),
	SYSCALL_ENTRY(newfstatat),
	SYSCALL_ENTRY(mmap),
	SYSCALL_ENTRY(setgid),
	SYSCALL_ENTRY(setgroups),
	SYSCALL_ENTRY(setregid),
	SYSCALL_ENTRY(setresgid),
	SYSCALL_ENTRY(setresuid),
	SYSCALL_ENTRY(setreuid),
	SYSCALL_ENTRY(setuid),
	/*
	 * chown(2), lchown(2), and select(2) are deprecated and not wired up
	 * on ARM64.
	 */
#ifndef CONFIG_ARM64
	SYSCALL_ENTRY(chown),
	SYSCALL_ENTRY(lchown),
	SYSCALL_ENTRY(select),
#endif
#endif

	/* 32-bit only syscalls. */
#if defined(CONFIG_ARM) || defined(CONFIG_X86_32)
	SYSCALL_ENTRY(chown32),
	SYSCALL_ENTRY(fchown32),
	SYSCALL_ENTRY(fcntl64),
	SYSCALL_ENTRY(fstat64),
	SYSCALL_ENTRY(fstatat64),
	SYSCALL_ENTRY(fstatfs64),
	SYSCALL_ENTRY(ftruncate64),
	SYSCALL_ENTRY(getegid32),
	SYSCALL_ENTRY(geteuid32),
	SYSCALL_ENTRY(getgid32),
	SYSCALL_ENTRY(getgroups32),
	SYSCALL_ENTRY(getresgid32),
	SYSCALL_ENTRY(getresuid32),
	SYSCALL_ENTRY(getuid32),
	SYSCALL_ENTRY(lchown32),
	SYSCALL_ENTRY(lstat64),
	SYSCALL_ENTRY(mmap2),
	SYSCALL_ENTRY(_newselect),
	SYSCALL_ENTRY(_llseek),
	SYSCALL_ENTRY(sigaction),
	SYSCALL_ENTRY(sigpending),
	SYSCALL_ENTRY(sigprocmask),
	SYSCALL_ENTRY(sigreturn),
	SYSCALL_ENTRY(sigsuspend),
	SYSCALL_ENTRY(sendfile64),
	SYSCALL_ENTRY(setgid32),
	SYSCALL_ENTRY(setgroups32),
	SYSCALL_ENTRY(setregid32),
	SYSCALL_ENTRY(setresgid32),
	SYSCALL_ENTRY(setresuid32),
	SYSCALL_ENTRY(setreuid32),
	SYSCALL_ENTRY(setuid32),
	SYSCALL_ENTRY(stat64),
	SYSCALL_ENTRY(statfs64),
	SYSCALL_ENTRY(truncate64),
	SYSCALL_ENTRY(ugetrlimit),
#endif

	/* X86-specific syscalls. */
#ifdef CONFIG_X86
	SYSCALL_ENTRY(modify_ldt),
	SYSCALL_ENTRY(set_thread_area),
#endif

#ifdef CONFIG_X86_64
	SYSCALL_ENTRY(arch_prctl),
#endif

}; /* end android whitelist */

static struct syscall_whitelist_entry third_party_whitelist[] = {
	SYSCALL_ENTRY(brk),
	SYSCALL_ENTRY(chdir),
	SYSCALL_ENTRY(clock_gettime),
	SYSCALL_ENTRY(clone),
	SYSCALL_ENTRY(close),
	SYSCALL_ENTRY(dup),
	SYSCALL_ENTRY(execve),
	SYSCALL_ENTRY(exit),
	SYSCALL_ENTRY(exit_group),
	SYSCALL_ENTRY(fcntl),
	SYSCALL_ENTRY(fstat),
	SYSCALL_ENTRY(futex),
	SYSCALL_ENTRY(getcwd),
	SYSCALL_ENTRY(getdents64),
	SYSCALL_ENTRY(getpid),
	SYSCALL_ENTRY(getpgid),
	SYSCALL_ENTRY(getppid),
	SYSCALL_ENTRY(getpriority),
	SYSCALL_ENTRY(getrlimit),
	SYSCALL_ENTRY(getsid),
	SYSCALL_ENTRY(gettimeofday),
	SYSCALL_ENTRY(ioctl),
	SYSCALL_ENTRY(lseek),
	SYSCALL_ENTRY(madvise),
	SYSCALL_ENTRY(memfd_create),
	SYSCALL_ENTRY(mprotect),
	SYSCALL_ENTRY(munmap),
	SYSCALL_ENTRY(nanosleep),
	SYSCALL_ENTRY(openat),
	SYSCALL_ENTRY(prlimit64),
	SYSCALL_ENTRY(read),
	SYSCALL_ENTRY(rt_sigaction),
	SYSCALL_ENTRY(rt_sigprocmask),
	SYSCALL_ENTRY(rt_sigreturn),
	SYSCALL_ENTRY(sendfile),
	SYSCALL_ENTRY(set_robust_list),
	SYSCALL_ENTRY(set_tid_address),
	SYSCALL_ENTRY(setpgid),
	SYSCALL_ENTRY(setpriority),
	SYSCALL_ENTRY(setsid),
	SYSCALL_ENTRY(syslog),
	SYSCALL_ENTRY(statfs),
	SYSCALL_ENTRY(umask),
	SYSCALL_ENTRY(uname),
	SYSCALL_ENTRY(wait4),
	SYSCALL_ENTRY(write),
	SYSCALL_ENTRY(writev),

	/*
	 * Deprecated syscalls which are not wired up on new architectures
	 * such as ARM64.
	 */
#ifndef CONFIG_ARM64
	SYSCALL_ENTRY(access),
	SYSCALL_ENTRY(creat),
	SYSCALL_ENTRY(dup2),
	SYSCALL_ENTRY(getdents),
	SYSCALL_ENTRY(getpgrp),
	SYSCALL_ENTRY(lstat),
	SYSCALL_ENTRY(mkdir),
	SYSCALL_ENTRY(open),
	SYSCALL_ENTRY(pipe),
	SYSCALL_ENTRY(poll),
	SYSCALL_ENTRY(readlink),
	SYSCALL_ENTRY(stat),
	SYSCALL_ENTRY(unlink),
#endif

	/* 32-bit only syscalls. */
#if defined(CONFIG_ARM) || defined(CONFIG_X86_32)
	SYSCALL_ENTRY(fcntl64),
	SYSCALL_ENTRY(fstat64),
	SYSCALL_ENTRY(geteuid32),
	SYSCALL_ENTRY(getuid32),
	SYSCALL_ENTRY(_llseek),
	SYSCALL_ENTRY(lstat64),
	SYSCALL_ENTRY(_newselect),
	SYSCALL_ENTRY(mmap2),
	SYSCALL_ENTRY(stat64),
	SYSCALL_ENTRY(ugetrlimit),
#endif


	/* IA32 uses the common socketcall(2) entrypoint for socket calls. */
#ifdef CONFIG_X86_32
	SYSCALL_ENTRY(socketcall),
#else
	SYSCALL_ENTRY(accept),
	SYSCALL_ENTRY(bind),
	SYSCALL_ENTRY(connect),
	SYSCALL_ENTRY(listen),
	SYSCALL_ENTRY(recvfrom),
	SYSCALL_ENTRY(recvmsg),
	SYSCALL_ENTRY(sendmsg),
	SYSCALL_ENTRY(sendto),
	SYSCALL_ENTRY(setsockopt),
	SYSCALL_ENTRY(socket),
	SYSCALL_ENTRY(socketpair),
#endif

	/* 64-bit only syscalls. */
#if defined(CONFIG_X86_64) || defined(CONFIG_ARM64)
	SYSCALL_ENTRY(getegid),
	SYSCALL_ENTRY(geteuid),
	SYSCALL_ENTRY(getgid),
	SYSCALL_ENTRY(getuid),
	SYSCALL_ENTRY(mmap),
	SYSCALL_ENTRY(setgid),
	SYSCALL_ENTRY(setuid),
	/*
	 * chown(2), lchown(2), and select(2) are deprecated and not wired up
	 * on ARM64.
	 */
#ifndef CONFIG_ARM64
	SYSCALL_ENTRY(select),
#endif
#endif

	/* X86_64-specific syscalls. */
#ifdef CONFIG_X86_64
	SYSCALL_ENTRY(arch_prctl),
#endif
};


#ifdef CONFIG_COMPAT
static struct syscall_whitelist_entry read_write_test_compat_whitelist[] = {
	COMPAT_SYSCALL_ENTRY(exit),
	COMPAT_SYSCALL_ENTRY(open),
	COMPAT_SYSCALL_ENTRY(close),
	COMPAT_SYSCALL_ENTRY(read),
	COMPAT_SYSCALL_ENTRY(write),
	COMPAT_SYSCALL_ENTRY_ALT(prctl, alt_sys_prctl),
};

static asmlinkage long android_compat_adjtimex(struct compat_timex __user *buf)
{
	struct compat_timex kbuf;

	/* adjtimex() is allowed only for read. */
	if (copy_from_user(&kbuf, buf, sizeof(struct compat_timex)))
		return -EFAULT;
	if (kbuf.modes != 0)
		return -EPERM;
	return compat_sys_adjtimex(buf);
}

static asmlinkage long
android_compat_clock_adjtime(const clockid_t which_clock,
			     struct compat_timex __user *buf)
{
	struct compat_timex kbuf;

	/* clock_adjtime() is allowed only for read. */
	if (copy_from_user(&kbuf, buf, sizeof(struct compat_timex)))
		return -EFAULT;
	if (kbuf.modes != 0)
		return -EPERM;
	return compat_sys_clock_adjtime(which_clock, buf);
}

static struct syscall_whitelist_entry android_compat_whitelist[] = {
	COMPAT_SYSCALL_ENTRY(access),
	COMPAT_SYSCALL_ENTRY_ALT(adjtimex, android_compat_adjtimex),
	COMPAT_SYSCALL_ENTRY(brk),
	COMPAT_SYSCALL_ENTRY(capget),
	COMPAT_SYSCALL_ENTRY(capset),
	COMPAT_SYSCALL_ENTRY(chdir),
	COMPAT_SYSCALL_ENTRY(chmod),
	COMPAT_SYSCALL_ENTRY_ALT(clock_adjtime, android_compat_clock_adjtime),
	COMPAT_SYSCALL_ENTRY(clock_getres),
	COMPAT_SYSCALL_ENTRY(clock_gettime),
	COMPAT_SYSCALL_ENTRY(clock_nanosleep),
	COMPAT_SYSCALL_ENTRY(clock_settime),
	COMPAT_SYSCALL_ENTRY(clone),
	COMPAT_SYSCALL_ENTRY(close),
	COMPAT_SYSCALL_ENTRY(creat),
	COMPAT_SYSCALL_ENTRY(dup),
	COMPAT_SYSCALL_ENTRY(dup2),
	COMPAT_SYSCALL_ENTRY(dup3),
	COMPAT_SYSCALL_ENTRY(epoll_create),
	COMPAT_SYSCALL_ENTRY(epoll_create1),
	COMPAT_SYSCALL_ENTRY(epoll_ctl),
	COMPAT_SYSCALL_ENTRY(epoll_wait),
	COMPAT_SYSCALL_ENTRY(epoll_pwait),
	COMPAT_SYSCALL_ENTRY(eventfd),
	COMPAT_SYSCALL_ENTRY(eventfd2),
	COMPAT_SYSCALL_ENTRY(execve),
	COMPAT_SYSCALL_ENTRY(exit),
	COMPAT_SYSCALL_ENTRY(exit_group),
	COMPAT_SYSCALL_ENTRY(faccessat),
	COMPAT_SYSCALL_ENTRY(fallocate),
	COMPAT_SYSCALL_ENTRY(fchdir),
	COMPAT_SYSCALL_ENTRY(fchmod),
	COMPAT_SYSCALL_ENTRY(fchmodat),
	COMPAT_SYSCALL_ENTRY(fchownat),
	COMPAT_SYSCALL_ENTRY(fcntl),
	COMPAT_SYSCALL_ENTRY(fdatasync),
	COMPAT_SYSCALL_ENTRY(fgetxattr),
	COMPAT_SYSCALL_ENTRY(flistxattr),
	COMPAT_SYSCALL_ENTRY(flock),
	COMPAT_SYSCALL_ENTRY(fork),
	COMPAT_SYSCALL_ENTRY(fremovexattr),
	COMPAT_SYSCALL_ENTRY(fsetxattr),
	COMPAT_SYSCALL_ENTRY(fstat),
	COMPAT_SYSCALL_ENTRY(fstatfs),
	COMPAT_SYSCALL_ENTRY(fsync),
	COMPAT_SYSCALL_ENTRY(ftruncate),
	COMPAT_SYSCALL_ENTRY(futex),
	COMPAT_SYSCALL_ENTRY(futimesat),
	COMPAT_SYSCALL_ENTRY_ALT(getcpu, android_getcpu),
	COMPAT_SYSCALL_ENTRY(getcwd),
	COMPAT_SYSCALL_ENTRY(getdents),
	COMPAT_SYSCALL_ENTRY(getdents64),
	COMPAT_SYSCALL_ENTRY(getpgid),
	COMPAT_SYSCALL_ENTRY(getpgrp),
	COMPAT_SYSCALL_ENTRY(getpid),
	COMPAT_SYSCALL_ENTRY(getppid),
	COMPAT_SYSCALL_ENTRY_ALT(getpriority, android_getpriority),
	COMPAT_SYSCALL_ENTRY(getrandom),
	COMPAT_SYSCALL_ENTRY(getrusage),
	COMPAT_SYSCALL_ENTRY(getsid),
	COMPAT_SYSCALL_ENTRY(gettid),
	COMPAT_SYSCALL_ENTRY(gettimeofday),
	COMPAT_SYSCALL_ENTRY(getxattr),
	COMPAT_SYSCALL_ENTRY(inotify_add_watch),
	COMPAT_SYSCALL_ENTRY(inotify_init),
	COMPAT_SYSCALL_ENTRY(inotify_init1),
	COMPAT_SYSCALL_ENTRY(inotify_rm_watch),
	COMPAT_SYSCALL_ENTRY(io_destroy),
	COMPAT_SYSCALL_ENTRY(io_setup),
	COMPAT_SYSCALL_ENTRY(io_submit),
	COMPAT_SYSCALL_ENTRY(ioctl),
	COMPAT_SYSCALL_ENTRY(ioprio_set),
	COMPAT_SYSCALL_ENTRY(kill),
	COMPAT_SYSCALL_ENTRY(lgetxattr),
	COMPAT_SYSCALL_ENTRY(link),
	COMPAT_SYSCALL_ENTRY(linkat),
	COMPAT_SYSCALL_ENTRY(listxattr),
	COMPAT_SYSCALL_ENTRY(llistxattr),
	COMPAT_SYSCALL_ENTRY(lremovexattr),
	COMPAT_SYSCALL_ENTRY(lseek),
	COMPAT_SYSCALL_ENTRY(lsetxattr),
	COMPAT_SYSCALL_ENTRY(lstat),
	COMPAT_SYSCALL_ENTRY(madvise),
	COMPAT_SYSCALL_ENTRY(memfd_create),
	COMPAT_SYSCALL_ENTRY(mincore),
	COMPAT_SYSCALL_ENTRY(mkdir),
	COMPAT_SYSCALL_ENTRY(mkdirat),
	COMPAT_SYSCALL_ENTRY(mknod),
	COMPAT_SYSCALL_ENTRY(mknodat),
	COMPAT_SYSCALL_ENTRY(mlock),
	COMPAT_SYSCALL_ENTRY(mlockall),
	COMPAT_SYSCALL_ENTRY(munlock),
	COMPAT_SYSCALL_ENTRY(munlockall),
	COMPAT_SYSCALL_ENTRY(mount),
	COMPAT_SYSCALL_ENTRY(mprotect),
	COMPAT_SYSCALL_ENTRY(mremap),
	COMPAT_SYSCALL_ENTRY(msync),
	COMPAT_SYSCALL_ENTRY(munmap),
	COMPAT_SYSCALL_ENTRY(name_to_handle_at),
	COMPAT_SYSCALL_ENTRY(nanosleep),
	COMPAT_SYSCALL_ENTRY(open),
	COMPAT_SYSCALL_ENTRY(open_by_handle_at),
	COMPAT_SYSCALL_ENTRY(openat),
	COMPAT_SYSCALL_ENTRY_ALT(perf_event_open, android_perf_event_open),
	COMPAT_SYSCALL_ENTRY(personality),
	COMPAT_SYSCALL_ENTRY(pipe),
	COMPAT_SYSCALL_ENTRY(pipe2),
	COMPAT_SYSCALL_ENTRY(poll),
	COMPAT_SYSCALL_ENTRY(ppoll),
	COMPAT_SYSCALL_ENTRY_ALT(prctl, alt_sys_prctl),
	COMPAT_SYSCALL_ENTRY(pread64),
	COMPAT_SYSCALL_ENTRY(preadv),
	COMPAT_SYSCALL_ENTRY(prlimit64),
	COMPAT_SYSCALL_ENTRY(process_vm_readv),
	COMPAT_SYSCALL_ENTRY(process_vm_writev),
	COMPAT_SYSCALL_ENTRY(pselect6),
	COMPAT_SYSCALL_ENTRY(ptrace),
	COMPAT_SYSCALL_ENTRY(pwrite64),
	COMPAT_SYSCALL_ENTRY(pwritev),
	COMPAT_SYSCALL_ENTRY(read),
	COMPAT_SYSCALL_ENTRY(readahead),
	COMPAT_SYSCALL_ENTRY(readv),
	COMPAT_SYSCALL_ENTRY(readlink),
	COMPAT_SYSCALL_ENTRY(readlinkat),
	COMPAT_SYSCALL_ENTRY(recvmmsg),
	COMPAT_SYSCALL_ENTRY(remap_file_pages),
	COMPAT_SYSCALL_ENTRY(removexattr),
	COMPAT_SYSCALL_ENTRY(rename),
	COMPAT_SYSCALL_ENTRY(renameat),
	COMPAT_SYSCALL_ENTRY(restart_syscall),
	COMPAT_SYSCALL_ENTRY(rmdir),
	COMPAT_SYSCALL_ENTRY(rt_sigaction),
	COMPAT_SYSCALL_ENTRY(rt_sigpending),
	COMPAT_SYSCALL_ENTRY(rt_sigprocmask),
	COMPAT_SYSCALL_ENTRY(rt_sigqueueinfo),
	COMPAT_SYSCALL_ENTRY(rt_sigreturn),
	COMPAT_SYSCALL_ENTRY(rt_sigsuspend),
	COMPAT_SYSCALL_ENTRY(rt_sigtimedwait),
	COMPAT_SYSCALL_ENTRY(rt_tgsigqueueinfo),
	COMPAT_SYSCALL_ENTRY(sched_get_priority_max),
	COMPAT_SYSCALL_ENTRY(sched_get_priority_min),
	COMPAT_SYSCALL_ENTRY(sched_getaffinity),
	COMPAT_SYSCALL_ENTRY(sched_getparam),
	COMPAT_SYSCALL_ENTRY(sched_getscheduler),
	COMPAT_SYSCALL_ENTRY(sched_setaffinity),
	COMPAT_SYSCALL_ENTRY_ALT(sched_setparam,
				 android_sched_setparam),
	COMPAT_SYSCALL_ENTRY_ALT(sched_setscheduler,
				 android_sched_setscheduler),
	COMPAT_SYSCALL_ENTRY(sched_yield),
	COMPAT_SYSCALL_ENTRY(seccomp),
	COMPAT_SYSCALL_ENTRY(sendfile),
	COMPAT_SYSCALL_ENTRY(sendfile64),
	COMPAT_SYSCALL_ENTRY(sendmmsg),
	COMPAT_SYSCALL_ENTRY(set_robust_list),
	COMPAT_SYSCALL_ENTRY(set_tid_address),
	COMPAT_SYSCALL_ENTRY(setitimer),
	COMPAT_SYSCALL_ENTRY(setns),
	COMPAT_SYSCALL_ENTRY(setpgid),
	COMPAT_SYSCALL_ENTRY_ALT(setpriority, android_setpriority),
	COMPAT_SYSCALL_ENTRY(setrlimit),
	COMPAT_SYSCALL_ENTRY(setsid),
	COMPAT_SYSCALL_ENTRY(settimeofday),
	COMPAT_SYSCALL_ENTRY(setxattr),
	COMPAT_SYSCALL_ENTRY(signalfd4),
	COMPAT_SYSCALL_ENTRY(sigaltstack),
	COMPAT_SYSCALL_ENTRY(splice),
	COMPAT_SYSCALL_ENTRY(stat),
	COMPAT_SYSCALL_ENTRY(statfs),
	COMPAT_SYSCALL_ENTRY(symlink),
	COMPAT_SYSCALL_ENTRY(symlinkat),
	COMPAT_SYSCALL_ENTRY(sysinfo),
	COMPAT_SYSCALL_ENTRY(syslog),
	COMPAT_SYSCALL_ENTRY(tgkill),
	COMPAT_SYSCALL_ENTRY(tee),
	COMPAT_SYSCALL_ENTRY(tkill),
	COMPAT_SYSCALL_ENTRY(timer_create),
	COMPAT_SYSCALL_ENTRY(timer_delete),
	COMPAT_SYSCALL_ENTRY(timer_gettime),
	COMPAT_SYSCALL_ENTRY(timer_getoverrun),
	COMPAT_SYSCALL_ENTRY(timer_settime),
	COMPAT_SYSCALL_ENTRY(timerfd_create),
	COMPAT_SYSCALL_ENTRY(timerfd_gettime),
	COMPAT_SYSCALL_ENTRY(timerfd_settime),
	COMPAT_SYSCALL_ENTRY(times),
	COMPAT_SYSCALL_ENTRY(truncate),
	COMPAT_SYSCALL_ENTRY(umask),
	COMPAT_SYSCALL_ENTRY(umount2),
	COMPAT_SYSCALL_ENTRY(uname),
	COMPAT_SYSCALL_ENTRY(unlink),
	COMPAT_SYSCALL_ENTRY(unlinkat),
	COMPAT_SYSCALL_ENTRY(unshare),
	COMPAT_SYSCALL_ENTRY(ustat),
	COMPAT_SYSCALL_ENTRY(utimensat),
	COMPAT_SYSCALL_ENTRY(utimes),
	COMPAT_SYSCALL_ENTRY(vfork),
	COMPAT_SYSCALL_ENTRY(vmsplice),
	COMPAT_SYSCALL_ENTRY(wait4),
	COMPAT_SYSCALL_ENTRY(waitid),
	COMPAT_SYSCALL_ENTRY(write),
	COMPAT_SYSCALL_ENTRY(writev),
	COMPAT_SYSCALL_ENTRY(chown32),
	COMPAT_SYSCALL_ENTRY(fchown32),
	COMPAT_SYSCALL_ENTRY(fcntl64),
	COMPAT_SYSCALL_ENTRY(fstat64),
	COMPAT_SYSCALL_ENTRY(fstatat64),
	COMPAT_SYSCALL_ENTRY(fstatfs64),
	COMPAT_SYSCALL_ENTRY(ftruncate64),
	COMPAT_SYSCALL_ENTRY(getegid),
	COMPAT_SYSCALL_ENTRY(getegid32),
	COMPAT_SYSCALL_ENTRY(geteuid),
	COMPAT_SYSCALL_ENTRY(geteuid32),
	COMPAT_SYSCALL_ENTRY(getgid),
	COMPAT_SYSCALL_ENTRY(getgid32),
	COMPAT_SYSCALL_ENTRY(getgroups32),
	COMPAT_SYSCALL_ENTRY(getresgid32),
	COMPAT_SYSCALL_ENTRY(getresuid32),
	COMPAT_SYSCALL_ENTRY(getuid),
	COMPAT_SYSCALL_ENTRY(getuid32),
	COMPAT_SYSCALL_ENTRY(lchown32),
	COMPAT_SYSCALL_ENTRY(lstat64),
	COMPAT_SYSCALL_ENTRY(mmap2),
	COMPAT_SYSCALL_ENTRY(_newselect),
	COMPAT_SYSCALL_ENTRY(_llseek),
	COMPAT_SYSCALL_ENTRY(setdomainname),
	COMPAT_SYSCALL_ENTRY(sigaction),
	COMPAT_SYSCALL_ENTRY(sigpending),
	COMPAT_SYSCALL_ENTRY(sigprocmask),
	COMPAT_SYSCALL_ENTRY(sigreturn),
	COMPAT_SYSCALL_ENTRY(sigsuspend),
	COMPAT_SYSCALL_ENTRY(setgid32),
	COMPAT_SYSCALL_ENTRY(setgroups32),
	COMPAT_SYSCALL_ENTRY(setregid32),
	COMPAT_SYSCALL_ENTRY(setresgid32),
	COMPAT_SYSCALL_ENTRY(setresuid32),
	COMPAT_SYSCALL_ENTRY(setreuid32),
	COMPAT_SYSCALL_ENTRY(setuid32),
	COMPAT_SYSCALL_ENTRY(stat64),
	COMPAT_SYSCALL_ENTRY(statfs64),
	COMPAT_SYSCALL_ENTRY(syncfs),
	COMPAT_SYSCALL_ENTRY(truncate64),
	COMPAT_SYSCALL_ENTRY(ugetrlimit),

	/*
	 * waitpid(2) is deprecated on most architectures, but still exists
	 * on IA32.
	 */
#ifdef CONFIG_X86
	COMPAT_SYSCALL_ENTRY(waitpid),
#endif

	/*
	 * posix_fadvise(2) and sync_file_range(2) have ARM-specific wrappers
	 * to deal with register alignment.
	 */
#ifdef CONFIG_ARM64
	COMPAT_SYSCALL_ENTRY(arm_fadvise64_64),
	COMPAT_SYSCALL_ENTRY(sync_file_range2),
#else
	COMPAT_SYSCALL_ENTRY(fadvise64_64),
	COMPAT_SYSCALL_ENTRY(fadvise64),
	COMPAT_SYSCALL_ENTRY(sync_file_range),
#endif

	/* IA32 uses the common socketcall(2) entrypoint for socket calls. */
#ifdef CONFIG_X86
	COMPAT_SYSCALL_ENTRY(socketcall),
#else
	COMPAT_SYSCALL_ENTRY(accept),
	COMPAT_SYSCALL_ENTRY(accept4),
	COMPAT_SYSCALL_ENTRY(bind),
	COMPAT_SYSCALL_ENTRY(connect),
	COMPAT_SYSCALL_ENTRY(getpeername),
	COMPAT_SYSCALL_ENTRY(getsockname),
	COMPAT_SYSCALL_ENTRY(getsockopt),
	COMPAT_SYSCALL_ENTRY(listen),
	COMPAT_SYSCALL_ENTRY(recvfrom),
	COMPAT_SYSCALL_ENTRY(recvmsg),
	COMPAT_SYSCALL_ENTRY(sendmsg),
	COMPAT_SYSCALL_ENTRY(sendto),
	COMPAT_SYSCALL_ENTRY(setsockopt),
	COMPAT_SYSCALL_ENTRY(shutdown),
	COMPAT_SYSCALL_ENTRY(socket),
	COMPAT_SYSCALL_ENTRY(socketpair),
	COMPAT_SYSCALL_ENTRY(recv),
	COMPAT_SYSCALL_ENTRY(send),
#endif

	/*
	 * getrlimit(2) and time(2) are deprecated and not wired in the ARM
	 * compat table on ARM64.
	 */
#ifndef CONFIG_ARM64
	COMPAT_SYSCALL_ENTRY(getrlimit),
	COMPAT_SYSCALL_ENTRY(time),
#endif

	/* x86-specific syscalls. */
#ifdef CONFIG_X86
	COMPAT_SYSCALL_ENTRY(modify_ldt),
	COMPAT_SYSCALL_ENTRY(set_thread_area),
#endif
};

static struct syscall_whitelist_entry third_party_compat_whitelist[] = {
	COMPAT_SYSCALL_ENTRY(access),
	COMPAT_SYSCALL_ENTRY(brk),
	COMPAT_SYSCALL_ENTRY(chdir),
	COMPAT_SYSCALL_ENTRY(clock_gettime),
	COMPAT_SYSCALL_ENTRY(clone),
	COMPAT_SYSCALL_ENTRY(close),
	COMPAT_SYSCALL_ENTRY(creat),
	COMPAT_SYSCALL_ENTRY(dup),
	COMPAT_SYSCALL_ENTRY(dup2),
	COMPAT_SYSCALL_ENTRY(execve),
	COMPAT_SYSCALL_ENTRY(exit),
	COMPAT_SYSCALL_ENTRY(exit_group),
	COMPAT_SYSCALL_ENTRY(fcntl),
	COMPAT_SYSCALL_ENTRY(fcntl64),
	COMPAT_SYSCALL_ENTRY(fstat),
	COMPAT_SYSCALL_ENTRY(fstat64),
	COMPAT_SYSCALL_ENTRY(futex),
	COMPAT_SYSCALL_ENTRY(getcwd),
	COMPAT_SYSCALL_ENTRY(getdents),
	COMPAT_SYSCALL_ENTRY(getdents64),
	COMPAT_SYSCALL_ENTRY(getegid),
	COMPAT_SYSCALL_ENTRY(geteuid),
	COMPAT_SYSCALL_ENTRY(geteuid32),
	COMPAT_SYSCALL_ENTRY(getgid),
	COMPAT_SYSCALL_ENTRY(getpgid),
	COMPAT_SYSCALL_ENTRY(getpgrp),
	COMPAT_SYSCALL_ENTRY(getpid),
	COMPAT_SYSCALL_ENTRY(getpriority),
	COMPAT_SYSCALL_ENTRY(getppid),
	COMPAT_SYSCALL_ENTRY(getsid),
	COMPAT_SYSCALL_ENTRY(gettimeofday),
	COMPAT_SYSCALL_ENTRY(getuid),
	COMPAT_SYSCALL_ENTRY(getuid32),
	COMPAT_SYSCALL_ENTRY(ioctl),
	COMPAT_SYSCALL_ENTRY(_llseek),
	COMPAT_SYSCALL_ENTRY(lseek),
	COMPAT_SYSCALL_ENTRY(lstat),
	COMPAT_SYSCALL_ENTRY(lstat64),
	COMPAT_SYSCALL_ENTRY(madvise),
	COMPAT_SYSCALL_ENTRY(memfd_create),
	COMPAT_SYSCALL_ENTRY(mkdir),
	COMPAT_SYSCALL_ENTRY(mmap2),
	COMPAT_SYSCALL_ENTRY(mprotect),
	COMPAT_SYSCALL_ENTRY(munmap),
	COMPAT_SYSCALL_ENTRY(nanosleep),
	COMPAT_SYSCALL_ENTRY(_newselect),
	COMPAT_SYSCALL_ENTRY(open),
	COMPAT_SYSCALL_ENTRY(openat),
	COMPAT_SYSCALL_ENTRY(pipe),
	COMPAT_SYSCALL_ENTRY(poll),
	COMPAT_SYSCALL_ENTRY(prlimit64),
	COMPAT_SYSCALL_ENTRY(read),
	COMPAT_SYSCALL_ENTRY(readlink),
	COMPAT_SYSCALL_ENTRY(rt_sigaction),
	COMPAT_SYSCALL_ENTRY(rt_sigprocmask),
	COMPAT_SYSCALL_ENTRY(rt_sigreturn),
	COMPAT_SYSCALL_ENTRY(sendfile),
	COMPAT_SYSCALL_ENTRY(set_robust_list),
	COMPAT_SYSCALL_ENTRY(set_tid_address),
	COMPAT_SYSCALL_ENTRY(setgid32),
	COMPAT_SYSCALL_ENTRY(setuid32),
	COMPAT_SYSCALL_ENTRY(setpgid),
	COMPAT_SYSCALL_ENTRY(setpriority),
	COMPAT_SYSCALL_ENTRY(setsid),
	COMPAT_SYSCALL_ENTRY(stat),
	COMPAT_SYSCALL_ENTRY(stat64),
	COMPAT_SYSCALL_ENTRY(statfs),
	COMPAT_SYSCALL_ENTRY(syslog),
	COMPAT_SYSCALL_ENTRY(ugetrlimit),
	COMPAT_SYSCALL_ENTRY(umask),
	COMPAT_SYSCALL_ENTRY(uname),
	COMPAT_SYSCALL_ENTRY(unlink),
	COMPAT_SYSCALL_ENTRY(wait4),
	COMPAT_SYSCALL_ENTRY(write),
	COMPAT_SYSCALL_ENTRY(writev),

	/* IA32 uses the common socketcall(2) entrypoint for socket calls. */
#ifdef CONFIG_X86
	COMPAT_SYSCALL_ENTRY(socketcall),
#else
	COMPAT_SYSCALL_ENTRY(accept),
	COMPAT_SYSCALL_ENTRY(bind),
	COMPAT_SYSCALL_ENTRY(connect),
	COMPAT_SYSCALL_ENTRY(listen),
	COMPAT_SYSCALL_ENTRY(recvfrom),
	COMPAT_SYSCALL_ENTRY(recvmsg),
	COMPAT_SYSCALL_ENTRY(sendmsg),
	COMPAT_SYSCALL_ENTRY(sendto),
	COMPAT_SYSCALL_ENTRY(setsockopt),
	COMPAT_SYSCALL_ENTRY(socket),
	COMPAT_SYSCALL_ENTRY(socketpair),
#endif

	/*
	 * getrlimit(2) is deprecated and not wired in the ARM compat table
	 * on ARM64.
	 */
#ifndef CONFIG_ARM64
	COMPAT_SYSCALL_ENTRY(getrlimit),
#endif
};
#endif

static struct syscall_whitelist whitelists[] = {
	SYSCALL_WHITELIST(read_write_test),
	SYSCALL_WHITELIST(android),
	PERMISSIVE_SYSCALL_WHITELIST(android),
	SYSCALL_WHITELIST(third_party),
	PERMISSIVE_SYSCALL_WHITELIST(third_party)
};

static int alt_syscall_apply_whitelist(const struct syscall_whitelist *wl,
				       struct alt_sys_call_table *t)
{
	unsigned int i;
	DECLARE_BITMAP(whitelist, t->size);

	bitmap_zero(whitelist, t->size);
	for (i = 0; i < wl->nr_whitelist; i++) {
		unsigned int nr = wl->whitelist[i].nr;

		if (nr >= t->size)
			return -EINVAL;
		bitmap_set(whitelist, nr, 1);
		if (wl->whitelist[i].alt)
			t->table[nr] = wl->whitelist[i].alt;
	}

	for (i = 0; i < t->size; i++) {
		if (!test_bit(i, whitelist)) {
			t->table[i] = wl->permissive ?
				(sys_call_ptr_t)warn_syscall :
				(sys_call_ptr_t)block_syscall;
		}
	}

	return 0;
}

#ifdef CONFIG_COMPAT
static int
alt_syscall_apply_compat_whitelist(const struct syscall_whitelist *wl,
				   struct alt_sys_call_table *t)
{
	unsigned int i;
	DECLARE_BITMAP(whitelist, t->compat_size);

	bitmap_zero(whitelist, t->compat_size);
	for (i = 0; i < wl->nr_compat_whitelist; i++) {
		unsigned int nr = wl->compat_whitelist[i].nr;

		if (nr >= t->compat_size)
			return -EINVAL;
		bitmap_set(whitelist, nr, 1);
		if (wl->compat_whitelist[i].alt)
			t->compat_table[nr] = wl->compat_whitelist[i].alt;
	}

	for (i = 0; i < t->compat_size; i++) {
		if (!test_bit(i, whitelist)) {
			t->compat_table[i] = wl->permissive ?
				(sys_call_ptr_t)warn_compat_syscall :
				(sys_call_ptr_t)block_syscall;
		}
	}

	return 0;
}
#else
static inline int
alt_syscall_apply_compat_whitelist(const struct syscall_whitelist *wl,
				   struct alt_sys_call_table *t)
{
	return 0;
}
#endif

static int alt_syscall_init_one(const struct syscall_whitelist *wl)
{
	struct alt_sys_call_table *t;
	int err;

	t = kzalloc(sizeof(*t), GFP_KERNEL);
	if (!t)
		return -ENOMEM;
	strncpy(t->name, wl->name, sizeof(t->name));

	err = arch_dup_sys_call_table(t);
	if (err)
		return err;

	err = alt_syscall_apply_whitelist(wl, t);
	if (err)
		return err;
	err = alt_syscall_apply_compat_whitelist(wl, t);
	if (err)
		return err;

	return register_alt_sys_call_table(t);
}

/*
 * Register an alternate syscall table for each whitelist.  Note that the
 * lack of a module_exit() is intentional - once a syscall table is registered
 * it cannot be unregistered.
 *
 * TODO(abrestic) Support unregistering syscall tables?
 */
static int chromiumos_alt_syscall_init(void)
{
	unsigned int i;
	int err;

#ifdef CONFIG_SYSCTL
	if (!register_sysctl_paths(chromiumos_sysctl_path,
				   chromiumos_sysctl_table))
		pr_warn("Failed to register sysctl\n");
#endif

	err = arch_dup_sys_call_table(&default_table);
	if (err)
		return err;

	for (i = 0; i < ARRAY_SIZE(whitelists); i++) {
		err = alt_syscall_init_one(&whitelists[i]);
		if (err)
			pr_warn("Failed to register syscall table %s: %d\n",
				whitelists[i].name, err);
	}

	return 0;
}
module_init(chromiumos_alt_syscall_init);
