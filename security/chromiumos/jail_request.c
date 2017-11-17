/*
 * Allows processes to ask a userspace daemon what level of access
 * should be granted at file open-time.
 *
 * Copyright (C) 2016 Google, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/miscdevice.h>
#include <linux/mutex.h>
#include <linux/poll.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <uapi/linux/device_jail.h>

#include "jail_request.h"

#define JAIL_REQUEST_NAME "jail-request"

/*
 * If the state is IDLE, there is no pending request. Otherwise, there
 * is a request in progress. REQUEST_READY means the kernel is waiting
 * for userspace to read a request from the request device. REQUEST_SENT
 * means userspace has read the request and the kernel is waiting for
 * a response. RESULT_READY means userspace has responded and the kernel
 * can proceed with the open call.
 *
 * Generally we move from one state to the next in the order given below,
 * but the kernel may also reset the state to IDLE at any time if it is
 * interrupted, e.g. if the open call was aborted.
 */
static enum request_state {
	IDLE,
	REQUEST_READY,
	REQUEST_SENT,
	RESULT_READY,
} request_state;

/* The path to the device the kernel wants to open. */
static const char *request_path;

/*
 * The response from userspace for the level of access that should be
 * granted for the device at |request_path|.
 */
static enum jail_request_result result;

/* True if some program has the request device open. */
static bool userspace_connected;

/* wait on this to watch for changes to the above */
static DECLARE_WAIT_QUEUE_HEAD(request_wait);

/* protects all of the above */
static DEFINE_MUTEX(request_mutex);

static int jail_request_open(struct inode *inode, struct file *file)
{
	mutex_lock(&request_mutex);
	if (userspace_connected) {
		mutex_unlock(&request_mutex);
		return -EBUSY;
	}

	userspace_connected = true;
	wake_up(&request_wait);
	mutex_unlock(&request_mutex);
	return 0;
}

static int jail_request_release(struct inode *inode, struct file *file)
{
	mutex_lock(&request_mutex);
	userspace_connected = false;
	wake_up(&request_wait);
	mutex_unlock(&request_mutex);
	return 0;
}

/**
 * wait_for_state_locked - wait interruptibly until the state machine
 * reaches a particular state
 *
 * Call this with request_mutex locked. Returns 0 if the desired
 * state was reached, -EIO if some side hung up, and -EINTR
 * if the wait was interrupted.
 */
static int wait_for_state_locked(enum request_state wanted_state)
{
	bool interrupted = false;

	while (userspace_connected && !interrupted &&
	       request_state != wanted_state && request_state != IDLE) {
		mutex_unlock(&request_mutex);
		if (wait_event_interruptible(request_wait,
					     (!userspace_connected ||
					      request_state == wanted_state ||
					      request_state == IDLE)))
			interrupted = true;
		mutex_lock(&request_mutex);
	}

	if (!userspace_connected ||
	    (request_state == IDLE && wanted_state != IDLE))
		return -EIO;
	else if (interrupted)
		return -EINTR;

	return 0;
}

static ssize_t jail_request_read(struct file *file, char __user *buf,
				 size_t count, loff_t *ppos)
{
	int ret;

	mutex_lock(&request_mutex);
	ret = wait_for_state_locked(REQUEST_READY);
	if (ret) {
		mutex_unlock(&request_mutex);
		return ret;
	}

	ret = strnlen(request_path, count);
	if (copy_to_user(buf, request_path, ret)) {
		mutex_unlock(&request_mutex);
		return -EFAULT;
	}

	request_state = REQUEST_SENT;
	wake_up(&request_wait);
	mutex_unlock(&request_mutex);

	return ret;
}

static ssize_t jail_request_write(struct file *file, const char __user *buf,
				  size_t count, loff_t *ppos)
{
	int ret;

	if (count != sizeof(enum jail_request_result))
		return -EINVAL;

	mutex_lock(&request_mutex);
	ret = wait_for_state_locked(REQUEST_SENT);
	if (ret) {
		mutex_unlock(&request_mutex);
		return ret;
	}

	if (copy_from_user(&result, buf, sizeof(enum jail_request_result))) {
		mutex_unlock(&request_mutex);
		return -EFAULT;
	}

	request_state = RESULT_READY;
	wake_up(&request_wait);
	mutex_unlock(&request_mutex);
	return count;
}

static unsigned int jail_request_poll(struct file *file, poll_table *wait)
{
	unsigned int ret = 0;

	mutex_lock(&request_mutex);
	poll_wait(file, &request_wait, wait);
	if (request_state == REQUEST_READY)
		ret = POLLIN | POLLRDNORM;
	else if (request_state == REQUEST_SENT)
		ret = POLLOUT | POLLWRNORM;
	mutex_unlock(&request_mutex);

	return ret;
}

static const struct file_operations jail_request_fops = {
	.owner			= THIS_MODULE,
	.open			= jail_request_open,
	.release		= jail_request_release,
	.read			= jail_request_read,
	.write			= jail_request_write,
	.poll			= jail_request_poll,
	.llseek			= noop_llseek,
};

static struct miscdevice jail_request_dev = {
	.minor			= MISC_DYNAMIC_MINOR,
	.name			= JAIL_REQUEST_NAME,
	.fops			= &jail_request_fops,
};

enum jail_request_result request_access(const char *path)
{
	enum jail_request_result ret = JAIL_REQUEST_DENY;

	mutex_lock(&request_mutex);
	if (wait_for_state_locked(IDLE) < 0)
		goto done;

	request_path = path;
	request_state = REQUEST_READY;
	wake_up(&request_wait);

	if (wait_for_state_locked(RESULT_READY) < 0)
		goto done;

	ret = result;

done:
	request_state = IDLE;
	wake_up(&request_wait);
	mutex_unlock(&request_mutex);
	return ret;
}

int jail_request_setup(void)
{
	return misc_register(&jail_request_dev);
}

void jail_request_teardown(void)
{
	misc_deregister(&jail_request_dev);
}
