#ifndef _LINUX_VIRTWL_H
#define _LINUX_VIRTWL_H

#include <asm/ioctl.h>

#define VIRTWL_SEND_MAX_ALLOCS 16

#define VIRTWL_IOCTL_BASE 'w'
#define VIRTWL_IO(nr)		_IO(VIRTWL_IOCTL_BASE, nr)
#define VIRTWL_IOR(nr, type)	_IOR(VIRTWL_IOCTL_BASE, nr, type)
#define VIRTWL_IOW(nr, type)	_IOW(VIRTWL_IOCTL_BASE, nr, type)
#define VIRTWL_IOWR(nr, type)	_IOWR(VIRTWL_IOCTL_BASE, nr, type)

enum virtwl_ioctl_new_type {
	VIRTWL_IOCTL_NEW_CTX, // struct virtwl_ioctl_new
	VIRTWL_IOCTL_NEW_ALLOC, // struct virtwl_ioctl_new_alloc
};

struct virtwl_ioctl_new {
	uint32_t type; // always 0
	int fd; // return fd
	uint32_t flags; // always 0
	size_t size; // only for VIRTWL_IOCTL_NEW_ALLOC
};

struct virtwl_ioctl_send {
	int fds[VIRTWL_SEND_MAX_ALLOCS];
	uint32_t len;
	uint8_t data[0];
};

struct virtwl_ioctl_recv {
	int fds[VIRTWL_SEND_MAX_ALLOCS];
	uint32_t len;
	uint8_t data[0];
};

#define VIRTWL_IOCTL_NEW VIRTWL_IOWR(0x00, struct virtwl_ioctl_new)
#define VIRTWL_IOCTL_SEND VIRTWL_IOR(0x01, struct virtwl_ioctl_send)
#define VIRTWL_IOCTL_RECV VIRTWL_IOW(0x02, struct virtwl_ioctl_recv)
#define VIRTWL_IOCTL_MAXNR 3

#endif /* _LINUX_VIRTWL_H */
