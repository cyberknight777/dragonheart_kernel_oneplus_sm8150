#ifndef _LINUX_VIRTIO_WL_H
#define _LINUX_VIRTIO_WL_H
/*
 * This header is BSD licensed so anyone can use the definitions to implement
 * compatible drivers/servers.
 */
#include <linux/virtio_ids.h>
#include <linux/virtio_config.h>
#include <linux/virtwl.h>

#define VIRTWL_IN_BUFFER_SIZE 4096
#define VIRTWL_OUT_BUFFER_SIZE 4096
#define VIRTWL_VQ_IN 0
#define VIRTWL_VQ_OUT 1
#define VIRTWL_QUEUE_COUNT 2
#define VIRTWL_MAX_ALLOC 0x800
#define VIRTWL_PFN_SHIFT 12

struct virtio_wl_config {
};

/*
 * The structure of each of these is virtio_wl_ctrl_hdr or one of its subclasses
 * where noted.
 */
enum virtio_wl_ctrl_type {
	VIRTIO_WL_CMD_VFD_NEW = 0x100, /* virtio_wl_ctrl_vfd_new */
	VIRTIO_WL_CMD_VFD_CLOSE, /* virtio_wl_ctrl_vfd */
	VIRTIO_WL_CMD_VFD_SEND, /* virtio_wl_ctrl_vfd_send + data */
	VIRTIO_WL_CMD_VFD_RECV, /* virtio_wl_ctrl_vfd_recv + data */
	VIRTIO_WL_CMD_VFD_NEW_CTX, /* virtio_wl_ctrl_vfd */

	VIRTIO_WL_RESP_OK = 0x1000,
	VIRTIO_WL_RESP_VFD_NEW = 0x1001, /* virtio_wl_ctrl_vfd_new */

	VIRTIO_WL_RESP_ERR = 0x1100,
	VIRTIO_WL_RESP_OUT_OF_MEMORY,
	VIRTIO_WL_RESP_INVALID_ID,
	VIRTIO_WL_RESP_INVALID_TYPE,
};

struct virtio_wl_ctrl_hdr {
	__le32 type; /* one of virtio_wl_ctrl_type */
	__le32 flags; /* always 0 */
};

enum virtio_wl_vfd_flags {
	VIRTIO_WL_VFD_WRITE = 0x1, /* mapped area is writable */
	VIRTIO_WL_VFD_MAP = 0x2, /* fixed size and mapped into a pfn range */
	VIRTIO_WL_VFD_CONTROL = 0x4, /* send/recv can transmit VFDs */
};

struct virtio_wl_ctrl_vfd {
	struct virtio_wl_ctrl_hdr hdr;
	__le32 vfd_id;
};

/*
 * If this command is sent to the guest, it indicates that the VFD has been
 * created and the fields indicate the properties of the VFD being offered.
 *
 * If this command is sent to the host, it represents a request to create a VFD
 * of the given properties. The pfn field is ignored by the host.
 */
struct virtio_wl_ctrl_vfd_new {
	struct virtio_wl_ctrl_hdr hdr;
	__le32 vfd_id; /* MSB indicates device allocated vfd */
	__le32 flags; /* virtio_wl_vfd_flags */
	__le64 pfn; /* first guest physical page frame number if VFD_MAP */
	__le32 size; /* size in bytes if VIRTIO_WL_VFD_MAP */
};

struct virtio_wl_ctrl_vfd_send {
	struct virtio_wl_ctrl_hdr hdr;
	__le32 vfd_id;
	__le32 vfd_count; /* struct is followed by this many IDs */
	/* the remainder is raw data */
};

struct virtio_wl_ctrl_vfd_recv {
	struct virtio_wl_ctrl_hdr hdr;
	__le32 vfd_id;
	__le32 vfd_count; /* struct is followed by this many IDs */
	/* the remainder is raw data */
};

#endif /* _LINUX_VIRTIO_WL_H */
