obj-$(CONFIG_SECURITY_CHROMIUMOS) := chromiumos_lsm.o

chromiumos_lsm-y := inode_mark.o lsm.o securityfs.o utils.o

obj-$(CONFIG_SECURITY_CHROMIUMOS_DEVICE_JAIL) += chromiumos_device_jail.o

chromiumos_device_jail-y := jail_control.o jail_device.o jail_request.o

obj-$(CONFIG_ALT_SYSCALL_CHROMIUMOS) += alt-syscall.o
