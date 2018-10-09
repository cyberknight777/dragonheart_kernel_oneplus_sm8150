subdir-$(CONFIG_SECURITY_CONTAINER_MONITOR) += nanopb

obj-$(CONFIG_SECURITY_CONTAINER_MONITOR) += nanopb/

ccflags-y := -I$(srctree)/security/container/protos \
	-I$(srctree)/security/container/protos/nanopb \
	-DPB_SYSTEM_HEADER=$(PB_SYSTEM_HEADER)
