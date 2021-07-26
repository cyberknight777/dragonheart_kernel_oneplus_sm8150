#
# Makefile for the touchscreen drivers.
#

# Each configuration option enables a list of files.

obj-$(CONFIG_TOUCHPANEL_SYNAPTICS_S3706) += S3706/
obj-$(CONFIG_TOUCHPANEL_SYNAPTICS) += synaptics_touch_panel_remote.o
obj-$(CONFIG_TOUCHPANEL_SYNAPTICS) += synaptics_common.o
ifdef ($(CONFIG_TOUCHPANEL_SYNAPTICS_TEST),y)
subdir-cflags-y += -DCONFIG_TOUCHPANEL_SYNAPTICS_TEST
endif