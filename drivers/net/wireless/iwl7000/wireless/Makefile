obj-$(CPTCFG_CFG80211) += iwl7000_cfg80211.o

cfg80211-y += core.o sysfs.o radiotap.o util.o reg.o scan.o nl80211.o
cfg80211-y += mlme.o ibss.o sme.o chan.o ethtool.o mesh.o ap.o trace.o ocb.o
cfg80211-$(CONFIG_OF) += of.o
cfg80211-$(CPTCFG_CFG80211_DEBUGFS) += debugfs.o
cfg80211-$(CPTCFG_CFG80211_WEXT) += wext-compat.o wext-sme.o
cfg80211-$(CPTCFG_CFG80211_INTERNAL_REGDB) += regdb.o

CFLAGS_trace.o := -I$(src)

$(obj)/regdb.c: $(src)/db.txt $(src)/genregdb.awk
	@$(AWK) -f $(src)/genregdb.awk < $< > $@

clean-files := regdb.c

iwl7000_cfg80211-objs := $(cfg80211-objs) $(cfg80211-y) backports.o
