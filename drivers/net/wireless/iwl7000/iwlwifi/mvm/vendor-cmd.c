/******************************************************************************
 *
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 * redistributing this file, you may do so under either license.
 *
 * GPL LICENSE SUMMARY
 *
 * Copyright(c) 2012 - 2014 Intel Corporation. All rights reserved.
 * Copyright(c) 2013 - 2015 Intel Mobile Communications GmbH
 * Copyright(c) 2016 - 2017 Intel Deutschland GmbH
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110,
 * USA
 *
 * The full GNU General Public License is included in this distribution
 * in the file called COPYING.
 *
 * Contact Information:
 *  Intel Linux Wireless <linuxwifi@intel.com>
 * Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497
 *
 * BSD LICENSE
 *
 * Copyright(c) 2012 - 2014 Intel Corporation. All rights reserved.
 * Copyright(c) 2013 - 2015 Intel Mobile Communications GmbH
 * Copyright(c) 2016 - 2017 Intel Deutschland GmbH
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *  * Neither the name Intel Corporation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *****************************************************************************/
#include <linux/etherdevice.h>
#include <net/mac80211.h>
#include <net/netlink.h>
#include "mvm.h"
#include "iwl-vendor-cmd.h"

#include "iwl-io.h"
#include "iwl-prph.h"

static const struct nla_policy
iwl_mvm_vendor_attr_policy[NUM_IWL_MVM_VENDOR_ATTR] = {
	[IWL_MVM_VENDOR_ATTR_LOW_LATENCY] = { .type = NLA_FLAG },
	[IWL_MVM_VENDOR_ATTR_COUNTRY] = { .type = NLA_STRING, .len = 2 },
	[IWL_MVM_VENDOR_ATTR_FILTER_ARP_NA] = { .type = NLA_FLAG },
	[IWL_MVM_VENDOR_ATTR_FILTER_GTK] = { .type = NLA_FLAG },
	[IWL_MVM_VENDOR_ATTR_ADDR] = { .len = ETH_ALEN },
	[IWL_MVM_VENDOR_ATTR_TXP_LIMIT_24] = { .type = NLA_U32 },
	[IWL_MVM_VENDOR_ATTR_TXP_LIMIT_52L] = { .type = NLA_U32 },
	[IWL_MVM_VENDOR_ATTR_TXP_LIMIT_52H] = { .type = NLA_U32 },
	[IWL_MVM_VENDOR_ATTR_OPPPS_WA] = { .type = NLA_FLAG },
	[IWL_MVM_VENDOR_ATTR_GSCAN_MAC_ADDR] = { .len = ETH_ALEN },
	[IWL_MVM_VENDOR_ATTR_GSCAN_MAC_ADDR_MASK] = { .len = ETH_ALEN },
	[IWL_MVM_VENDOR_ATTR_GSCAN_MAX_AP_PER_SCAN] = { .type = NLA_U32 },
	[IWL_MVM_VENDOR_ATTR_GSCAN_REPORT_THRESHOLD] = { .type = NLA_U32 },
	[IWL_MVM_VENDOR_ATTR_GSCAN_BUCKET_SPECS] = { .type = NLA_NESTED },
	[IWL_MVM_VENDOR_ATTR_GSCAN_LOST_AP_SAMPLE_SIZE] = { .type = NLA_U8 },
	[IWL_MVM_VENDOR_ATTR_GSCAN_AP_LIST] = { .type = NLA_NESTED },
	[IWL_MVM_VENDOR_ATTR_GSCAN_RSSI_SAMPLE_SIZE] = { .type = NLA_U8 },
	[IWL_MVM_VENDOR_ATTR_GSCAN_MIN_BREACHING] = { .type = NLA_U8 },
	[IWL_MVM_VENDOR_ATTR_RXFILTER] = { .type = NLA_U32 },
	[IWL_MVM_VENDOR_ATTR_RXFILTER_OP] = { .type = NLA_U32 },
	[IWL_MVM_VENDOR_ATTR_DBG_COLLECT_TRIGGER] = { .type = NLA_STRING },
	[IWL_MVM_VENDOR_ATTR_NAN_FAW_FREQ] = { .type = NLA_U32 },
	[IWL_MVM_VENDOR_ATTR_NAN_FAW_SLOTS] = { .type = NLA_U8 },
	[IWL_MVM_VENDOR_ATTR_LQM_DURATION] = { .type = NLA_U32 },
	[IWL_MVM_VENDOR_ATTR_LQM_TIMEOUT] = { .type = NLA_U32 },
	[IWL_MVM_VENDOR_ATTR_GSCAN_REPORT_THRESHOLD_NUM] = { .type = NLA_U32 },
	[IWL_MVM_VENDOR_ATTR_SAR_CHAIN_A_PROFILE] = { .type = NLA_U8 },
	[IWL_MVM_VENDOR_ATTR_SAR_CHAIN_B_PROFILE] = { .type = NLA_U8 },
};

static int iwl_mvm_parse_vendor_data(struct nlattr **tb,
				     const void *data, int data_len)
{
	if (!data)
		return -EINVAL;

	return nla_parse(tb, MAX_IWL_MVM_VENDOR_ATTR, data, data_len,
			 iwl_mvm_vendor_attr_policy, NULL);
}

static int iwl_mvm_set_low_latency(struct wiphy *wiphy,
				   struct wireless_dev *wdev,
				   const void *data, int data_len)
{
	struct ieee80211_hw *hw = wiphy_to_ieee80211_hw(wiphy);
	struct iwl_mvm *mvm = IWL_MAC80211_GET_MVM(hw);
	struct nlattr *tb[NUM_IWL_MVM_VENDOR_ATTR];
	int err;
	struct ieee80211_vif *vif = wdev_to_ieee80211_vif(wdev);
	struct iwl_mvm_vif *mvmvif;
	bool prev;

	if (!vif)
		return -ENODEV;

	mvmvif = iwl_mvm_vif_from_mac80211(vif);

	err = iwl_mvm_parse_vendor_data(tb, data, data_len);
	if (err)
		return err;

	mutex_lock(&mvm->mutex);
	prev = iwl_mvm_vif_low_latency(mvmvif);
	mvmvif->low_latency_vcmd = tb[IWL_MVM_VENDOR_ATTR_LOW_LATENCY];
	err = iwl_mvm_update_low_latency(mvm, vif, prev);
	mutex_unlock(&mvm->mutex);

	return err;
}

static int iwl_mvm_get_low_latency(struct wiphy *wiphy,
				   struct wireless_dev *wdev,
				   const void *data, int data_len)
{
	struct ieee80211_vif *vif = wdev_to_ieee80211_vif(wdev);
	struct iwl_mvm_vif *mvmvif;
	struct sk_buff *skb;

	if (!vif)
		return -ENODEV;
	mvmvif = iwl_mvm_vif_from_mac80211(vif);

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 100);
	if (!skb)
		return -ENOMEM;
	if (iwl_mvm_vif_low_latency(mvmvif) &&
	    nla_put_flag(skb, IWL_MVM_VENDOR_ATTR_LOW_LATENCY)) {
		kfree_skb(skb);
		return -ENOBUFS;
	}

	return cfg80211_vendor_cmd_reply(skb);
}

static int iwl_mvm_set_country(struct wiphy *wiphy,
			       struct wireless_dev *wdev,
			       const void *data, int data_len)
{
	struct ieee80211_regdomain *regd;
	struct nlattr *tb[NUM_IWL_MVM_VENDOR_ATTR];
	struct ieee80211_hw *hw = wiphy_to_ieee80211_hw(wiphy);
	struct iwl_mvm *mvm = IWL_MAC80211_GET_MVM(hw);
	int retval;

	if (!iwl_mvm_is_lar_supported(mvm))
		return -EOPNOTSUPP;

	retval = iwl_mvm_parse_vendor_data(tb, data, data_len);
	if (retval)
		return retval;

	if (!tb[IWL_MVM_VENDOR_ATTR_COUNTRY])
		return -EINVAL;

	mutex_lock(&mvm->mutex);

	/* set regdomain information to FW */
	regd = iwl_mvm_get_regdomain(wiphy,
				     nla_data(tb[IWL_MVM_VENDOR_ATTR_COUNTRY]),
				     iwl_mvm_is_wifi_mcc_supported(mvm) ?
				     MCC_SOURCE_3G_LTE_HOST :
				     MCC_SOURCE_OLD_FW, NULL);
	if (IS_ERR_OR_NULL(regd)) {
		retval = -EIO;
		goto unlock;
	}

	retval = regulatory_set_wiphy_regd(wiphy, regd);
	kfree(regd);
unlock:
	mutex_unlock(&mvm->mutex);
	return retval;
}

static int iwl_vendor_frame_filter_cmd(struct wiphy *wiphy,
				       struct wireless_dev *wdev,
				       const void *data, int data_len)
{
	struct nlattr *tb[NUM_IWL_MVM_VENDOR_ATTR];
	struct ieee80211_vif *vif = wdev_to_ieee80211_vif(wdev);
	int err = iwl_mvm_parse_vendor_data(tb, data, data_len);

	if (err)
		return err;
	if (!vif)
		return -EINVAL;
	vif->filter_grat_arp_unsol_na =
		tb[IWL_MVM_VENDOR_ATTR_FILTER_ARP_NA];
	vif->filter_gtk = tb[IWL_MVM_VENDOR_ATTR_FILTER_GTK];

	return 0;
}

#ifdef CPTCFG_IWLMVM_TDLS_PEER_CACHE
static int iwl_vendor_tdls_peer_cache_add(struct wiphy *wiphy,
					  struct wireless_dev *wdev,
					  const void *data, int data_len)
{
	struct nlattr *tb[NUM_IWL_MVM_VENDOR_ATTR];
	struct ieee80211_hw *hw = wiphy_to_ieee80211_hw(wiphy);
	struct iwl_mvm *mvm = IWL_MAC80211_GET_MVM(hw);
	struct iwl_mvm_tdls_peer_counter *cnt;
	u8 *addr;
	struct ieee80211_vif *vif = wdev_to_ieee80211_vif(wdev);
	int err = iwl_mvm_parse_vendor_data(tb, data, data_len);

	if (err)
		return err;

	if (!vif)
		return -ENODEV;

	if (vif->type != NL80211_IFTYPE_STATION ||
	    !tb[IWL_MVM_VENDOR_ATTR_ADDR])
		return -EINVAL;

	mutex_lock(&mvm->mutex);
	if (mvm->tdls_peer_cache_cnt >= IWL_MVM_TDLS_CNT_MAX_PEERS) {
		err = -ENOSPC;
		goto out_unlock;
	}

	addr = nla_data(tb[IWL_MVM_VENDOR_ATTR_ADDR]);

	rcu_read_lock();
	cnt = iwl_mvm_tdls_peer_cache_find(mvm, addr);
	rcu_read_unlock();
	if (cnt) {
		err = -EEXIST;
		goto out_unlock;
	}

	cnt = kzalloc(sizeof(*cnt) +
		      sizeof(cnt->rx[0]) * mvm->trans->num_rx_queues,
		      GFP_KERNEL);
	if (!cnt) {
		err = -ENOMEM;
		goto out_unlock;
	}

	IWL_DEBUG_TDLS(mvm, "Adding %pM to TDLS peer cache\n", addr);
	ether_addr_copy(cnt->mac.addr, addr);
	cnt->vif = vif;
	list_add_tail_rcu(&cnt->list, &mvm->tdls_peer_cache_list);
	mvm->tdls_peer_cache_cnt++;

out_unlock:
	mutex_unlock(&mvm->mutex);
	return err;
}

static int iwl_vendor_tdls_peer_cache_del(struct wiphy *wiphy,
					  struct wireless_dev *wdev,
					  const void *data, int data_len)
{
	struct nlattr *tb[NUM_IWL_MVM_VENDOR_ATTR];
	struct ieee80211_hw *hw = wiphy_to_ieee80211_hw(wiphy);
	struct iwl_mvm *mvm = IWL_MAC80211_GET_MVM(hw);
	struct iwl_mvm_tdls_peer_counter *cnt;
	u8 *addr;
	int err = iwl_mvm_parse_vendor_data(tb, data, data_len);

	if (err)
		return err;

	if (!tb[IWL_MVM_VENDOR_ATTR_ADDR])
		return -EINVAL;

	addr = nla_data(tb[IWL_MVM_VENDOR_ATTR_ADDR]);

	mutex_lock(&mvm->mutex);
	rcu_read_lock();
	cnt = iwl_mvm_tdls_peer_cache_find(mvm, addr);
	if (!cnt) {
		IWL_DEBUG_TDLS(mvm, "%pM not found in TDLS peer cache\n", addr);
		err = -ENOENT;
		goto out_unlock;
	}

	IWL_DEBUG_TDLS(mvm, "Removing %pM from TDLS peer cache\n", addr);
	mvm->tdls_peer_cache_cnt--;
	list_del_rcu(&cnt->list);
	kfree_rcu(cnt, rcu_head);

out_unlock:
	rcu_read_unlock();
	mutex_unlock(&mvm->mutex);
	return err;
}

static int iwl_vendor_tdls_peer_cache_query(struct wiphy *wiphy,
					    struct wireless_dev *wdev,
					    const void *data, int data_len)
{
	struct nlattr *tb[NUM_IWL_MVM_VENDOR_ATTR];
	struct ieee80211_hw *hw = wiphy_to_ieee80211_hw(wiphy);
	struct iwl_mvm *mvm = IWL_MAC80211_GET_MVM(hw);
	struct iwl_mvm_tdls_peer_counter *cnt;
	struct sk_buff *skb;
	u32 rx_bytes, tx_bytes;
	u8 *addr;
	int err = iwl_mvm_parse_vendor_data(tb, data, data_len);

	if (err)
		return err;

	if (!tb[IWL_MVM_VENDOR_ATTR_ADDR])
		return -EINVAL;

	addr = nla_data(tb[IWL_MVM_VENDOR_ATTR_ADDR]);

	rcu_read_lock();
	cnt = iwl_mvm_tdls_peer_cache_find(mvm, addr);
	if (!cnt) {
		IWL_DEBUG_TDLS(mvm, "%pM not found in TDLS peer cache\n",
			       addr);
		err = -ENOENT;
	} else {
		int q;

		tx_bytes = cnt->tx_bytes;
		rx_bytes = 0;
		for (q = 0; q < mvm->trans->num_rx_queues; q++)
			rx_bytes += cnt->rx[q].bytes;
	}
	rcu_read_unlock();
	if (err)
		return err;

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 100);
	if (!skb)
		return -ENOMEM;
	if (nla_put_u32(skb, IWL_MVM_VENDOR_ATTR_TX_BYTES, tx_bytes) ||
	    nla_put_u32(skb, IWL_MVM_VENDOR_ATTR_RX_BYTES, rx_bytes)) {
		kfree_skb(skb);
		return -ENOBUFS;
	}

	return cfg80211_vendor_cmd_reply(skb);
}
#endif /* CPTCFG_IWLMVM_TDLS_PEER_CACHE */

static int iwl_vendor_set_nic_txpower_limit(struct wiphy *wiphy,
					    struct wireless_dev *wdev,
					    const void *data, int data_len)
{
	struct ieee80211_hw *hw = wiphy_to_ieee80211_hw(wiphy);
	struct iwl_mvm *mvm = IWL_MAC80211_GET_MVM(hw);
	struct iwl_dev_tx_power_cmd cmd = {
		.v3.set_mode = cpu_to_le32(IWL_TX_POWER_MODE_SET_DEVICE),
		.v3.dev_24 = cpu_to_le16(IWL_DEV_MAX_TX_POWER),
		.v3.dev_52_low = cpu_to_le16(IWL_DEV_MAX_TX_POWER),
		.v3.dev_52_high = cpu_to_le16(IWL_DEV_MAX_TX_POWER),
	};
	struct nlattr *tb[NUM_IWL_MVM_VENDOR_ATTR];
	int len = sizeof(cmd);
	int err;

	err = iwl_mvm_parse_vendor_data(tb, data, data_len);
	if (err)
		return err;

	if (tb[IWL_MVM_VENDOR_ATTR_TXP_LIMIT_24]) {
		s32 txp = nla_get_u32(tb[IWL_MVM_VENDOR_ATTR_TXP_LIMIT_24]);

		if (txp < 0 || txp > IWL_DEV_MAX_TX_POWER)
			return -EINVAL;
		cmd.v3.dev_24 = cpu_to_le16(txp);
	}

	if (tb[IWL_MVM_VENDOR_ATTR_TXP_LIMIT_52L]) {
		s32 txp = nla_get_u32(tb[IWL_MVM_VENDOR_ATTR_TXP_LIMIT_52L]);

		if (txp < 0 || txp > IWL_DEV_MAX_TX_POWER)
			return -EINVAL;
		cmd.v3.dev_52_low = cpu_to_le16(txp);
	}

	if (tb[IWL_MVM_VENDOR_ATTR_TXP_LIMIT_52H]) {
		s32 txp = nla_get_u32(tb[IWL_MVM_VENDOR_ATTR_TXP_LIMIT_52H]);

		if (txp < 0 || txp > IWL_DEV_MAX_TX_POWER)
			return -EINVAL;
		cmd.v3.dev_52_high = cpu_to_le16(txp);
	}

	mvm->txp_cmd = cmd;

	if (!fw_has_capa(&mvm->fw->ucode_capa, IWL_UCODE_TLV_CAPA_TX_POWER_ACK))
		len = sizeof(cmd.v3);

	mutex_lock(&mvm->mutex);
	err = iwl_mvm_send_cmd_pdu(mvm, REDUCE_TX_POWER_CMD, 0, len, &cmd);
	mutex_unlock(&mvm->mutex);

	if (err)
		IWL_ERR(mvm, "failed to update device TX power: %d\n", err);
	return 0;
}

#ifdef CPTCFG_IWLMVM_P2P_OPPPS_TEST_WA
static int iwl_mvm_oppps_wa_update_quota(struct iwl_mvm *mvm,
					 struct ieee80211_vif *vif,
					 bool enable)
{
	struct iwl_mvm_vif *mvmvif = iwl_mvm_vif_from_mac80211(vif);
	struct ieee80211_p2p_noa_attr *noa = &vif->bss_conf.p2p_noa_attr;
	bool force_update = true;

	if (enable && noa->oppps_ctwindow & IEEE80211_P2P_OPPPS_ENABLE_BIT)
		mvm->p2p_opps_test_wa_vif = mvmvif;
	else
		mvm->p2p_opps_test_wa_vif = NULL;
	return iwl_mvm_update_quotas(mvm, force_update, NULL);
}

static int iwl_mvm_oppps_wa(struct wiphy *wiphy,
			    struct wireless_dev *wdev,
			    const void *data, int data_len)
{
	struct ieee80211_hw *hw = wiphy_to_ieee80211_hw(wiphy);
	struct iwl_mvm *mvm = IWL_MAC80211_GET_MVM(hw);
	struct nlattr *tb[NUM_IWL_MVM_VENDOR_ATTR];
	int err = iwl_mvm_parse_vendor_data(tb, data, data_len);
	struct ieee80211_vif *vif = wdev_to_ieee80211_vif(wdev);

	if (err)
		return err;

	if (!vif)
		return -ENODEV;

	mutex_lock(&mvm->mutex);
	if (vif->type == NL80211_IFTYPE_STATION && vif->p2p) {
		bool enable = !!tb[IWL_MVM_VENDOR_ATTR_OPPPS_WA];

		err = iwl_mvm_oppps_wa_update_quota(mvm, vif, enable);
	}
	mutex_unlock(&mvm->mutex);

	return err;
}
#endif

void iwl_mvm_active_rx_filters(struct iwl_mvm *mvm)
{
	int i, len, total = 0;
	struct iwl_mcast_filter_cmd *cmd;
	static const u8 ipv4mc[] = {0x01, 0x00, 0x5e};
	static const u8 ipv6mc[] = {0x33, 0x33};
	static const u8 ipv4_mdns[] = {0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb};
	static const u8 ipv6_mdns[] = {0x33, 0x33, 0x00, 0x00, 0x00, 0xfb};

	lockdep_assert_held(&mvm->mutex);

	if (mvm->rx_filters & IWL_MVM_VENDOR_RXFILTER_EINVAL)
		return;

	for (i = 0; i < mvm->mcast_filter_cmd->count; i++) {
		if (mvm->rx_filters & IWL_MVM_VENDOR_RXFILTER_MCAST4 &&
		    memcmp(&mvm->mcast_filter_cmd->addr_list[i * ETH_ALEN],
			   ipv4mc, sizeof(ipv4mc)) == 0)
			total++;
		else if (memcmp(&mvm->mcast_filter_cmd->addr_list[i * ETH_ALEN],
				ipv4_mdns, sizeof(ipv4_mdns)) == 0)
			total++;
		else if (mvm->rx_filters & IWL_MVM_VENDOR_RXFILTER_MCAST6 &&
			 memcmp(&mvm->mcast_filter_cmd->addr_list[i * ETH_ALEN],
				ipv6mc, sizeof(ipv6mc)) == 0)
			total++;
		else if (memcmp(&mvm->mcast_filter_cmd->addr_list[i * ETH_ALEN],
				ipv6_mdns, sizeof(ipv6_mdns)) == 0)
			total++;
	}

	/* FW expects full words */
	len = roundup(sizeof(*cmd) + total * ETH_ALEN, 4);
	cmd = kzalloc(len, GFP_KERNEL);
	if (!cmd)
		return;

	memcpy(cmd, mvm->mcast_filter_cmd, sizeof(*cmd));
	cmd->count = 0;

	for (i = 0; i < mvm->mcast_filter_cmd->count; i++) {
		bool copy_filter = false;

		if (mvm->rx_filters & IWL_MVM_VENDOR_RXFILTER_MCAST4 &&
		    memcmp(&mvm->mcast_filter_cmd->addr_list[i * ETH_ALEN],
			   ipv4mc, sizeof(ipv4mc)) == 0)
			copy_filter = true;
		else if (memcmp(&mvm->mcast_filter_cmd->addr_list[i * ETH_ALEN],
				ipv4_mdns, sizeof(ipv4_mdns)) == 0)
			copy_filter = true;
		else if (mvm->rx_filters & IWL_MVM_VENDOR_RXFILTER_MCAST6 &&
			 memcmp(&mvm->mcast_filter_cmd->addr_list[i * ETH_ALEN],
				ipv6mc, sizeof(ipv6mc)) == 0)
			copy_filter = true;
		else if (memcmp(&mvm->mcast_filter_cmd->addr_list[i * ETH_ALEN],
				ipv6_mdns, sizeof(ipv6_mdns)) == 0)
			copy_filter = true;

		if (!copy_filter)
			continue;

		ether_addr_copy(&cmd->addr_list[cmd->count * ETH_ALEN],
				&mvm->mcast_filter_cmd->addr_list[i * ETH_ALEN]);
		cmd->count++;
	}

	kfree(mvm->mcast_active_filter_cmd);
	mvm->mcast_active_filter_cmd = cmd;
}

static int iwl_mvm_vendor_rxfilter(struct wiphy *wiphy,
				   struct wireless_dev *wdev,
				   const void *data, int data_len)
{
	struct nlattr *tb[NUM_IWL_MVM_VENDOR_ATTR];
	struct ieee80211_hw *hw = wiphy_to_ieee80211_hw(wiphy);
	struct iwl_mvm *mvm = IWL_MAC80211_GET_MVM(hw);
	enum iwl_mvm_vendor_rxfilter_flags filter, rx_filters, old_rx_filters;
	enum iwl_mvm_vendor_rxfilter_op op;
	bool first_set;
	u32 mask;
	int retval;

	retval = iwl_mvm_parse_vendor_data(tb, data, data_len);
	if (retval)
		return retval;

	if (!tb[IWL_MVM_VENDOR_ATTR_RXFILTER])
		return -EINVAL;

	if (!tb[IWL_MVM_VENDOR_ATTR_RXFILTER_OP])
		return -EINVAL;

	filter = nla_get_u32(tb[IWL_MVM_VENDOR_ATTR_RXFILTER]);
	op = nla_get_u32(tb[IWL_MVM_VENDOR_ATTR_RXFILTER_OP]);

	if (filter != IWL_MVM_VENDOR_RXFILTER_UNICAST &&
	    filter != IWL_MVM_VENDOR_RXFILTER_BCAST &&
	    filter != IWL_MVM_VENDOR_RXFILTER_MCAST4 &&
	    filter != IWL_MVM_VENDOR_RXFILTER_MCAST6)
		return -EINVAL;

	rx_filters = mvm->rx_filters & ~IWL_MVM_VENDOR_RXFILTER_EINVAL;
	switch (op) {
	case IWL_MVM_VENDOR_RXFILTER_OP_DROP:
		rx_filters &= ~filter;
		break;
	case IWL_MVM_VENDOR_RXFILTER_OP_PASS:
		rx_filters |= filter;
		break;
	default:
		return -EINVAL;
	}

	first_set = mvm->rx_filters & IWL_MVM_VENDOR_RXFILTER_EINVAL;

	/* If first time set - clear EINVAL value */
	mvm->rx_filters &= ~IWL_MVM_VENDOR_RXFILTER_EINVAL;

	if (rx_filters == mvm->rx_filters && !first_set)
		return 0;

	mutex_lock(&mvm->mutex);

	old_rx_filters = mvm->rx_filters;
	mvm->rx_filters = rx_filters;

	mask = IWL_MVM_VENDOR_RXFILTER_MCAST4 | IWL_MVM_VENDOR_RXFILTER_MCAST6;
	if ((old_rx_filters & mask) != (rx_filters & mask) || first_set) {
		iwl_mvm_active_rx_filters(mvm);
		iwl_mvm_recalc_multicast(mvm);
	}

	mask = IWL_MVM_VENDOR_RXFILTER_BCAST;
	if ((old_rx_filters & mask) != (rx_filters & mask) || first_set)
		iwl_mvm_configure_bcast_filter(mvm);

	mutex_unlock(&mvm->mutex);

	return 0;
}

static int iwl_mvm_vendor_dbg_collect(struct wiphy *wiphy,
				      struct wireless_dev *wdev,
				      const void *data, int data_len)
{
	struct ieee80211_hw *hw = wiphy_to_ieee80211_hw(wiphy);
	struct iwl_mvm *mvm = IWL_MAC80211_GET_MVM(hw);
	struct nlattr *tb[NUM_IWL_MVM_VENDOR_ATTR];
	int err, len = 0;
	const char *trigger_desc;

	err = iwl_mvm_parse_vendor_data(tb, data, data_len);
	if (err)
		return err;

	if (!tb[IWL_MVM_VENDOR_ATTR_DBG_COLLECT_TRIGGER])
		return -EINVAL;

	trigger_desc = nla_data(tb[IWL_MVM_VENDOR_ATTR_DBG_COLLECT_TRIGGER]);
	len = nla_len(tb[IWL_MVM_VENDOR_ATTR_DBG_COLLECT_TRIGGER]);

	iwl_fw_dbg_collect(&mvm->fwrt, FW_DBG_TRIGGER_USER_EXTENDED,
			   trigger_desc, len, NULL);

	return 0;
}

static int iwl_mvm_vendor_nan_faw_conf(struct wiphy *wiphy,
				       struct wireless_dev *wdev,
				       const void *data, int data_len)
{
	struct nlattr *tb[NUM_IWL_MVM_VENDOR_ATTR];
	struct ieee80211_hw *hw = wiphy_to_ieee80211_hw(wiphy);
	struct iwl_mvm *mvm = IWL_MAC80211_GET_MVM(hw);
	struct cfg80211_chan_def def = {};
	struct ieee80211_channel *chan;
	u32 freq;
	u8 slots;
	int retval;

	retval = iwl_mvm_parse_vendor_data(tb, data, data_len);
	if (retval)
		return retval;

	if (!tb[IWL_MVM_VENDOR_ATTR_NAN_FAW_SLOTS])
		return -EINVAL;

	if (!tb[IWL_MVM_VENDOR_ATTR_NAN_FAW_FREQ])
		return -EINVAL;

	freq = nla_get_u32(tb[IWL_MVM_VENDOR_ATTR_NAN_FAW_FREQ]);
	slots = nla_get_u8(tb[IWL_MVM_VENDOR_ATTR_NAN_FAW_SLOTS]);

	chan = ieee80211_get_channel(wiphy, freq);
	if (!chan)
		return -EINVAL;

	cfg80211_chandef_create(&def, chan, NL80211_CHAN_NO_HT);

	if (!cfg80211_chandef_usable(wiphy, &def, IEEE80211_CHAN_DISABLED))
		return -EINVAL;

	return iwl_mvm_nan_config_nan_faw_cmd(mvm, &def, slots);
}

static int iwl_mvm_vendor_link_quality_measurements(struct wiphy *wiphy,
						    struct wireless_dev *wdev,
						    const void *data,
						    int data_len)
{
	struct ieee80211_vif *vif = wdev_to_ieee80211_vif(wdev);
	struct iwl_mvm_vif *mvm_vif = iwl_mvm_vif_from_mac80211(vif);
	struct nlattr *tb[NUM_IWL_MVM_VENDOR_ATTR];
	u32 duration;
	u32 timeout;
	int retval;

	if (!vif)
		return -ENODEV;

	if (vif->type != NL80211_IFTYPE_STATION || vif->p2p ||
	    !vif->bss_conf.assoc)
		return -EINVAL;

	retval = iwl_mvm_parse_vendor_data(tb, data, data_len);
	if (retval)
		return retval;

	if (!tb[IWL_MVM_VENDOR_ATTR_LQM_DURATION] ||
	    !tb[IWL_MVM_VENDOR_ATTR_LQM_TIMEOUT])
		return -EINVAL;

	duration = nla_get_u32(tb[IWL_MVM_VENDOR_ATTR_LQM_DURATION]);
	timeout = nla_get_u32(tb[IWL_MVM_VENDOR_ATTR_LQM_TIMEOUT]);

	if (!mvm_vif)
		return -ENODEV;

	mutex_lock(&mvm_vif->mvm->mutex);
	retval = iwl_mvm_send_lqm_cmd(vif, LQM_CMD_OPERATION_START_MEASUREMENT,
				      duration, timeout);
	mutex_unlock(&mvm_vif->mvm->mutex);

	return retval;
}

#ifdef CONFIG_ACPI
static int iwl_mvm_vendor_set_dynamic_txp_profile(struct wiphy *wiphy,
						  struct wireless_dev *wdev,
						  const void *data,
						  int data_len)
{
	struct ieee80211_hw *hw = wiphy_to_ieee80211_hw(wiphy);
	struct iwl_mvm *mvm = IWL_MAC80211_GET_MVM(hw);
	struct nlattr *tb[NUM_IWL_MVM_VENDOR_ATTR];
	int ret;
	u8 chain_a, chain_b;

	ret = iwl_mvm_parse_vendor_data(tb, data, data_len);
	if (ret)
		return ret;

	if (!tb[IWL_MVM_VENDOR_ATTR_SAR_CHAIN_A_PROFILE] ||
	    !tb[IWL_MVM_VENDOR_ATTR_SAR_CHAIN_B_PROFILE])
		return -EINVAL;

	chain_a = nla_get_u8(tb[IWL_MVM_VENDOR_ATTR_SAR_CHAIN_A_PROFILE]);
	chain_b = nla_get_u8(tb[IWL_MVM_VENDOR_ATTR_SAR_CHAIN_B_PROFILE]);

	if (mvm->sar_chain_a_profile == chain_a &&
	    mvm->sar_chain_b_profile == chain_b)
		return 0;

	mvm->sar_chain_a_profile = chain_a;
	mvm->sar_chain_b_profile = chain_b;

	return iwl_mvm_sar_select_profile(mvm, chain_a, chain_b);
}

static int iwl_mvm_vendor_get_sar_profile_info(struct wiphy *wiphy,
					       struct wireless_dev *wdev,
					       const void *data,
					       int data_len)
{
	struct ieee80211_hw *hw = wiphy_to_ieee80211_hw(wiphy);
	struct iwl_mvm *mvm = IWL_MAC80211_GET_MVM(hw);
	struct sk_buff *skb;
	int i;
	u32 n_profiles = 0;

	for (i = 0; i < IWL_MVM_SAR_PROFILE_NUM; i++) {
		if (mvm->sar_profiles[i].enabled)
			n_profiles++;
	}

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 100);
	if (!skb)
		return -ENOMEM;
	if (nla_put_u8(skb, IWL_MVM_VENDOR_ATTR_SAR_ENABLED_PROFILE_NUM,
		       n_profiles) ||
	    nla_put_u8(skb, IWL_MVM_VENDOR_ATTR_SAR_CHAIN_A_PROFILE,
		       mvm->sar_chain_a_profile) ||
	    nla_put_u8(skb, IWL_MVM_VENDOR_ATTR_SAR_CHAIN_B_PROFILE,
		       mvm->sar_chain_b_profile)) {
		kfree_skb(skb);
		return -ENOBUFS;
	}

	return cfg80211_vendor_cmd_reply(skb);
}

#define IWL_MVM_SAR_GEO_NUM_BANDS	2

static int iwl_mvm_vendor_get_geo_profile_info(struct wiphy *wiphy,
					       struct wireless_dev *wdev,
					       const void *data,
					       int data_len)
{
	struct ieee80211_hw *hw = wiphy_to_ieee80211_hw(wiphy);
	struct iwl_mvm *mvm = IWL_MAC80211_GET_MVM(hw);
	struct sk_buff *skb;
	struct nlattr *nl_profile;
	int i, tbl_idx;

	tbl_idx = iwl_mvm_get_sar_geo_profile(mvm);
	if (tbl_idx < 0)
		return tbl_idx;

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 100);
	if (!skb)
		return -ENOMEM;

	nl_profile = nla_nest_start(skb, IWL_MVM_VENDOR_ATTR_SAR_GEO_PROFILE);
	if (!nl_profile) {
		kfree_skb(skb);
		return -ENOBUFS;
	}
	if (!tbl_idx)
		goto out;

	for (i = 0; i < IWL_MVM_SAR_GEO_NUM_BANDS; i++) {
		u8 *value;
		struct nlattr *nl_chain = nla_nest_start(skb, i + 1);
		int idx = i * IWL_GEO_PER_CHAIN_SIZE;

		if (!nl_chain) {
			kfree_skb(skb);
			return -ENOBUFS;
		}

		value =  &mvm->geo_profiles[tbl_idx - 1].values[idx];

		nla_put_u8(skb, IWL_VENDOR_SAR_GEO_MAX_TXP, value[0]);
		nla_put_u8(skb, IWL_VENDOR_SAR_GEO_CHAIN_A_OFFSET, value[1]);
		nla_put_u8(skb, IWL_VENDOR_SAR_GEO_CHAIN_B_OFFSET, value[2]);
		nla_nest_end(skb, nl_chain);
	}
out:
	nla_nest_end(skb, nl_profile);

	return cfg80211_vendor_cmd_reply(skb);
}
#endif

static const struct wiphy_vendor_command iwl_mvm_vendor_commands[] = {
	{
		.info = {
			.vendor_id = INTEL_OUI,
			.subcmd = IWL_MVM_VENDOR_CMD_SET_LOW_LATENCY,
		},
		.flags = WIPHY_VENDOR_CMD_NEED_NETDEV |
			 WIPHY_VENDOR_CMD_NEED_RUNNING,
		.doit = iwl_mvm_set_low_latency,
	},
	{
		.info = {
			.vendor_id = INTEL_OUI,
			.subcmd = IWL_MVM_VENDOR_CMD_GET_LOW_LATENCY,
		},
		.flags = WIPHY_VENDOR_CMD_NEED_NETDEV |
			 WIPHY_VENDOR_CMD_NEED_RUNNING,
		.doit = iwl_mvm_get_low_latency,
	},
	{
		.info = {
			.vendor_id = INTEL_OUI,
			.subcmd = IWL_MVM_VENDOR_CMD_SET_COUNTRY,
		},
		.flags = WIPHY_VENDOR_CMD_NEED_NETDEV |
			 WIPHY_VENDOR_CMD_NEED_RUNNING,
		.doit = iwl_mvm_set_country,
	},
	{
		.info = {
			.vendor_id = INTEL_OUI,
			.subcmd = IWL_MVM_VENDOR_CMD_PROXY_FRAME_FILTERING,
		},
		.flags = WIPHY_VENDOR_CMD_NEED_NETDEV |
			 WIPHY_VENDOR_CMD_NEED_RUNNING,
		.doit = iwl_vendor_frame_filter_cmd,
	},
#ifdef CPTCFG_IWLMVM_TDLS_PEER_CACHE
	{
		.info = {
			.vendor_id = INTEL_OUI,
			.subcmd = IWL_MVM_VENDOR_CMD_TDLS_PEER_CACHE_ADD,
		},
		.flags = WIPHY_VENDOR_CMD_NEED_NETDEV |
			 WIPHY_VENDOR_CMD_NEED_RUNNING,
		.doit = iwl_vendor_tdls_peer_cache_add,
	},
	{
		.info = {
			.vendor_id = INTEL_OUI,
			.subcmd = IWL_MVM_VENDOR_CMD_TDLS_PEER_CACHE_DEL,
		},
		.flags = WIPHY_VENDOR_CMD_NEED_NETDEV |
			 WIPHY_VENDOR_CMD_NEED_RUNNING,
		.doit = iwl_vendor_tdls_peer_cache_del,
	},
	{
		.info = {
			.vendor_id = INTEL_OUI,
			.subcmd = IWL_MVM_VENDOR_CMD_TDLS_PEER_CACHE_QUERY,
		},
		.flags = WIPHY_VENDOR_CMD_NEED_NETDEV |
			 WIPHY_VENDOR_CMD_NEED_RUNNING,
		.doit = iwl_vendor_tdls_peer_cache_query,
	},
#endif /* CPTCFG_IWLMVM_TDLS_PEER_CACHE */
	{
		.info = {
			.vendor_id = INTEL_OUI,
			.subcmd = IWL_MVM_VENDOR_CMD_SET_NIC_TXPOWER_LIMIT,
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV |
			 WIPHY_VENDOR_CMD_NEED_RUNNING,
		.doit = iwl_vendor_set_nic_txpower_limit,
	},
#ifdef CPTCFG_IWLMVM_P2P_OPPPS_TEST_WA
	{
		.info = {
			.vendor_id = INTEL_OUI,
			.subcmd = IWL_MVM_VENDOR_CMD_OPPPS_WA,
		},
		.flags = WIPHY_VENDOR_CMD_NEED_NETDEV |
			 WIPHY_VENDOR_CMD_NEED_RUNNING,
		.doit = iwl_mvm_oppps_wa,
	},
#endif
	{
		.info = {
			.vendor_id = INTEL_OUI,
			.subcmd = IWL_MVM_VENDOR_CMD_RXFILTER,
		},
		.flags = WIPHY_VENDOR_CMD_NEED_NETDEV |
			 WIPHY_VENDOR_CMD_NEED_RUNNING,
		.doit = iwl_mvm_vendor_rxfilter,
	},
	{
		.info = {
			.vendor_id = INTEL_OUI,
			.subcmd = IWL_MVM_VENDOR_CMD_DBG_COLLECT,
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV |
			 WIPHY_VENDOR_CMD_NEED_RUNNING,
		.doit = iwl_mvm_vendor_dbg_collect,
	},
	{
		.info = {
			.vendor_id = INTEL_OUI,

			.subcmd = IWL_MVM_VENDOR_CMD_NAN_FAW_CONF,
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV |
			 WIPHY_VENDOR_CMD_NEED_RUNNING,
		.doit = iwl_mvm_vendor_nan_faw_conf,
	},
	{
		.info = {
			.vendor_id = INTEL_OUI,
			.subcmd = IWL_MVM_VENDOR_CMD_QUALITY_MEASUREMENTS,
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV |
			 WIPHY_VENDOR_CMD_NEED_RUNNING,
		.doit = iwl_mvm_vendor_link_quality_measurements,
	},
#ifdef CONFIG_ACPI
	{
		.info = {
			.vendor_id = INTEL_OUI,
			.subcmd = IWL_MVM_VENDOR_CMD_SET_SAR_PROFILE,
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV,
		.doit = iwl_mvm_vendor_set_dynamic_txp_profile,
	},
	{
		.info = {
			.vendor_id = INTEL_OUI,
			.subcmd = IWL_MVM_VENDOR_CMD_GET_SAR_PROFILE_INFO,
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV,
		.doit = iwl_mvm_vendor_get_sar_profile_info,
	},
	{
		.info = {
			.vendor_id = INTEL_OUI,
			.subcmd = IWL_MVM_VENDOR_CMD_GET_SAR_GEO_PROFILE,
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV |
			 WIPHY_VENDOR_CMD_NEED_RUNNING,
		.doit = iwl_mvm_vendor_get_geo_profile_info,
	},
#endif
};

enum iwl_mvm_vendor_events_idx {
#ifdef CPTCFG_IWLMVM_TCM
	IWL_MVM_VENDOR_EVENT_IDX_TCM,
#endif
	IWL_MVM_VENDOR_EVENT_IDX_LQM,
	NUM_IWL_MVM_VENDOR_EVENT_IDX
};

static const struct nl80211_vendor_cmd_info
iwl_mvm_vendor_events[NUM_IWL_MVM_VENDOR_EVENT_IDX] = {
#ifdef CPTCFG_IWLMVM_TCM
	[IWL_MVM_VENDOR_EVENT_IDX_TCM] = {
		.vendor_id = INTEL_OUI,
		.subcmd = IWL_MVM_VENDOR_CMD_TCM_EVENT,
	},
#endif
	[IWL_MVM_VENDOR_EVENT_IDX_LQM] = {
		.vendor_id = INTEL_OUI,
		.subcmd = IWL_MVM_VENDOR_CMD_QUALITY_MEASUREMENTS,
	},
};

void iwl_mvm_set_wiphy_vendor_commands(struct wiphy *wiphy)
{
	wiphy->vendor_commands = iwl_mvm_vendor_commands;
	wiphy->n_vendor_commands = ARRAY_SIZE(iwl_mvm_vendor_commands);
	wiphy->vendor_events = iwl_mvm_vendor_events;
	wiphy->n_vendor_events = ARRAY_SIZE(iwl_mvm_vendor_events);
}

#ifdef CPTCFG_IWLMVM_TCM
void iwl_mvm_send_tcm_event(struct iwl_mvm *mvm, struct ieee80211_vif *vif)
{
	struct sk_buff *msg =
		cfg80211_vendor_event_alloc(mvm->hw->wiphy,
					    ieee80211_vif_to_wdev(vif),
					    200, IWL_MVM_VENDOR_EVENT_IDX_TCM,
					    GFP_ATOMIC);

	if (!msg)
		return;

	if (vif) {
		struct iwl_mvm_vif *mvmvif = iwl_mvm_vif_from_mac80211(vif);

		if (nla_put(msg, IWL_MVM_VENDOR_ATTR_VIF_ADDR,
			    ETH_ALEN, vif->addr) ||
		    nla_put_u8(msg, IWL_MVM_VENDOR_ATTR_VIF_LL,
			       iwl_mvm_vif_low_latency(mvmvif)) ||
		    nla_put_u8(msg, IWL_MVM_VENDOR_ATTR_VIF_LOAD,
			       mvm->tcm.result.load[mvmvif->id]))
			goto nla_put_failure;
	}

	if (nla_put_u8(msg, IWL_MVM_VENDOR_ATTR_LL, iwl_mvm_low_latency(mvm)) ||
	    nla_put_u8(msg, IWL_MVM_VENDOR_ATTR_LOAD,
		       mvm->tcm.result.global_load))
		goto nla_put_failure;

	cfg80211_vendor_event(msg, GFP_ATOMIC);
	return;

 nla_put_failure:
	kfree_skb(msg);
}
#endif

static int iwl_mvm_vendor_send_chandef(struct sk_buff *msg,
				       const struct cfg80211_chan_def *chandef)
{
	if (WARN_ON(!cfg80211_chandef_valid(chandef)))
		return -EINVAL;

	if (nla_put_u32(msg, IWL_MVM_VENDOR_ATTR_WIPHY_FREQ,
			chandef->chan->center_freq) ||
	   nla_put_u32(msg, IWL_MVM_VENDOR_ATTR_CHANNEL_WIDTH,
		       chandef->width) ||
	   nla_put_u32(msg, IWL_MVM_VENDOR_ATTR_CENTER_FREQ1,
		       chandef->center_freq1) ||
	   (chandef->center_freq2 &&
	    nla_put_u32(msg, IWL_MVM_VENDOR_ATTR_CENTER_FREQ2,
			chandef->center_freq2)))
		return -ENOBUFS;

	return 0;
}

void iwl_mvm_lqm_notif_iterator(void *_data, u8 *mac,
				struct ieee80211_vif *vif)
{
	struct iwl_link_qual_msrmnt_notif *report = _data;
	struct iwl_mvm_vif *mvm_vif = iwl_mvm_vif_from_mac80211(vif);
	struct nlattr *res, *air_time;
	struct sk_buff *msg;
	u32 status, num_sta;
	int i;

	if (mvm_vif->id != le32_to_cpu(report->mac_id))
		return;

	mvm_vif->lqm_active = false;

	msg = cfg80211_vendor_event_alloc(mvm_vif->mvm->hw->wiphy,
					  ieee80211_vif_to_wdev(vif), 2048,
					  IWL_MVM_VENDOR_EVENT_IDX_LQM,
					  GFP_ATOMIC);
	if (!msg)
		return;

	if (iwl_mvm_vendor_send_chandef(msg, &vif->bss_conf.chandef))
		goto nla_put_failure;

	res = nla_nest_start(msg, IWL_MVM_VENDOR_ATTR_LQM_RESULT);
	if (!res)
		goto nla_put_failure;

	status = le32_to_cpu(report->status);

	switch (status) {
	case LQM_STATUS_SUCCESS:
		status = IWL_MVM_VENDOR_LQM_STATUS_SUCCESS;
		break;
	case LQM_STATUS_TIMEOUT:
		status = IWL_MVM_VENDOR_LQM_STATUS_TIMEOUT;
		break;
	case LQM_STATUS_ABORT:
	default:
		status = IWL_MVM_VENDOR_LQM_STATUS_ABORT;
		break;
	}

	if (nla_put_u32(msg, IWL_MVM_VENDOR_ATTR_LQM_MEAS_STATUS,
			status) ||
	    nla_put_u32(msg, IWL_MVM_VENDOR_ATTR_LQM_RETRY_LIMIT,
			le32_to_cpu(report->tx_frame_dropped)) ||
	    nla_put_u32(msg, IWL_MVM_VENDOR_ATTR_LQM_MEAS_TIME,
			le32_to_cpu(report->time_in_measurement_window)) ||
	    nla_put_u32(msg, IWL_MVM_VENDOR_ATTR_LQM_OTHER_STA,
			le32_to_cpu(report->total_air_time_other_stations)))
		goto nla_put_failure;

	air_time = nla_nest_start(msg, IWL_MVM_VENDOR_ATTR_LQM_ACTIVE_STA_AIR_TIME);
	if (!air_time)
		goto nla_put_failure;

	num_sta = le32_to_cpu(report->number_of_stations);
	for (i = 0; i < num_sta; i++) {
		u32 sta_air_time =
			le32_to_cpu(report->frequent_stations_air_time[i]);

		if (nla_put_u32(msg, i, sta_air_time))
			goto nla_put_failure;
	}
	nla_nest_end(msg, air_time);
	nla_nest_end(msg, res);

	cfg80211_vendor_event(msg, GFP_ATOMIC);

	return;

nla_put_failure:
	kfree_skb(msg);
}

void iwl_mvm_vendor_lqm_notif(struct iwl_mvm *mvm,
			      struct iwl_rx_cmd_buffer *rxb)
{
	struct iwl_rx_packet *pkt = rxb_addr(rxb);
	struct iwl_link_qual_msrmnt_notif *report = (void *)pkt->data;

	ieee80211_iterate_active_interfaces_atomic(
		mvm->hw, IEEE80211_IFACE_ITER_NORMAL,
		iwl_mvm_lqm_notif_iterator, report);
}
