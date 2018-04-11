/******************************************************************************
 *
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 * redistributing this file, you may do so under either license.
 *
 * GPL LICENSE SUMMARY
 *
 * Copyright(c) 2015 - 2017 Intel Deutschland GmbH
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
 * Intel Linux Wireless <linuxwifi@intel.com>
 * Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497
 *
 * BSD LICENSE
 *
 * Copyright(c) 2015 - 2017 Intel Deutschland GmbH
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
#include <net/cfg80211.h>
#include <linux/etherdevice.h>
#include <linux/math64.h>
#include "mvm.h"
#include "iwl-io.h"
#include "iwl-prph.h"
#include "fw/api/tof.h"

#ifdef CPTCFG_IWLMVM_TOF_TSF_WA
static u32 tof_tsf_addr_hash(const void *key, u32 length, u32 seed)
{
	return jhash(key, ETH_ALEN, seed);
}

static const struct rhashtable_params tsf_rht_params = {
	.automatic_shrinking = true,
	.head_offset = offsetof(struct iwl_mvm_tof_tsf_entry, hash_node),
	.key_offset = offsetof(struct iwl_mvm_tof_tsf_entry, bssid),
	.key_len = ETH_ALEN,
	.hashfn = tof_tsf_addr_hash,
};
#endif

void iwl_mvm_tof_init(struct iwl_mvm *mvm)
{
	struct iwl_mvm_tof_data *tof_data = &mvm->tof_data;

	if (!fw_has_capa(&mvm->fw->ucode_capa, IWL_UCODE_TLV_CAPA_TOF_SUPPORT))
		return;

	memset(tof_data, 0, sizeof(*tof_data));

#ifdef CPTCFG_IWLWIFI_DEBUGFS
	if (IWL_MVM_TOF_IS_RESPONDER) {
		tof_data->responder_cfg.sta_id = IWL_MVM_INVALID_STA;
	}
#endif

	tof_data->range_req.req_timeout = 1;
	tof_data->range_req.initiator = 1;
	tof_data->range_req.report_policy = IWL_MVM_TOF_RESPONSE_COMPLETE;

	tof_data->range_req_ext.tsf_timer_offset_msec =
		cpu_to_le16(IWL_MVM_FTM_REQ_EXT_TSF_TIMER_OFFSET_MSEC_DFLT);
	tof_data->range_req_ext.min_delta_ftm =
		IWL_MVM_FTM_REQ_EXT_MIN_DELTA_FTM_DFLT;
	tof_data->range_req_ext.ftm_format_and_bw20M =
		IWL_MVM_FTM_REQ_EXT_FORMAT_AND_BW20M_DFLT;
	tof_data->range_req_ext.ftm_format_and_bw40M =
		IWL_MVM_FTM_REQ_EXT_FORMAT_AND_BW40M_DFLT;
	tof_data->range_req_ext.ftm_format_and_bw80M =
		IWL_MVM_FTM_REQ_EXT_FORMAT_AND_BW80M_DFLT;

	mvm->tof_data.active_request_id = IWL_MVM_TOF_RANGE_REQ_MAX_ID;
	mvm->tof_data.active_cookie = 0;
	mvm->tof_data.enable_dyn_ack = 1;

#ifdef CPTCFG_IWLMVM_TOF_TSF_WA
	{
		if (rhashtable_init(&tof_data->tsf_hash, &tsf_rht_params))
			IWL_ERR(mvm, "TSF hashtable init failed\n");
		else
			tof_data->tsf_hash_valid = true;
	}
#endif

	INIT_LIST_HEAD(&tof_data->lci_civic_info);
	mvm->init_status |= IWL_MVM_INIT_STATUS_TOF_INIT_COMPLETE;
}

#ifdef CPTCFG_IWLMVM_TOF_TSF_WA
void iwl_mvm_tof_update_tsf(struct iwl_mvm *mvm, struct iwl_rx_packet *pkt)
{
	u32 delta, ts;
	u8 delta_sign;
	struct iwl_mvm_tof_tsf_entry *tsf_entry;
	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *)(pkt->data +
					sizeof(struct iwl_rx_mpdu_res_start));
	struct ieee80211_mgmt *mgmt = (struct ieee80211_mgmt *)hdr;

	if (!mvm->tof_data.tsf_hash_valid)
		return;

	ts = (u32)le64_to_cpu(mgmt->u.beacon.timestamp);
	if (ts > le32_to_cpu(mvm->last_phy_info.system_timestamp)) {
		delta = ts - le32_to_cpu(mvm->last_phy_info.system_timestamp);
		delta_sign = 0;
	} else {
		delta = le32_to_cpu(mvm->last_phy_info.system_timestamp) - ts;
		delta_sign = 1;
	}

	/* try to find this bss in the hash table */
	tsf_entry = rhashtable_lookup_fast(&mvm->tof_data.tsf_hash,
					   hdr->addr3, tsf_rht_params);
	if (tsf_entry) {
		tsf_entry->delta = delta;
		tsf_entry->delta_sign = delta_sign;
		return;
	}

	/* the bss is not found in the hash table */
	tsf_entry = kmalloc(sizeof(*tsf_entry), GFP_ATOMIC);
	if (!tsf_entry)
		return;

	tsf_entry->delta = delta;
	tsf_entry->delta_sign = delta_sign;
	ether_addr_copy(tsf_entry->bssid, hdr->addr3);

	rhashtable_insert_fast(&mvm->tof_data.tsf_hash, &tsf_entry->hash_node,
			       tsf_rht_params);
}

static void iwl_mvm_tof_range_req_fill_tsf(struct iwl_mvm *mvm)
{
	int i;
	struct iwl_tof_range_req_cmd *cmd = &mvm->tof_data.range_req;
	struct iwl_mvm_tof_tsf_entry *tsf_entry;

	if (!mvm->tof_data.tsf_hash_valid)
		return;

	for (i = 0; i < cmd->num_of_ap; i++) {
		tsf_entry = rhashtable_lookup_fast(&mvm->tof_data.tsf_hash,
						   cmd->ap[i].bssid,
						   tsf_rht_params);
		if (tsf_entry) {
			cmd->ap[i].tsf_delta = cpu_to_le32(tsf_entry->delta);
			cmd->ap[i].tsf_delta_direction = tsf_entry->delta_sign;
		} else {
			IWL_INFO(mvm, "Cannot find BSSID %pM\n",
				 cmd->ap[i].bssid);
			cmd->ap[i].tsf_delta = 0;
			cmd->ap[i].tsf_delta_direction = 0;
		}
	}
}

static void iwl_mvm_tsf_hash_free_elem(void *ptr, void *arg)
{
	kfree(ptr);
}
#endif

static void iwl_mvm_tof_clean_lci_civic(struct iwl_mvm_tof_data *data)
{
	struct lci_civic_entry *cur, *prev;

	list_for_each_entry_safe(cur, prev, &data->lci_civic_info, list) {
		list_del(&cur->list);
		kfree(cur);
	}
}

static void iwl_mvm_tof_reset_active(struct iwl_mvm *mvm)
{
	mvm->tof_data.active_request_id = IWL_MVM_TOF_RANGE_REQ_MAX_ID;
	mvm->tof_data.active_cookie = 0;
	kfree(mvm->tof_data.active_request.targets);
	mvm->tof_data.active_request.targets = NULL;
	memset(&mvm->tof_data.active_bssid_for_tsf, 0, ETH_ALEN);
	iwl_mvm_tof_clean_lci_civic(&mvm->tof_data);
}

void iwl_mvm_tof_clean(struct iwl_mvm *mvm)
{
	struct iwl_mvm_tof_data *tof_data = &mvm->tof_data;

	if (!fw_has_capa(&mvm->fw->ucode_capa,
			 IWL_UCODE_TLV_CAPA_TOF_SUPPORT) ||
	    !(mvm->init_status & IWL_MVM_INIT_STATUS_TOF_INIT_COMPLETE))
		return;

#ifdef CPTCFG_IWLMVM_TOF_TSF_WA
	if (tof_data->tsf_hash_valid)
		rhashtable_free_and_destroy(&tof_data->tsf_hash,
					    iwl_mvm_tsf_hash_free_elem, NULL);
#endif

	kfree(tof_data->active_request.targets);
	iwl_mvm_tof_clean_lci_civic(tof_data);
	memset(tof_data, 0, sizeof(*tof_data));
	mvm->tof_data.active_request_id = IWL_MVM_TOF_RANGE_REQ_MAX_ID;
	mvm->init_status &= ~IWL_MVM_INIT_STATUS_TOF_INIT_COMPLETE;
}

static void iwl_tof_iterator(void *_data, u8 *mac,
			     struct ieee80211_vif *vif)
{
	bool *enabled = _data;

	/* non bss vif exists */
	if (ieee80211_vif_type_p2p(vif) !=  NL80211_IFTYPE_STATION)
		*enabled = false;
}

int iwl_mvm_tof_config_cmd(struct iwl_mvm *mvm)
{
	struct iwl_tof_config_cmd *cmd = &mvm->tof_data.tof_cfg;
	bool enabled;

	lockdep_assert_held(&mvm->mutex);

	if (!fw_has_capa(&mvm->fw->ucode_capa, IWL_UCODE_TLV_CAPA_TOF_SUPPORT))
		return -EINVAL;

	ieee80211_iterate_active_interfaces_atomic(mvm->hw,
						   IEEE80211_IFACE_ITER_NORMAL,
						   iwl_tof_iterator, &enabled);
	if (!enabled) {
		IWL_DEBUG_INFO(mvm, "ToF is not supported (non bss vif)\n");
		return -EINVAL;
	}

	mvm->tof_data.active_request_id = IWL_MVM_TOF_RANGE_REQ_MAX_ID;
	mvm->tof_data.active_cookie = 0;
	return iwl_mvm_send_cmd_pdu(mvm, iwl_cmd_id(TOF_CONFIG_CMD,
						    TOF_GROUP, 0),
				    0, sizeof(*cmd), cmd);
}

int iwl_mvm_tof_range_abort_cmd(struct iwl_mvm *mvm, u8 id)
{
	struct iwl_tof_range_abort_cmd cmd = {
		.request_id = id,
	};

	lockdep_assert_held(&mvm->mutex);

	IWL_DEBUG_INFO(mvm, "Sending ToF abort command\n");

	if (!fw_has_capa(&mvm->fw->ucode_capa,
			 IWL_UCODE_TLV_CAPA_TOF_SUPPORT)) {
		IWL_ERR(mvm, "%s: ToF is not supported!\n", __func__);
		return -EINVAL;
	}

	if (id != mvm->tof_data.active_request_id) {
		IWL_ERR(mvm, "Invalid range request id %d (active %d)\n",
			id, mvm->tof_data.active_request_id);
		return -EINVAL;
	}

	/* after abort is sent there's no active request anymore */
	iwl_mvm_tof_reset_active(mvm);

	return iwl_mvm_send_cmd_pdu(mvm, iwl_cmd_id(TOF_RANGE_ABORT_CMD,
						    TOF_GROUP, 0),
				    0, sizeof(cmd), &cmd);
}

/* Initializes responder_cfg command. (TOF_RESPONDER_CONFIG_CMD_API in FW) */
static void
iwl_mvm_tof_set_responder(struct iwl_mvm *mvm,
			  struct ieee80211_vif *vif,
			  struct cfg80211_ftm_responder_params *params,
			  struct cfg80211_chan_def *def)
{
	struct iwl_tof_responder_config_cmd *cmd = &mvm->tof_data.responder_cfg;

	memset(cmd, 0, sizeof(*cmd));

	cmd->channel_num = def->chan->hw_value;

	switch (def->width) {
	case NL80211_CHAN_WIDTH_20_NOHT:
		cmd->bandwidth = IWL_TOF_BW_20_LEGACY;
		break;
	case NL80211_CHAN_WIDTH_20:
		cmd->bandwidth = IWL_TOF_BW_20_HT;
		break;
	case NL80211_CHAN_WIDTH_40:
		cmd->bandwidth = IWL_TOF_BW_40;
		if (def->center_freq1 > def->chan->center_freq)
			cmd->ctrl_ch_position = 1;
		break;
	case NL80211_CHAN_WIDTH_80:
		cmd->bandwidth = IWL_TOF_BW_80;
		if (def->center_freq1 > def->chan->center_freq)
			cmd->ctrl_ch_position = 2;
		if (abs((int)def->center_freq1 -
			 (int)def->chan->center_freq) > 20)
			cmd->ctrl_ch_position += 1;
		break;
	default:
		WARN_ON(1);
	}

	cmd->cmd_valid_fields =
		cpu_to_le32(IWL_TOF_RESPONDER_CMD_VALID_CHAN_INFO |
			   /* ftm_resp_asap == true means asap ONLY mode,
			    * meaning non-ASAP not supported.
			    */
			   (iwlmvm_mod_params.ftm_resp_asap ?
			    0 : IWL_TOF_RESPONDER_CMD_VALID_NON_ASAP_SUPPORT));

	cmd->responder_cfg_flags =
		cpu_to_le32(iwlmvm_mod_params.ftm_resp_asap ?
			    0 : IWL_TOF_RESPONDER_FLAGS_NON_ASAP_SUPPORT);
}

int iwl_mvm_tof_responder_cmd(struct iwl_mvm *mvm,
			      struct ieee80211_vif *vif)
{
	struct iwl_tof_responder_config_cmd *cmd = &mvm->tof_data.responder_cfg;
	struct iwl_mvm_vif *mvmvif = iwl_mvm_vif_from_mac80211(vif);

	lockdep_assert_held(&mvm->mutex);

	if (!fw_has_capa(&mvm->fw->ucode_capa, IWL_UCODE_TLV_CAPA_TOF_SUPPORT))
		return -EINVAL;

	if (vif->p2p || vif->type != NL80211_IFTYPE_AP ||
	    !mvmvif->ap_ibss_active) {
		IWL_ERR(mvm, "Cannot start responder, not in AP mode\n");
		return -EIO;
	}

	/* sta_id and mac address are always present in the responder
	 * configuration cmd
	 */
	cmd->sta_id = mvmvif->bcast_sta.sta_id;
	memcpy(cmd->bssid, vif->addr, ETH_ALEN);
	cmd->cmd_valid_fields |= cpu_to_le32(
					IWL_TOF_RESPONDER_CMD_VALID_BSSID |
					IWL_TOF_RESPONDER_CMD_VALID_STA_ID);
	return iwl_mvm_send_cmd_pdu(mvm, iwl_cmd_id(TOF_RESPONDER_CONFIG_CMD,
						    TOF_GROUP, 0),
				    0, sizeof(*cmd), cmd);
}

static void
iwl_mvm_tof_set_responder_dyn(struct iwl_mvm *mvm,
			      struct ieee80211_vif *vif,
			      struct cfg80211_ftm_responder_params *params)
{
	struct iwl_tof_responder_dyn_config_cmd *cmd =
					&mvm->tof_data.responder_dyn_cfg;
	int aligned = ALIGN(params->lci_len + 2, 4);

	if (aligned + 2 + params->civic_len > IWL_TOF_LCI_CIVIC_BUF_SIZE)
		return;

	memset(cmd, 0, sizeof(*cmd));

	cmd->lci_len = cpu_to_le32(params->lci_len + 2);
	cmd->civic_len = cpu_to_le32(params->civic_len + 2);

	cmd->lci_civic[0] = WLAN_EID_MEASURE_REPORT;
	cmd->lci_civic[1] = params->lci_len;
	memcpy(cmd->lci_civic + 2, params->lci, params->lci_len);

	cmd->lci_civic[aligned] = WLAN_EID_MEASURE_REPORT;
	cmd->lci_civic[aligned + 1] = params->civic_len;
	memcpy(cmd->lci_civic + aligned + 2, params->civic, params->civic_len);
}

int iwl_mvm_tof_responder_dyn_cfg_cmd(struct iwl_mvm *mvm,
				struct ieee80211_vif *vif)
{
	struct iwl_tof_responder_dyn_config_cmd *cmd =
		&mvm->tof_data.responder_dyn_cfg;
	u32 actual_lci_len =
		ALIGN(le32_to_cpu(cmd->lci_len), 4);
	u32 actual_civic_len =
		ALIGN(le32_to_cpu(cmd->civic_len), 4);

	lockdep_assert_held(&mvm->mutex);

	if (!fw_has_capa(&mvm->fw->ucode_capa, IWL_UCODE_TLV_CAPA_TOF_SUPPORT))
		return -EINVAL;

	if (vif->p2p || vif->type != NL80211_IFTYPE_AP) {
		IWL_ERR(mvm, "Cannot start responder, not in AP mode\n");
		return -EIO;
	}

	return iwl_mvm_send_cmd_pdu(mvm,
				    iwl_cmd_id(TOF_RESPONDER_DYN_CONFIG_CMD,
					       TOF_GROUP, 0),
				    0, sizeof(*cmd) + actual_lci_len +
				    actual_civic_len, cmd);
}

int iwl_mvm_tof_start_responder(struct iwl_mvm *mvm,
				struct ieee80211_vif *vif,
				struct cfg80211_ftm_responder_params *params)
{
	struct ieee80211_chanctx_conf ctx, *pctx;
	u16 *phy_ctxt_id;
	struct iwl_mvm_phy_ctxt *phy_ctxt;
	int ret;

	lockdep_assert_held(&mvm->mutex);

	rcu_read_lock();
	pctx = rcu_dereference(vif->chanctx_conf);
	/* Copy the ctx to unlock the rcu and send the phy ctxt. We don't care
	 * about changes in the ctx after releasing the lock because the driver
	 * is still protected by the mutex. */
	ctx = *pctx;
	phy_ctxt_id  = (u16 *)pctx->drv_priv;
	rcu_read_unlock();

	phy_ctxt = &mvm->phy_ctxts[*phy_ctxt_id];
	ret = iwl_mvm_phy_ctxt_changed(mvm, phy_ctxt, &ctx.def,
				       ctx.rx_chains_static,
				       ctx.rx_chains_dynamic);
	if (ret)
		return ret;

	iwl_mvm_tof_set_responder(mvm, vif, params, &ctx.def);
	ret = iwl_mvm_tof_responder_cmd(mvm, vif);
	if (ret)
		return ret;

	if (params->lci_len || params->civic_len) {
		iwl_mvm_tof_set_responder_dyn(mvm, vif, params);
		ret = iwl_mvm_tof_responder_dyn_cfg_cmd(mvm, vif);
	}

	return ret;
}

void iwl_mvm_tof_restart_responder(struct iwl_mvm *mvm,
				   struct ieee80211_vif *vif)
{
	iwl_mvm_tof_responder_cmd(mvm, vif);
	if (mvm->tof_data.responder_dyn_cfg.lci_len ||
	    mvm->tof_data.responder_dyn_cfg.civic_len)
		iwl_mvm_tof_responder_dyn_cfg_cmd(mvm, vif);
}

int iwl_mvm_tof_perform_ftm(struct iwl_mvm *mvm, u64 cookie,
			    struct ieee80211_vif *vif,
			    struct cfg80211_ftm_request *req)
{
	struct iwl_tof_range_req_cmd *cmd = &mvm->tof_data.range_req;
	int i;
	int ret = 0;

	lockdep_assert_held(&mvm->mutex);

	/* nesting of range requests is not supported in FW */
	if (mvm->tof_data.active_request_id != IWL_MVM_TOF_RANGE_REQ_MAX_ID) {
		IWL_DEBUG_INFO(mvm,
			       "Cannot send range req, already active req %d\n",
			       mvm->tof_data.active_request_id);
		return -EBUSY;
	}

	/* FW requires sending the ext command prior to each range request */
	ret = iwl_mvm_tof_range_request_ext_cmd(mvm);
	if (ret)
		goto err;

	cmd->request_id++;
	if (cmd->request_id == 0)
		cmd->request_id++;
	cmd->one_sided_los_disable = 0;
	cmd->req_timeout = req->timeout;
	cmd->report_policy = IWL_MVM_TOF_RESPONSE_COMPLETE;
	cmd->num_of_ap = req->num_of_targets;
	cmd->macaddr_random = 1;
	memcpy(cmd->macaddr_template, req->macaddr_template, ETH_ALEN);
	for (i = 0; i < ETH_ALEN; i++)
		cmd->macaddr_mask[i] = ~req->macaddr_mask[i];

	memset(cmd->ap, 0, sizeof(cmd->ap));

	for (i = 0; i < cmd->num_of_ap; i++) {
		struct cfg80211_ftm_target *req_target = &req->targets[i];
		struct iwl_tof_range_req_ap_entry *cmd_target = &cmd->ap[i];

		cmd_target->channel_num = ieee80211_frequency_to_channel(
				req_target->chan_def.chan->center_freq);
		switch (req_target->chan_def.width) {
		case NL80211_CHAN_WIDTH_20_NOHT:
			cmd_target->bandwidth = IWL_TOF_BW_20_LEGACY;
			break;
		case NL80211_CHAN_WIDTH_20:
			cmd_target->bandwidth = IWL_TOF_BW_20_HT;
			break;
		case NL80211_CHAN_WIDTH_40:
			cmd_target->bandwidth = IWL_TOF_BW_40;
			break;
		case NL80211_CHAN_WIDTH_80:
			cmd_target->bandwidth = IWL_TOF_BW_80;
			break;
		default:
			IWL_ERR(mvm, "Unsupported BW in FTM request (%d)\n",
				req_target->chan_def.width);
			ret = -EINVAL;
			goto err;
		}
		cmd_target->ctrl_ch_position =
			(req_target->chan_def.width > NL80211_CHAN_WIDTH_20) ?
			iwl_mvm_get_ctrl_pos(&req_target->chan_def) : 0;

		cmd_target->tsf_delta_direction = 0;
		cmd_target->tsf_delta = 0;

		memcpy(cmd_target->bssid, req_target->bssid, ETH_ALEN);
		cmd_target->measure_type = req_target->one_sided;
		cmd_target->num_of_bursts = req_target->num_of_bursts_exp;
		cmd_target->burst_period =
			cpu_to_le16(req_target->burst_period);
		cmd_target->samples_per_burst = req_target->samples_per_burst;
		cmd_target->retries_per_sample = req_target->retries;
		cmd_target->asap_mode = req_target->asap;
		cmd_target->enable_dyn_ack = mvm->tof_data.enable_dyn_ack;
		cmd_target->rssi = 0;

		if (req_target->lci)
			cmd_target->location_req |= IWL_TOF_LOC_LCI;
		if (req_target->civic)
			cmd_target->location_req |= IWL_TOF_LOC_CIVIC;

		/* By default it's 0 - IWL_TOF_ALGO_TYPE_MAX_LIKE */
		cmd_target->algo_type = mvm->tof_data.tof_algo_type;
		cmd_target->notify_mcsi = IWL_TOF_MCSI_ENABLED;
	}

	mvm->tof_data.active_cookie = cookie;
	memcpy(&mvm->tof_data.active_request, req,
	       sizeof(struct cfg80211_ftm_request));
	mvm->tof_data.active_request.targets =
		kmemdup(req->targets, sizeof(struct cfg80211_ftm_target) *
			req->num_of_targets, GFP_KERNEL);
	if (!mvm->tof_data.active_request.targets) {
		ret = -ENOMEM;
		goto err;
	}
	if (vif->bss_conf.assoc && req->report_tsf)
		memcpy(mvm->tof_data.active_bssid_for_tsf, vif->bss_conf.bssid,
		       ETH_ALEN);

	if (vif->bss_conf.assoc)
		memcpy(cmd->range_req_bssid, vif->bss_conf.bssid, ETH_ALEN);
	else
		eth_broadcast_addr(cmd->range_req_bssid);

	return iwl_mvm_tof_range_request_cmd(mvm);

err:
	iwl_mvm_tof_reset_active(mvm);
	return ret;
}

int iwl_mvm_tof_abort_ftm(struct iwl_mvm *mvm, u64 cookie)
{
	lockdep_assert_held(&mvm->mutex);

	if (cookie != mvm->tof_data.active_cookie)
		return -EINVAL;

	return iwl_mvm_tof_range_abort_cmd(mvm,
					   mvm->tof_data.active_request_id);
}

static void iwl_mvm_debug_range_req(struct iwl_mvm *mvm)
{
	struct iwl_tof_range_req_cmd *req = &mvm->tof_data.range_req;
	int i;

	IWL_DEBUG_INFO(mvm, "Sending FTM request, params:\n");
	IWL_DEBUG_INFO(mvm, "\trequest id: %hhu\n", req->request_id);
	IWL_DEBUG_INFO(mvm, "\tinitiator: %hhu\n", req->initiator);
	IWL_DEBUG_INFO(mvm, "\tOSLD: %hhu\n", req->one_sided_los_disable);
	IWL_DEBUG_INFO(mvm, "\tTO: %hhu\n", req->req_timeout);
	IWL_DEBUG_INFO(mvm, "\treport policy: %hhu\n", req->report_policy);
	IWL_DEBUG_INFO(mvm, "\tnum of aps: %hhu\n", req->num_of_ap);
	IWL_DEBUG_INFO(mvm, "\tmac rand: %hhu\n", req->macaddr_random);
	IWL_DEBUG_INFO(mvm, "\tmac temp: %pM\n", req->macaddr_template);
	IWL_DEBUG_INFO(mvm, "\tmac mask: %pM\n", req->macaddr_mask);

	for (i = 0; i < req->num_of_ap; i++) {
		struct iwl_tof_range_req_ap_entry ap = req->ap[i];

		IWL_DEBUG_INFO(mvm, "ap[%d]:\n", i);
		IWL_DEBUG_INFO(mvm, "\tchannel: %hhu\n", ap.channel_num);
		IWL_DEBUG_INFO(mvm, "\tbw: %hhu\n", ap.bandwidth);
		IWL_DEBUG_INFO(mvm, "\ttsf delta direction: %hhu\n",
			       ap.tsf_delta);
		IWL_DEBUG_INFO(mvm, "\tctrl channel: %hhu\n",
			       ap.ctrl_ch_position);
		IWL_DEBUG_INFO(mvm, "\tbssid: %pM\n", ap.bssid);
		IWL_DEBUG_INFO(mvm, "\tone sided: %hhu\n", ap.measure_type);
		IWL_DEBUG_INFO(mvm, "\tnum of bursts: %hhu\n",
			       ap.num_of_bursts);
		IWL_DEBUG_INFO(mvm, "\tburst period: %hu\n",
			       le16_to_cpu(ap.burst_period));
		IWL_DEBUG_INFO(mvm, "\tsamples/burst: %hhu\n",
			       ap.samples_per_burst);
		IWL_DEBUG_INFO(mvm, "\tretries/sample: %hhu\n",
			       ap.retries_per_sample);
		IWL_DEBUG_INFO(mvm, "\ttsf delta: %u\n",
			       le32_to_cpu(ap.tsf_delta));
		IWL_DEBUG_INFO(mvm, "\tlocation: %hhu\n", ap.location_req);
		IWL_DEBUG_INFO(mvm, "\tasap: %hhu\n", ap.asap_mode);
		IWL_DEBUG_INFO(mvm, "\tdyn ack: %hhu\n", ap.enable_dyn_ack);
		IWL_DEBUG_INFO(mvm, "\trssi: %hhd\n", ap.rssi);
		IWL_DEBUG_INFO(mvm, "\tnotify MCSI: %hhu\n", ap.notify_mcsi);
	}
}

static int
iwl_tof_range_request_status_to_err(enum iwl_tof_range_request_status s)
{
	switch (s) {
	case IWL_TOF_RANGE_REQUEST_STATUS_SUCCESS:
		return 0;
	case IWL_TOF_RANGE_REQUEST_STATUS_BUSY:
		return -EBUSY;
	default:
		WARN_ON_ONCE(1);
		return -EIO;
	}
}

int iwl_mvm_tof_range_request_cmd(struct iwl_mvm *mvm)
{
	int err;
	u32 status;
	struct iwl_host_cmd cmd = {
		.id = iwl_cmd_id(TOF_RANGE_REQ_CMD, TOF_GROUP, 0),
		.len = { sizeof(mvm->tof_data.range_req), },
		/* no copy because of the command size */
		.dataflags = { IWL_HCMD_DFL_NOCOPY, },
	};

	lockdep_assert_held(&mvm->mutex);

	if (!fw_has_capa(&mvm->fw->ucode_capa, IWL_UCODE_TLV_CAPA_TOF_SUPPORT))
		return -EINVAL;

#ifdef CPTCFG_IWLMVM_TOF_TSF_WA
	iwl_mvm_tof_range_req_fill_tsf(mvm);
#endif
	mvm->tof_data.active_request_id = mvm->tof_data.range_req.request_id;

	cmd.data[0] = &mvm->tof_data.range_req;

	iwl_mvm_debug_range_req(mvm);

	status = 0;
	err = iwl_mvm_send_cmd_status(mvm, &cmd, &status);
	if (err) {
		IWL_ERR(mvm, "Failed to send ToF cmd! err: %d\n", err);
	} else if (status) {
		IWL_ERR(mvm, "ToF cmd failure! status: %u\n", status);
		err = iwl_tof_range_request_status_to_err(status);
	}
	if (err)
		iwl_mvm_tof_reset_active(mvm);

	return err;
}

int iwl_mvm_tof_range_request_ext_cmd(struct iwl_mvm *mvm)
{
	lockdep_assert_held(&mvm->mutex);

	if (!fw_has_capa(&mvm->fw->ucode_capa,
			 IWL_UCODE_TLV_CAPA_TOF_SUPPORT)) {
		IWL_ERR(mvm, "%s: ToF is not supported!\n", __func__);
		return -EINVAL;
	}

	return iwl_mvm_send_cmd_pdu(mvm, iwl_cmd_id(TOF_RANGE_REQ_EXT_CMD,
						    TOF_GROUP, 0),
				    0, sizeof(mvm->tof_data.range_req_ext),
				    &mvm->tof_data.range_req_ext);
}

static struct cfg80211_ftm_target *
iwl_mvm_tof_find_target_in_request(struct iwl_mvm *mvm, const u8 *bssid)
{
	int i;

	for (i = 0; i < mvm->tof_data.active_request.num_of_targets; i++)
		if (ether_addr_equal_unaligned(
		    mvm->tof_data.active_request.targets[i].bssid, bssid))
			return &mvm->tof_data.active_request.targets[i];

	return NULL;
}

#ifdef CPTCFG_IWLMVM_TOF_TSF_WA
static u64 iwl_mvm_tof_get_tsf(struct iwl_mvm *mvm, u32 gp2_ts)
{
	struct iwl_mvm_tof_tsf_entry *tsf_entry;
	u8 *bssid = mvm->tof_data.active_bssid_for_tsf;

	tsf_entry = rhashtable_lookup_fast(&mvm->tof_data.tsf_hash, bssid,
					   tsf_rht_params);
	if (!tsf_entry)
		return 0;

	if (tsf_entry->delta_sign)
		return (u64)gp2_ts - tsf_entry->delta;
	else
		return (u64)gp2_ts + tsf_entry->delta;
}
#endif

static u64 iwl_mvm_tof_get_host_time(struct iwl_mvm *mvm, u32 msrment_gp2_ts)
{
	u32 curr_gp2, diff;
	u64 now_from_boot_ns;

	iwl_mvm_get_sync_time(mvm, &curr_gp2, &now_from_boot_ns);

	if (curr_gp2 >= msrment_gp2_ts)
		diff = curr_gp2 - msrment_gp2_ts;
	else
		diff = curr_gp2 + (U32_MAX - msrment_gp2_ts + 1);

	return now_from_boot_ns - (u64)diff * 1000;
}

static inline enum rate_info_bw iwl_mvm_tof_fw_bw_to_rate_info_bw(u8 fw_bw)
{
	switch (fw_bw) {
	case 0:
		return RATE_INFO_BW_20;
	case 1:
		return RATE_INFO_BW_40;
	case 2:
		return RATE_INFO_BW_80;
	default:
		break;
	}

	return -1;
}

static inline int iwl_mvm_tof_is_ht(struct iwl_mvm *mvm, u8 fw_bw)
{
	switch (iwl_mvm_tof_fw_bw_to_rate_info_bw(fw_bw)) {
	case RATE_INFO_BW_20:
		return mvm->tof_data.range_req_ext.ftm_format_and_bw20M ==
			IEEE80211_FTM_FORMAT_BW_HT_20;
	case RATE_INFO_BW_40:
		return mvm->tof_data.range_req_ext.ftm_format_and_bw40M ==
			IEEE80211_FTM_FORMAT_BW_HT_40;
	default:
		break;
	}

	return 0;
}

static inline int iwl_mvm_tof_is_vht(struct iwl_mvm *mvm, u8 fw_bw)
{
	switch (iwl_mvm_tof_fw_bw_to_rate_info_bw(fw_bw)) {
	case RATE_INFO_BW_20:
		return mvm->tof_data.range_req_ext.ftm_format_and_bw20M ==
			IEEE80211_FTM_FORMAT_BW_VHT_20;
	case RATE_INFO_BW_40:
		return mvm->tof_data.range_req_ext.ftm_format_and_bw40M ==
			IEEE80211_FTM_FORMAT_BW_VHT_40;
	case RATE_INFO_BW_80:
		return mvm->tof_data.range_req_ext.ftm_format_and_bw80M ==
			IEEE80211_FTM_FORMAT_BW_VHT_80;
	default:
		break;
	}

	return 0;
}

static void iwl_mvm_debug_range_resp(struct iwl_mvm *mvm,
				     struct cfg80211_msrment_response *resp)
{
	u8 num_of_entries = resp->u.ftm.num_of_entries;
	int i;

	IWL_DEBUG_INFO(mvm, "Range response received\n");
	IWL_DEBUG_INFO(mvm, "status: %d, cookie: %lld, num of entries: %hhx\n",
		       resp->status, resp->cookie, num_of_entries);

	for (i = 0; i < num_of_entries; i++) {
		struct cfg80211_ftm_result *res = &resp->u.ftm.entries[i];

		IWL_DEBUG_INFO(mvm, "entry %d\n", i);
		IWL_DEBUG_INFO(mvm, "\tstatus: %d\n", res->status);
		IWL_DEBUG_INFO(mvm, "\tcomplete: %s\n",
			       res->complete ? "true" : "false");
		IWL_DEBUG_INFO(mvm, "\tBSSID: %pM\n", res->target->bssid);
		IWL_DEBUG_INFO(mvm, "\thost time: %llu\n", res->host_time);
		IWL_DEBUG_INFO(mvm, "\ttsf: %llu\n", res->tsf);
		IWL_DEBUG_INFO(mvm, "\tburst index: %hhu\n", res->burst_index);
		IWL_DEBUG_INFO(mvm, "\tmeasurement num: %u\n",
			       res->measurement_num);
		IWL_DEBUG_INFO(mvm, "\tsuccess num: %u\n", res->success_num);
		IWL_DEBUG_INFO(mvm, "\tnum per burst: %hhu\n",
			       res->num_per_burst);
		IWL_DEBUG_INFO(mvm, "\tretry after duration: %u\n",
			       res->retry_after_duration);
		IWL_DEBUG_INFO(mvm, "\tburst duration: %u\n",
			       res->burst_duration);
		IWL_DEBUG_INFO(mvm, "\tnegotiated burst: %u\n",
			       res->negotiated_burst_num);
		IWL_DEBUG_INFO(mvm, "\trssi: %hhd\n", res->rssi);
		IWL_DEBUG_INFO(mvm, "\trssi spread: %hhu\n", res->rssi_spread);
		IWL_DEBUG_INFO(mvm, "\trtt: %lld\n", res->rtt);
		IWL_DEBUG_INFO(mvm, "\trtt var: %llu\n", res->rtt_variance);
		IWL_DEBUG_INFO(mvm, "\trtt spread: %llu\n", res->rtt_spread);
		IWL_DEBUG_INFO(mvm, "\tdistance: %lld\n", res->distance);
		IWL_DEBUG_INFO(mvm, "\tdistance variance: %llu\n",
			       res->distance_variance);
		IWL_DEBUG_INFO(mvm, "\tdistance spread: %llu\n",
			       res->distance_spread);
		IWL_DEBUG_INFO(mvm, "\tfilled: %x\n", res->filled);
	}
}

static enum nl80211_msrment_status
iwl_mvm_get_msrment_status(enum iwl_tof_response_status status)
{
	switch (status) {
	case IWL_TOF_RESPONSE_SUCCESS:
		return NL80211_MSRMENT_STATUS_SUCCESS;
	case IWL_TOF_RESPONSE_TIMEOUT:
		return NL80211_MSRMENT_STATUS_TIMEOUT;
	case IWL_TOF_RESPONSE_ABORTED:
	default:
		return NL80211_MSRMENT_STATUS_FAIL;
	}
}

static enum nl80211_ftm_response_status
iwl_mvm_get_target_status(enum iwl_tof_entry_status status)
{
	switch (status) {
	case IWL_TOF_ENTRY_SUCCESS:
		return NL80211_FTM_RESP_SUCCESS;
	case IWL_TOF_ENTRY_TIMING_MEASURE_TIMEOUT:
		return NL80211_FTM_RESP_NOT_MEASURED;
	case IWL_TOF_ENTRY_NO_RESPONSE:
		return NL80211_FTM_RESP_TARGET_UNAVAILABLE;
	default:
		return NL80211_FTM_RESP_FAIL;
	}
}

static void iwl_mvm_get_lci_civic(struct iwl_mvm_tof_data *data,
				  struct cfg80211_ftm_result *res,
				  struct cfg80211_ftm_target *target)
{
	struct lci_civic_entry *entry;

	if (!target->lci && !target->civic)
		return;

	list_for_each_entry(entry, &data->lci_civic_info, list) {
		if (!ether_addr_equal_unaligned(target->bssid, entry->bssid))
			continue;

		if (entry->lci_len && target->lci) {
			res->lci_len = entry->lci_len;
			res->lci = entry->buf;
			res->filled |= BIT(NL80211_FTM_RESP_ENTRY_ATTR_LCI);
		}

		if (entry->civic_len && target->civic) {
			res->civic_len = entry->civic_len;
			res->civic = entry->buf + entry->lci_len;
			res->filled |= BIT(NL80211_FTM_RESP_ENTRY_ATTR_CIVIC);
		}

		break;
	}
}

/* Speed of light in cm/nanosec. Though RTT is in picosec units, calculations
 * are done using nanosec, in order to avoid floating point usage.
 */
#define SOL_CM_NSEC 30

void iwl_mvm_tof_range_resp(struct iwl_mvm *mvm,
			    struct iwl_rx_cmd_buffer *rxb)
{
	struct iwl_rx_packet *pkt = rxb_addr(rxb);
	struct iwl_tof_range_rsp_ntfy *fw_resp = (void *)pkt->data;
	struct cfg80211_msrment_response user_resp = {0};
	int i;

	lockdep_assert_held(&mvm->mutex);

	if (fw_resp->request_id != mvm->tof_data.active_request_id) {
		IWL_ERR(mvm, "Request id mismatch, got %d, active %d\n",
			fw_resp->request_id,
			mvm->tof_data.active_request_id);
		return;
	}

	if (fw_resp->num_of_aps > mvm->tof_data.active_request.num_of_targets) {
		IWL_ERR(mvm, "FTM range response invalid\n");
		return;
	}

	user_resp.cookie = mvm->tof_data.active_cookie;
	user_resp.type = NL80211_MSRMENT_TYPE_FTM;
	user_resp.status = iwl_mvm_get_msrment_status(fw_resp->request_status);
	user_resp.u.ftm.num_of_entries = fw_resp->num_of_aps;
	user_resp.u.ftm.entries = kzalloc(sizeof(*user_resp.u.ftm.entries) *
					  fw_resp->num_of_aps, GFP_KERNEL);
	if (!user_resp.u.ftm.entries) {
		iwl_mvm_tof_reset_active(mvm);
		return;
	}

	for (i = 0; i < fw_resp->num_of_aps && i < IWL_MVM_TOF_MAX_APS; i++) {
		struct cfg80211_ftm_result *result =
			&user_resp.u.ftm.entries[i];
		struct iwl_tof_range_rsp_ap_entry_ntfy *fw_ap = &fw_resp->ap[i];
		struct cfg80211_ftm_target *target;
		u32 timestamp;

		target = iwl_mvm_tof_find_target_in_request(mvm, fw_ap->bssid);
		if (!target) {
			IWL_WARN(mvm,
				 "Unknown bssid (target #%d) in FTM response\n",
				 i);
			continue;
		}

		result->status =
			iwl_mvm_get_target_status(fw_ap->measure_status);
		result->target = target;
		timestamp = le32_to_cpu(fw_ap->timestamp);
		result->host_time =
			iwl_mvm_tof_get_host_time(mvm, timestamp);
		result->rssi = fw_ap->rssi;
		result->rssi_spread = fw_ap->rssi_spread;
		if (iwl_mvm_tof_is_ht(mvm, fw_ap->measure_bw))
			result->tx_rate_info.flags |= RATE_INFO_FLAGS_MCS;
		if (iwl_mvm_tof_is_vht(mvm, fw_ap->measure_bw))
			result->tx_rate_info.flags |= RATE_INFO_FLAGS_VHT_MCS;
#if CFG80211_VERSION < KERNEL_VERSION(3,20,0)
		switch (iwl_mvm_tof_fw_bw_to_rate_info_bw(fw_ap->measure_bw)) {
		default:
		case RATE_INFO_BW_20:
			break;
		case RATE_INFO_BW_40:
			result->tx_rate_info.flags |= RATE_INFO_FLAGS_40_MHZ_WIDTH;
			break;
		case RATE_INFO_BW_80:
			result->tx_rate_info.flags |= RATE_INFO_FLAGS_80_MHZ_WIDTH;
			break;
		}
#else
		result->tx_rate_info.bw =
			iwl_mvm_tof_fw_bw_to_rate_info_bw(fw_ap->measure_bw);
#endif
		result->rtt = (s32)le32_to_cpu(fw_ap->rtt);
		result->rtt_variance = le32_to_cpu(fw_ap->rtt_variance);
		result->rtt_spread = le32_to_cpu(fw_ap->rtt_spread);
		result->distance = div_s64(div_s64(result->rtt, 2) *
					   SOL_CM_NSEC, 1000);
		result->distance_variance = div_u64((result->rtt_variance >>
						     2) *
						    (SOL_CM_NSEC * SOL_CM_NSEC),
						     1000000);
		result->distance_spread = div_u64((result->rtt_spread >> 1) *
						  SOL_CM_NSEC, 1000);
		iwl_mvm_get_lci_civic(&mvm->tof_data, result, target);

#define FTM_RESP_BIT(attr) BIT(NL80211_FTM_RESP_ENTRY_ATTR_##attr)
#ifdef CPTCFG_IWLMVM_TOF_TSF_WA
		if (mvm->tof_data.active_request.report_tsf) {
			result->tsf = iwl_mvm_tof_get_tsf(mvm, timestamp);
			result->filled |= FTM_RESP_BIT(TSF);
		}
#endif

		/* Mark only optional fields */
		result->filled |= FTM_RESP_BIT(HOST_TIME) |
				  FTM_RESP_BIT(RSSI) |
				  FTM_RESP_BIT(RSSI_SPREAD) |
				  FTM_RESP_BIT(TX_RATE_INFO) |
				  FTM_RESP_BIT(RTT_VAR) |
				  FTM_RESP_BIT(RTT_SPREAD) |
				  FTM_RESP_BIT(DISTANCE) |
				  FTM_RESP_BIT(DISTANCE_VAR) |
				  FTM_RESP_BIT(DISTANCE_SPREAD);
#undef FTM_RESP_BIT
	}

	iwl_mvm_debug_range_resp(mvm, &user_resp);

	cfg80211_measurement_response(mvm->hw->wiphy, &user_resp, GFP_KERNEL);
	kfree(user_resp.u.ftm.entries);

	/* for debugfs retrieving */
	memcpy(&mvm->tof_data.range_resp, fw_resp,
	       sizeof(struct iwl_tof_range_rsp_ntfy));

	if (fw_resp->last_in_batch)
		iwl_mvm_tof_reset_active(mvm);

	return;
}

void iwl_mvm_tof_mcsi_notif(struct iwl_mvm *mvm,
			    struct iwl_rx_cmd_buffer *rxb)

{
	struct iwl_rx_packet *pkt = rxb_addr(rxb);
	struct iwl_tof_mcsi_notif *resp = (void *)pkt->data;

	IWL_DEBUG_INFO(mvm, "MCSI notification, token %d\n", resp->token);
	return;
}

void iwl_mvm_tof_responder_stats(struct iwl_mvm *mvm,
				 struct iwl_rx_cmd_buffer *rxb)
{
	struct iwl_rx_packet *pkt = rxb_addr(rxb);
	struct iwl_tof_responder_stats *resp = (void *)pkt->data;
	struct cfg80211_ftm_responder_stats *stats = &mvm->tof_data.resp_stats;
	unsigned flags = le32_to_cpu(resp->flags);

	IWL_DEBUG_INFO(mvm, "Responder statistics info\n");

	if (resp->success_ftm == resp->ftm_per_burst)
		stats->success_num++;
	else if (resp->success_ftm >= 2)
		stats->partial_num++;
	else
		stats->failed_num++;

	if (flags & FTM_RESP_STAT_ASAP_REQ &&
	    flags & FTM_RESP_STAT_ASAP_RESP)
		stats->asap_num++;

	if (flags & FTM_RESP_STAT_NON_ASAP_RESP)
		stats->non_asap_num++;

	stats->total_duration_ms += le32_to_cpu(resp->duration) / USEC_PER_MSEC;

	if (flags & FTM_RESP_STAT_TRIGGER_UNKNOWN)
		stats->unknown_triggers_num++;

	if (flags & FTM_RESP_STAT_DUP)
		stats->reschedule_requests_num++;

	if (flags & FTM_RESP_STAT_NON_ASAP_OUT_WIN)
		stats->out_of_window_triggers_num++;

	return;
}

void iwl_mvm_tof_lc_notif(struct iwl_mvm *mvm,
			  struct iwl_rx_cmd_buffer *rxb)
{
	struct iwl_rx_packet *pkt = rxb_addr(rxb);
	const struct ieee80211_mgmt *mgmt = (void *)pkt->data;
	size_t len = iwl_rx_packet_payload_len(pkt);
	struct lci_civic_entry *lci_civic;
	const u8 *ies, *lci, *civic, *msr_ie;
	size_t ies_len, lci_len = 0, civic_len = 0;
	size_t baselen = IEEE80211_MIN_ACTION_SIZE +
			 sizeof(mgmt->u.action.u.ftm);
	static const u8 rprt_type_lci = IEEE80211_SPCT_MSR_RPRT_TYPE_LCI;
	static const u8 rprt_type_civic = IEEE80211_SPCT_MSR_RPRT_TYPE_CIVIC;

	if (len <= baselen)
		return;

	ies = mgmt->u.action.u.ftm.variable;
	ies_len = len - baselen;

	msr_ie = cfg80211_find_ie_match(WLAN_EID_MEASURE_REPORT, ies, ies_len,
					&rprt_type_lci, 1, 4);
	if (msr_ie) {
		lci = msr_ie + 2;
		lci_len = msr_ie[1];
	}

	msr_ie = cfg80211_find_ie_match(WLAN_EID_MEASURE_REPORT, ies, ies_len,
					&rprt_type_civic, 1, 4);
	if (msr_ie) {
		civic = msr_ie + 2;
		civic_len = msr_ie[1];
	}

	lci_civic = kmalloc(sizeof(*lci_civic) + lci_len + civic_len,
			    GFP_KERNEL);
	if (!lci_civic)
		return;

	memcpy(lci_civic->bssid, mgmt->bssid, ETH_ALEN);

	lci_civic->lci_len = lci_len;
	if (lci_len)
		memcpy(lci_civic->buf, lci, lci_len);

	lci_civic->civic_len = civic_len;
	if (civic_len)
		memcpy(lci_civic->buf + lci_len, civic, civic_len);

	list_add_tail(&lci_civic->list, &mvm->tof_data.lci_civic_info);
}
