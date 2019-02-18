/******************************************************************************
 *
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 * redistributing this file, you may do so under either license.
 *
 * GPL LICENSE SUMMARY
 *
 * Copyright(c) 2015 - 2016 Intel Deutschland GmbH
 * Copyright(c) 2018 Intel Corporation
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
 * The full GNU General Public License is included in this distribution
 * in the file called COPYING.
 *
 * Contact Information:
 * Intel Linux Wireless <linuxwifi@intel.com>
 * Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497
 *
 * BSD LICENSE
 *
 * Copyright(c) 2015 - 2016 Intel Deutschland GmbH
 * Copyright(c) 2018 Intel Corporation
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
#ifndef __tof_h__
#define __tof_h__

#include "fw/api/tof.h"

#ifdef CPTCFG_IWLMVM_TOF_TSF_WA
#include <linux/rhashtable.h>
#include "iwl-trans.h"

struct iwl_mvm_tof_tsf_entry {
	struct rhash_head hash_node;
	u8 bssid[ETH_ALEN] __aligned(2);
	u8 delta_sign;
	u32 delta;
};

void iwl_mvm_tof_update_tsf(struct iwl_mvm *mvm, struct ieee80211_hdr *hdr,
			    u32 gp2);
#endif

/* The buffer at the end of this struct holds lci_len bytes of lci data followed
 * by civic_len bytes of civic data.
 */
struct lci_civic_entry {
	struct list_head list;
	u8 bssid[ETH_ALEN];
	u32 lci_len;
	u32 civic_len;
	u8 buf[];
};

struct iwl_mvm_tof_data {
	struct iwl_tof_config_cmd tof_cfg;
	struct iwl_tof_range_req_cmd range_req;
	struct iwl_tof_range_req_ext_cmd range_req_ext;
#define IWL_TOF_LCI_CIVIC_BUF_SIZE 512
	struct iwl_tof_responder_config_cmd responder_cfg;
	struct iwl_tof_responder_dyn_config_cmd responder_dyn_cfg;
	u8 lci_civic_buf[IWL_TOF_LCI_CIVIC_BUF_SIZE];
	struct iwl_tof_range_rsp_ntfy range_resp;
	u8 last_abort_id;
#define IWL_MVM_TOF_RANGE_REQ_MAX_ID 256
	u16 active_request_id;
	u64 active_cookie;
	struct cfg80211_ftm_request active_request;
	u8 active_bssid_for_tsf[ETH_ALEN];
#ifdef CPTCFG_IWLMVM_TOF_TSF_WA
	struct rhashtable tsf_hash;
	/* use this flag to minimize changes in mvm code needed for this WA */
	bool tsf_hash_valid;
#endif
	struct cfg80211_ftm_responder_stats resp_stats;
	u8 tof_algo_type;
	u8 enable_dyn_ack;
	u16 toa_offset;
	struct list_head lci_civic_info;
};

void iwl_mvm_tof_init(struct iwl_mvm *mvm);
void iwl_mvm_tof_clean(struct iwl_mvm *mvm);
int iwl_mvm_tof_config_cmd(struct iwl_mvm *mvm);
int iwl_mvm_tof_perform_ftm(struct iwl_mvm *mvm, u64 cookie,
			    struct ieee80211_vif *vif,
			    struct cfg80211_ftm_request *req);
int iwl_mvm_tof_abort_ftm(struct iwl_mvm *mvm, u64 cookie);
int iwl_mvm_tof_range_abort_cmd(struct iwl_mvm *mvm, u8 id);
int iwl_mvm_tof_range_request_cmd(struct iwl_mvm *mvm);
void iwl_mvm_tof_range_resp(struct iwl_mvm *mvm,
			    struct iwl_rx_cmd_buffer *rxb);
void iwl_mvm_tof_mcsi_notif(struct iwl_mvm *mvm,
			    struct iwl_rx_cmd_buffer *rxb);
void iwl_mvm_tof_responder_stats(struct iwl_mvm *mvm,
				 struct iwl_rx_cmd_buffer *rxb);
void iwl_mvm_tof_lc_notif(struct iwl_mvm *mvm,
			  struct iwl_rx_cmd_buffer *rxb);
int iwl_mvm_tof_range_request_ext_cmd(struct iwl_mvm *mvm);
int iwl_mvm_tof_responder_cmd(struct iwl_mvm *mvm,
			      struct ieee80211_vif *vif);
int iwl_mvm_tof_start_responder(struct iwl_mvm *mvm,
				struct ieee80211_vif *vif,
				struct cfg80211_ftm_responder_params *params);
void iwl_mvm_tof_restart_responder(struct iwl_mvm *mvm,
				   struct ieee80211_vif *vif);
#endif /* __tof_h__ */
