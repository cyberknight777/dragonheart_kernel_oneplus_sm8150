/******************************************************************************
 *
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 * redistributing this file, you may do so under either license.
 *
 * GPL LICENSE SUMMARY
 *
 * Copyright(c) 2017        Intel Deutschland GmbH
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
 *  Intel Linux Wireless <linuxwifi@intel.com>
 * Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497
 *
 * BSD LICENSE
 *
 * Copyright(c) 2017        Intel Deutschland GmbH
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
#include "rs.h"
#include "fw-api.h"
#include "sta.h"
#include "iwl-op-mode.h"
#include "mvm.h"

void rs_fw_rate_init(struct iwl_mvm *mvm, struct ieee80211_sta *sta,
		     enum nl80211_band band)
{
}

static void rs_fw_get_rate(void *mvm_r, struct ieee80211_sta *sta,
			   void *mvm_sta,
			   struct ieee80211_tx_rate_control *txrc)
{
}

static void *rs_fw_alloc_sta(void *mvm_rate, struct ieee80211_sta *sta,
			     gfp_t gfp)
{
	return NULL;
}

static void rs_fw_rate_update(void *mvm_rate,
			      struct ieee80211_supported_band *sband,
			      struct cfg80211_chan_def *chandef,
			      struct ieee80211_sta *sta,
			      void *priv_sta, u32 changed)
{
}

static void rs_fw_mac80211_tx_status(void *mvm_r,
				     struct ieee80211_supported_band *sband,
				     struct ieee80211_sta *sta, void *priv_sta,
				     struct sk_buff *skb)
{
}

#ifdef CPTCFG_MAC80211_DEBUGFS
static void rs_fw_add_sta_debugfs(void *mvm_rate, void *priv_sta,
				  struct dentry *dir)
{
}
#endif

/* ops for rate scaling offloaded to FW */
static struct rate_control_ops rs_mvm_ops_fw = {
	.name = RS_NAME_FW,
	.tx_status = rs_fw_mac80211_tx_status,
	.get_rate = rs_fw_get_rate,
	.rate_init = rs_rate_init_ops,
	.alloc = rs_alloc,
	.free = rs_free,
	.alloc_sta = rs_fw_alloc_sta,
	.free_sta = rs_free_sta,
	.rate_update = rs_fw_rate_update,
#ifdef CPTCFG_MAC80211_DEBUGFS
	.add_sta_debugfs = rs_fw_add_sta_debugfs,
	.remove_sta_debugfs = rs_remove_sta_debugfs,
#endif
};

int rs_fw_register_ops(void)
{
	return ieee80211_rate_control_register(&rs_mvm_ops_fw);
}

void rs_fw_unregister_ops(void)
{
	ieee80211_rate_control_unregister(&rs_mvm_ops_fw);
}
