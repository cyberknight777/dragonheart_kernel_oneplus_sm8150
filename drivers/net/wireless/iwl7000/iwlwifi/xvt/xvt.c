/******************************************************************************
 *
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 * redistributing this file, you may do so under either license.
 *
 * GPL LICENSE SUMMARY
 *
 * Copyright(c) 2007 - 2014 Intel Corporation. All rights reserved.
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
 *  Intel Linux Wireless <linuxwifi@intel.com>
 * Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497
 *
 * BSD LICENSE
 *
 * Copyright(c) 2005 - 2014 Intel Corporation. All rights reserved.
 * Copyright(c) 2017   Intel Deutschland GmbH
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
#include <linux/module.h>
#include <linux/types.h>

#include "iwl-drv.h"
#include "iwl-trans.h"
#include "iwl-op-mode.h"
#include "fw/img.h"
#include "iwl-config.h"
#include "iwl-phy-db.h"
#include "iwl-csr.h"
#include "xvt.h"
#include "user-infc.h"
#include "iwl-dnt-cfg.h"
#include "iwl-dnt-dispatch.h"
#include "iwl-io.h"
#include "iwl-prph.h"

#define DRV_DESCRIPTION	"Intel(R) xVT driver for Linux"
MODULE_DESCRIPTION(DRV_DESCRIPTION);
MODULE_AUTHOR(DRV_COPYRIGHT " " DRV_AUTHOR);
MODULE_LICENSE("GPL");

#define TX_QUEUE_CFG_TID (6)

static const struct iwl_op_mode_ops iwl_xvt_ops;

/*
 * module init and exit functions
 */
static int __init iwl_xvt_init(void)
{
	return iwl_opmode_register("iwlxvt", &iwl_xvt_ops);
}
module_init(iwl_xvt_init);

static void __exit iwl_xvt_exit(void)
{
	iwl_opmode_deregister("iwlxvt");
}
module_exit(iwl_xvt_exit);

/* Please keep this array *SORTED* by hex value.
 * Access is done through binary search.
 * A warning will be triggered on violation.
 */
static const struct iwl_hcmd_names iwl_xvt_cmd_names[] = {
	HCMD_NAME(MVM_ALIVE),
	HCMD_NAME(INIT_COMPLETE_NOTIF),
	HCMD_NAME(TX_CMD),
	HCMD_NAME(SCD_QUEUE_CFG),
	HCMD_NAME(FW_PAGING_BLOCK_CMD),
	HCMD_NAME(PHY_CONFIGURATION_CMD),
	HCMD_NAME(CALIB_RES_NOTIF_PHY_DB),
	HCMD_NAME(NVM_ACCESS_CMD),
	HCMD_NAME(GET_SET_PHY_DB_CMD),
	HCMD_NAME(REPLY_HD_PARAMS_CMD),
	HCMD_NAME(NVM_COMMIT_COMPLETE_NOTIFICATION),
	HCMD_NAME(REPLY_RX_PHY_CMD),
	HCMD_NAME(REPLY_RX_MPDU_CMD),
	HCMD_NAME(REPLY_RX_DSP_EXT_INFO),
	HCMD_NAME(DTS_MEASUREMENT_NOTIFICATION),
	HCMD_NAME(REPLY_DEBUG_XVT_CMD),
	HCMD_NAME(DEBUG_LOG_MSG),
};

/* Please keep this array *SORTED* by hex value.
 * Access is done through binary search.
 */
static const struct iwl_hcmd_names iwl_xvt_long_cmd_names[] = {
	HCMD_NAME(GET_SET_PHY_DB_CMD),
};

/* Please keep this array *SORTED* by hex value.
 * Access is done through binary search.
 */
static const struct iwl_hcmd_names iwl_xvt_phy_names[] = {
	HCMD_NAME(DTS_MEASUREMENT_NOTIF_WIDE),
};

/* Please keep this array *SORTED* by hex value.
 * Access is done through binary search.
 */
static const struct iwl_hcmd_names iwl_xvt_data_path_names[] = {
	HCMD_NAME(DQA_ENABLE_CMD),
};

/* Please keep this array *SORTED* by hex value.
 * Access is done through binary search.
 */
static const struct iwl_hcmd_names iwl_xvt_regulatory_and_nvm_names[] = {
	HCMD_NAME(NVM_ACCESS_COMPLETE),
};

/* Please keep this array *SORTED* by hex value.
 * Access is done through binary search.
 */
static const struct iwl_hcmd_names iwl_xvt_tof_names[] = {
	HCMD_NAME(LOCATION_GROUP_NOTIFICATION),
	HCMD_NAME(TOF_MCSI_DEBUG_NOTIF),
	HCMD_NAME(TOF_RANGE_RESPONSE_NOTIF),
};

/* Please keep this array *SORTED* by hex value.
 * Access is done through binary search.
 */
static const struct iwl_hcmd_names iwl_xvt_system_names[] = {
	HCMD_NAME(INIT_EXTENDED_CFG_CMD),
};

static const struct iwl_hcmd_arr iwl_xvt_cmd_groups[] = {
	[LEGACY_GROUP] = HCMD_ARR(iwl_xvt_cmd_names),
	[LONG_GROUP] = HCMD_ARR(iwl_xvt_long_cmd_names),
	[SYSTEM_GROUP] = HCMD_ARR(iwl_xvt_system_names),
	[PHY_OPS_GROUP] = HCMD_ARR(iwl_xvt_phy_names),
	[DATA_PATH_GROUP] = HCMD_ARR(iwl_xvt_data_path_names),
	[TOF_GROUP] = HCMD_ARR(iwl_xvt_tof_names),
	[REGULATORY_AND_NVM_GROUP] = HCMD_ARR(iwl_xvt_regulatory_and_nvm_names),
};

static struct iwl_op_mode *iwl_xvt_start(struct iwl_trans *trans,
					 const struct iwl_cfg *cfg,
					 const struct iwl_fw *fw,
					 struct dentry *dbgfs_dir)
{
	struct iwl_op_mode *op_mode;
	struct iwl_xvt *xvt;
	struct iwl_trans_config trans_cfg = {};
	static const u8 no_reclaim_cmds[] = {
		TX_CMD,
	};
	u8 i, num_of_lmacs;

	op_mode = kzalloc(sizeof(struct iwl_op_mode) +
			  sizeof(struct iwl_xvt), GFP_KERNEL);
	if (!op_mode)
		return NULL;

	op_mode->ops = &iwl_xvt_ops;

	xvt = IWL_OP_MODE_GET_XVT(op_mode);
	xvt->fw = fw;
	xvt->cfg = cfg;
	xvt->trans = trans;
	xvt->dev = trans->dev;

	iwl_fw_runtime_init(&xvt->fwrt, trans, fw, NULL, NULL);

	mutex_init(&xvt->mutex);
	spin_lock_init(&xvt->notif_lock);

	/*
	 * Populate the state variables that the
	 * transport layer needs to know about.
	 */
	trans_cfg.op_mode = op_mode;
	trans_cfg.no_reclaim_cmds = no_reclaim_cmds;
	trans_cfg.n_no_reclaim_cmds = ARRAY_SIZE(no_reclaim_cmds);
	trans_cfg.command_groups = iwl_xvt_cmd_groups;
	trans_cfg.command_groups_size = ARRAY_SIZE(iwl_xvt_cmd_groups);
	trans_cfg.cmd_queue = IWL_MVM_DQA_CMD_QUEUE;
	IWL_DEBUG_INFO(xvt, "dqa supported\n");
	trans_cfg.cmd_fifo = IWL_MVM_TX_FIFO_CMD;
	trans_cfg.bc_table_dword = true;
	trans_cfg.scd_set_active = true;
	trans->wide_cmd_header = true;

	switch (iwlwifi_mod_params.amsdu_size) {
	case IWL_AMSDU_DEF:
	case IWL_AMSDU_4K:
		trans_cfg.rx_buf_size = IWL_AMSDU_4K;
		break;
	case IWL_AMSDU_8K:
		trans_cfg.rx_buf_size = IWL_AMSDU_8K;
		break;
	case IWL_AMSDU_12K:
		trans_cfg.rx_buf_size = IWL_AMSDU_12K;
		break;
	default:
		pr_err("%s: Unsupported amsdu_size: %d\n", KBUILD_MODNAME,
		       iwlwifi_mod_params.amsdu_size);
		trans_cfg.rx_buf_size = IWL_AMSDU_4K;
	}
	/* the hardware splits the A-MSDU */
	if (xvt->trans->cfg->mq_rx_supported)
		trans_cfg.rx_buf_size = IWL_AMSDU_4K;

	trans_cfg.cb_data_offs = 0;

	/* Configure transport layer */
	iwl_trans_configure(xvt->trans, &trans_cfg);
	trans->command_groups = trans_cfg.command_groups;
	trans->command_groups_size = trans_cfg.command_groups_size;

	/* set up notification wait support */
	iwl_notification_wait_init(&xvt->notif_wait);

	/* Init phy db */
	xvt->phy_db = iwl_phy_db_init(xvt->trans);
	if (!xvt->phy_db)
		goto out_free;

	iwl_dnt_init(xvt->trans, dbgfs_dir);

	num_of_lmacs = iwl_xvt_is_cdb_supported(xvt) ? NUM_OF_LMACS : 1;

	for (i = 0; i < num_of_lmacs; i++) {
		init_waitqueue_head(&xvt->tx_meta_data[i].mod_tx_wq);
		init_waitqueue_head(&xvt->tx_meta_data[i].mod_tx_done_wq);
		xvt->tx_meta_data[i].queue = -1;
		xvt->tx_meta_data[i].tx_mod_thread = NULL;
		xvt->tx_meta_data[i].txq_full = false;
	};

	IWL_INFO(xvt, "Detected %s, REV=0x%X, xVT operation mode\n",
		 xvt->cfg->name, xvt->trans->hw_rev);

	return op_mode;

out_free:
	kfree(op_mode);

	return NULL;
}

static void iwl_xvt_stop(struct iwl_op_mode *op_mode)
{
	struct iwl_xvt *xvt = IWL_OP_MODE_GET_XVT(op_mode);

	if (xvt->state != IWL_XVT_STATE_UNINITIALIZED) {
		if (xvt->fw_running) {
			iwl_xvt_txq_disable(xvt);
			xvt->fw_running = false;
		}
		iwl_trans_stop_device(xvt->trans);
	}

	iwl_phy_db_free(xvt->phy_db);
	xvt->phy_db = NULL;
	iwl_dnt_free(xvt->trans);
	kfree(op_mode);
}

static void iwl_xvt_rx_tx_cmd_handler(struct iwl_xvt *xvt,
				      struct iwl_rx_packet *pkt)
{
	/* struct iwl_mvm_tx_resp_v3 is almost the same */
	struct iwl_mvm_tx_resp *tx_resp = (void *)pkt->data;
	int txq_id = SEQ_TO_QUEUE(le16_to_cpu(pkt->hdr.sequence));
	u16 ssn = iwl_xvt_get_scd_ssn(xvt, tx_resp);
	struct sk_buff_head skbs;
	struct sk_buff *skb;
	struct iwl_device_cmd **cb_dev_cmd;
	struct tx_meta_data *tx_data;

	__skb_queue_head_init(&skbs);

	if (iwl_xvt_is_unified_fw(xvt)) {
		txq_id = le16_to_cpu(tx_resp->tx_queue);

		if (txq_id == xvt->tx_meta_data[XVT_LMAC_0_ID].queue) {
			tx_data = &xvt->tx_meta_data[XVT_LMAC_0_ID];
		} else if (txq_id == xvt->tx_meta_data[XVT_LMAC_1_ID].queue) {
			tx_data = &xvt->tx_meta_data[XVT_LMAC_1_ID];
		} else {
			IWL_ERR(xvt, "got TX_CMD from unidentified queque\n");
			return;
		}
	} else {
		tx_data = &xvt->tx_meta_data[XVT_LMAC_0_ID];
	}

	iwl_trans_reclaim(xvt->trans, txq_id, ssn, &skbs);

	while (!skb_queue_empty(&skbs)) {
		skb = __skb_dequeue(&skbs);
		cb_dev_cmd = (void *)skb->cb;
		tx_data->tx_counter++;
		if (cb_dev_cmd && *cb_dev_cmd)
			iwl_trans_free_tx_cmd(xvt->trans, *cb_dev_cmd);
		kfree_skb(skb);
	}
	if (tx_data->tot_tx == tx_data->tx_counter)
		wake_up_interruptible(&tx_data->mod_tx_done_wq);
}

static void iwl_xvt_rx_dispatch(struct iwl_op_mode *op_mode,
				struct napi_struct *napi,
				struct iwl_rx_cmd_buffer *rxb)
{
	struct iwl_xvt *xvt = IWL_OP_MODE_GET_XVT(op_mode);
	struct iwl_rx_packet *pkt = rxb_addr(rxb);

	spin_lock(&xvt->notif_lock);
	iwl_notification_wait_notify(&xvt->notif_wait, pkt);
	IWL_DEBUG_INFO(xvt, "rx dispatch got notification\n");

	if (pkt->hdr.cmd == TX_CMD)
		iwl_xvt_rx_tx_cmd_handler(xvt, pkt);

	iwl_xvt_send_user_rx_notif(xvt, rxb);
	spin_unlock(&xvt->notif_lock);
}

static void iwl_xvt_nic_config(struct iwl_op_mode *op_mode)
{
	struct iwl_xvt *xvt = IWL_OP_MODE_GET_XVT(op_mode);
	u8 radio_cfg_type, radio_cfg_step, radio_cfg_dash;
	u32 reg_val = 0;

	radio_cfg_type = (xvt->fw->phy_config & FW_PHY_CFG_RADIO_TYPE) >>
			 FW_PHY_CFG_RADIO_TYPE_POS;
	radio_cfg_step = (xvt->fw->phy_config & FW_PHY_CFG_RADIO_STEP) >>
			 FW_PHY_CFG_RADIO_STEP_POS;
	radio_cfg_dash = (xvt->fw->phy_config & FW_PHY_CFG_RADIO_DASH) >>
			 FW_PHY_CFG_RADIO_DASH_POS;

	/* SKU control */
	reg_val |= CSR_HW_REV_STEP(xvt->trans->hw_rev) <<
				CSR_HW_IF_CONFIG_REG_POS_MAC_STEP;
	reg_val |= CSR_HW_REV_DASH(xvt->trans->hw_rev) <<
				CSR_HW_IF_CONFIG_REG_POS_MAC_DASH;

	/* radio configuration */
	reg_val |= radio_cfg_type << CSR_HW_IF_CONFIG_REG_POS_PHY_TYPE;
	reg_val |= radio_cfg_step << CSR_HW_IF_CONFIG_REG_POS_PHY_STEP;
	reg_val |= radio_cfg_dash << CSR_HW_IF_CONFIG_REG_POS_PHY_DASH;

	WARN_ON((radio_cfg_type << CSR_HW_IF_CONFIG_REG_POS_PHY_TYPE) &
		 ~CSR_HW_IF_CONFIG_REG_MSK_PHY_TYPE);

	/*
	 * TODO: Bits 7-8 of CSR in 8000 HW family and higher set the ADC
	 * sampling, and shouldn't be set to any non-zero value.
	 * The same is supposed to be true of the other HW, but unsetting
	 * them (such as the 7260) causes automatic tests to fail on seemingly
	 * unrelated errors. Need to further investigate this, but for now
	 * we'll separate cases.
	 */
	if (xvt->trans->cfg->device_family < IWL_DEVICE_FAMILY_8000)
		reg_val |= CSR_HW_IF_CONFIG_REG_BIT_RADIO_SI;

	iwl_trans_set_bits_mask(xvt->trans, CSR_HW_IF_CONFIG_REG,
				CSR_HW_IF_CONFIG_REG_MSK_MAC_DASH |
				CSR_HW_IF_CONFIG_REG_MSK_MAC_STEP |
				CSR_HW_IF_CONFIG_REG_MSK_PHY_TYPE |
				CSR_HW_IF_CONFIG_REG_MSK_PHY_STEP |
				CSR_HW_IF_CONFIG_REG_MSK_PHY_DASH |
				CSR_HW_IF_CONFIG_REG_BIT_RADIO_SI |
				CSR_HW_IF_CONFIG_REG_BIT_MAC_SI,
				reg_val);

	IWL_DEBUG_INFO(xvt, "Radio type=0x%x-0x%x-0x%x\n", radio_cfg_type,
		       radio_cfg_step, radio_cfg_dash);

	/*
	 * W/A : NIC is stuck in a reset state after Early PCIe power off
	 * (PCIe power is lost before PERST# is asserted), causing ME FW
	 * to lose ownership and not being able to obtain it back.
	 */
	if (!xvt->trans->cfg->apmg_not_supported)
		iwl_set_bits_mask_prph(xvt->trans, APMG_PS_CTRL_REG,
				       APMG_PS_CTRL_EARLY_PWR_OFF_RESET_DIS,
				       ~APMG_PS_CTRL_EARLY_PWR_OFF_RESET_DIS);
}

static void iwl_xvt_nic_error(struct iwl_op_mode *op_mode)
{
	struct iwl_xvt *xvt = IWL_OP_MODE_GET_XVT(op_mode);
	void *p_table;
	void *p_table_umac = NULL;
	struct iwl_error_event_table_v2 table_v2;
	struct iwl_umac_error_event_table table_umac;
	int err, table_size;

	xvt->fw_error = true;
	wake_up_interruptible(&xvt->tx_meta_data[XVT_LMAC_0_ID].mod_tx_wq);

	iwl_xvt_get_nic_error_log_v2(xvt, &table_v2);
	iwl_xvt_dump_nic_error_log_v2(xvt, &table_v2);
	p_table = kmemdup(&table_v2, sizeof(table_v2), GFP_ATOMIC);
	table_size = sizeof(table_v2);

	if (xvt->support_umac_log) {
		iwl_xvt_get_umac_error_log(xvt, &table_umac);
		iwl_xvt_dump_umac_error_log(xvt, &table_umac);
		p_table_umac = kmemdup(&table_umac, sizeof(table_umac),
				       GFP_ATOMIC);
	}

	if (p_table) {
		err = iwl_xvt_user_send_notif(xvt, IWL_XVT_CMD_SEND_NIC_ERROR,
					      (void *)p_table, table_size,
					      GFP_ATOMIC);
		if (err)
			IWL_WARN(xvt,
				 "Error %d sending NIC error notification\n",
				 err);
		kfree(p_table);
	}

	if (p_table_umac) {
		err = iwl_xvt_user_send_notif(xvt,
					      IWL_XVT_CMD_SEND_NIC_UMAC_ERROR,
					      (void *)p_table_umac,
					      sizeof(table_umac), GFP_ATOMIC);
		if (err)
			IWL_WARN(xvt,
				 "Error %d sending NIC umac error notification\n",
				 err);
		kfree(p_table_umac);
	}

}

static bool iwl_xvt_set_hw_rfkill_state(struct iwl_op_mode *op_mode, bool state)
{
	struct iwl_xvt *xvt = IWL_OP_MODE_GET_XVT(op_mode);
	u32 rfkill_state = state ? IWL_XVT_RFKILL_ON : IWL_XVT_RFKILL_OFF;
	int err;

	err = iwl_xvt_user_send_notif(xvt, IWL_XVT_CMD_SEND_RFKILL,
				      &rfkill_state, sizeof(rfkill_state),
				      GFP_ATOMIC);
	if (err)
		IWL_WARN(xvt, "Error %d sending RFKILL notification\n", err);

	return false;
}

static bool iwl_xvt_valid_hw_addr(u32 addr)
{
	/* TODO need to implement */
	return true;
}

static void iwl_xvt_free_skb(struct iwl_op_mode *op_mode, struct sk_buff *skb)
{
	struct iwl_xvt *xvt = IWL_OP_MODE_GET_XVT(op_mode);
	struct iwl_device_cmd **cb_dev_cmd = (void *)skb->cb;

	iwl_trans_free_tx_cmd(xvt->trans, *cb_dev_cmd);
	kfree_skb(skb);
}

static void iwl_xvt_stop_sw_queue(struct iwl_op_mode *op_mode, int queue)
{
	struct iwl_xvt *xvt = IWL_OP_MODE_GET_XVT(op_mode);
	u8 i;

	for (i = 0; i < NUM_OF_LMACS; i++) {
		if (queue == xvt->tx_meta_data[i].queue) {
			xvt->tx_meta_data[i].txq_full = true;
			break;
		}
	}
}

static void iwl_xvt_wake_sw_queue(struct iwl_op_mode *op_mode, int queue)
{
	struct iwl_xvt *xvt = IWL_OP_MODE_GET_XVT(op_mode);
	u8 i;

	for (i = 0; i < NUM_OF_LMACS; i++) {
		if (queue == xvt->tx_meta_data[i].queue) {
			xvt->tx_meta_data[i].txq_full = false;
			wake_up_interruptible(&xvt->tx_meta_data[i].mod_tx_wq);
			break;
		}
	}
}

static const struct iwl_op_mode_ops iwl_xvt_ops = {
	.start = iwl_xvt_start,
	.stop = iwl_xvt_stop,
	.rx = iwl_xvt_rx_dispatch,
	.nic_config = iwl_xvt_nic_config,
	.nic_error = iwl_xvt_nic_error,
	.hw_rf_kill = iwl_xvt_set_hw_rfkill_state,
	.free_skb = iwl_xvt_free_skb,
	.queue_full = iwl_xvt_stop_sw_queue,
	.queue_not_full = iwl_xvt_wake_sw_queue,
	.test_ops = {
		.cmd_execute = iwl_xvt_user_cmd_execute,
		.valid_hw_addr = iwl_xvt_valid_hw_addr,
	},
};

void iwl_xvt_free_tx_queue(struct iwl_xvt *xvt, u8 lmac_id)
{
	if (xvt->tx_meta_data[lmac_id].queue == -1)
		return;

	iwl_trans_txq_free(xvt->trans, xvt->tx_meta_data[lmac_id].queue);

	xvt->tx_meta_data[lmac_id].queue = -1;
}

int iwl_xvt_allocate_tx_queue(struct iwl_xvt *xvt, u8 sta_id,
			      u8 lmac_id)
{
	int ret;
	struct iwl_tx_queue_cfg_cmd cmd = {
			.flags = cpu_to_le16(TX_QUEUE_CFG_ENABLE_QUEUE),
			.sta_id = sta_id,
			.tid = TX_QUEUE_CFG_TID };

	ret = iwl_trans_txq_alloc(xvt->trans, (void *)&cmd, SCD_QUEUE_CFG, 0);
	/* ret is positive when func returns the allocated the queue number */
	if (ret > 0) {
		xvt->tx_meta_data[lmac_id].queue = ret;
		ret = 0;
	} else {
		IWL_ERR(xvt, "failed to allocate queue\n");
	}

	return ret;
}

void iwl_xvt_txq_disable(struct iwl_xvt *xvt)
{
	if (iwl_xvt_is_unified_fw(xvt)) {
		iwl_xvt_free_tx_queue(xvt, XVT_LMAC_0_ID);
		iwl_xvt_free_tx_queue(xvt, XVT_LMAC_1_ID);
	} else {
		iwl_trans_txq_disable(xvt->trans,
				      IWL_XVT_DEFAULT_TX_QUEUE,
				      true);
	}
}
