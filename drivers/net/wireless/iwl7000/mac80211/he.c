/*
 * HE handling
 *
 * Copyright(c) 2017 Intel Deutschland GmbH
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "ieee80211_i.h"

void
ieee80211_he_cap_ie_to_sta_he_cap(struct ieee80211_sub_if_data *sdata,
				  struct ieee80211_supported_band *sband,
				  const u8 *he_cap_ie, u8 he_cap_len,
				  struct sta_info *sta)
{
	struct ieee80211_sta_he_cap *he_cap = &sta->sta.he_cap;
	u8 he_ppe_size;
	u8 pos;
	u8 n;

	memset(he_cap, 0, sizeof(*he_cap));

	if (!he_cap_ie || !ieee80211_get_he_sta_cap(sband))
		return;

	/* Make sure mandatory part exists */
	if (he_cap_len < (sizeof(he_cap->he_cap_elem) + 2))
		return;

	memcpy(&he_cap->he_cap_elem, he_cap_ie, sizeof(he_cap->he_cap_elem));
	pos = sizeof(he_cap->he_cap_elem);

	/* HE Tx/Rx HE MCS NSS Support Field */
	he_cap->he_mcs_nss_supp.mcs_hdr =
		cpu_to_le16(*((u16 *)&he_cap_ie[pos]));
	pos += 2;

	n = hweight16(le16_to_cpu(he_cap->he_mcs_nss_supp.mcs_hdr) &
		      IEEE80211_TX_RX_MCS_NSS_SUPP_TX_BITMAP_MASK);
	if (n > 0)
		memcpy(&he_cap->he_mcs_nss_supp.nss_tx_desc[0],
		       &he_cap_ie[pos], n);
	pos += n;

	n = hweight16(le16_to_cpu(he_cap->he_mcs_nss_supp.mcs_hdr) &
		      IEEE80211_TX_RX_MCS_NSS_SUPP_RX_BITMAP_MASK);
	if (n > 0)
		memcpy(&he_cap->he_mcs_nss_supp.nss_rx_desc[0],
		       &he_cap_ie[pos], n);
	pos += n;

	/* Check if there are (optional) PPE Thresholds */
	if (!(he_cap->he_cap_elem.phy_cap_info[6] &
	      IEEE80211_HE_PHY_CAP6_PPE_THRESHOLD_PRESENT)) {
		he_cap->has_he = true;
		return;
	}

	/* Make sure there is at least the hdr byte */
	if (he_cap_len < (pos + 1))
		return;

	/*
	 * Calculate how many PPET16/PPET8 pairs are to come. Algorithm:
	 * (NSS_M1 + 1) x (num of 1 bits in RU_INDEX_BITMASK)
	 */
	he_ppe_size = hweight8(he_cap_ie[pos] &
			       IEEE80211_PPE_THRES_RU_INDEX_BITMASK_MASK);
	he_ppe_size *= (1 + ((he_cap_ie[pos] &
			      IEEE80211_PPE_THRES_NSS_M1_MASK) >>
			      IEEE80211_PPE_THRES_NSS_M1_POS));

	/*
	 * Each pair is 6 bits, and we need to add the 7 "header" bits to the
	 * total size.
	 */
	he_ppe_size = (2 * he_ppe_size *
		       IEEE80211_PPE_THRES_INFO_PPET_SIZE) + 7;
	he_ppe_size = DIV_ROUND_UP(he_ppe_size, 8);

	if (he_cap_len < (pos + he_ppe_size))
		return;

	memcpy((u8 *)he_cap->ppe_thres, &he_cap_ie[pos], he_ppe_size);

	he_cap->has_he = true;
}
