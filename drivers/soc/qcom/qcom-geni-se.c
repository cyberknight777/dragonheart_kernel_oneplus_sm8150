/*
 * Copyright (c) 2017-2018, The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <linux/clk.h>
#include <linux/slab.h>
#include <linux/dma-mapping.h>
#include <linux/io.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_platform.h>
#include <linux/pm_runtime.h>
#include <linux/qcom-geni-se.h>
#include <linux/spinlock.h>

#define MAX_CLK_PERF_LEVEL 32

/**
 * @struct geni_se_device - Data structure to represent the QUP Wrapper Core
 * @dev:		Device pointer of the QUP wrapper core.
 * @base:		Base address of this instance of QUP wrapper core.
 * @m_ahb_clk:		Handle to the primary AHB clock.
 * @s_ahb_clk:		Handle to the secondary AHB clock.
 * @geni_dev_lock:	Lock to protect the device elements.
 * @num_clk_levels:	Number of valid clock levels in clk_perf_tbl.
 * @clk_perf_tbl:	Table of clock frequency input to Serial Engine clock.
 */
struct geni_se_device {
	struct device *dev;
	void __iomem *base;
	struct clk *m_ahb_clk;
	struct clk *s_ahb_clk;
	struct mutex geni_dev_lock;
	unsigned int num_clk_levels;
	unsigned long *clk_perf_tbl;
};

/* Offset of QUP Hardware Version Register */
#define QUP_HW_VER (0x4)

#define HW_VER_MAJOR_MASK GENMASK(31, 28)
#define HW_VER_MAJOR_SHFT 28
#define HW_VER_MINOR_MASK GENMASK(27, 16)
#define HW_VER_MINOR_SHFT 16
#define HW_VER_STEP_MASK GENMASK(15, 0)

/**
 * geni_read_reg_nolog() - Helper function to read from a GENI register
 * @base:	Base address of the serial engine's register block.
 * @offset:	Offset within the serial engine's register block.
 *
 * Return:	Return the contents of the register.
 */
unsigned int geni_read_reg_nolog(void __iomem *base, int offset)
{
	return readl_relaxed(base + offset);
}
EXPORT_SYMBOL(geni_read_reg_nolog);

/**
 * geni_write_reg_nolog() - Helper function to write into a GENI register
 * @value:	Value to be written into the register.
 * @base:	Base address of the serial engine's register block.
 * @offset:	Offset within the serial engine's register block.
 */
void geni_write_reg_nolog(unsigned int value, void __iomem *base, int offset)
{
	return writel_relaxed(value, (base + offset));
}
EXPORT_SYMBOL(geni_write_reg_nolog);

/**
 * geni_read_reg() - Helper function to read from a GENI register
 * @base:	Base address of the serial engine's register block.
 * @offset:	Offset within the serial engine's register block.
 *
 * Return:	Return the contents of the register.
 */
unsigned int geni_read_reg(void __iomem *base, int offset)
{
	return readl_relaxed(base + offset);
}
EXPORT_SYMBOL(geni_read_reg);

/**
 * geni_write_reg() - Helper function to write into a GENI register
 * @value:	Value to be written into the register.
 * @base:	Base address of the serial engine's register block.
 * @offset:	Offset within the serial engine's register block.
 */
void geni_write_reg(unsigned int value, void __iomem *base, int offset)
{
	return writel_relaxed(value, (base + offset));
}
EXPORT_SYMBOL(geni_write_reg);

/**
 * geni_get_qup_hw_version() - Read the QUP wrapper Hardware version
 * @wrapper_dev:	Pointer to the corresponding QUP wrapper core.
 * @major:		Buffer for Major Version field.
 * @minor:		Buffer for Minor Version field.
 * @step:		Buffer for Step Version field.
 *
 * Return:	0 on success, standard Linux error codes on failure/error.
 */
int geni_get_qup_hw_version(struct device *wrapper_dev, unsigned int *major,
			    unsigned int *minor, unsigned int *step)
{
	unsigned int version;
	struct geni_se_device *geni_se_dev;

	if (!wrapper_dev || !major || !minor || !step)
		return -EINVAL;

	geni_se_dev = dev_get_drvdata(wrapper_dev);
	if (unlikely(!geni_se_dev))
		return -ENODEV;

	version = geni_read_reg(geni_se_dev->base, QUP_HW_VER);
	*major = (version & HW_VER_MAJOR_MASK) >> HW_VER_MAJOR_SHFT;
	*minor = (version & HW_VER_MINOR_MASK) >> HW_VER_MINOR_SHFT;
	*step = version & HW_VER_STEP_MASK;
	return 0;
}
EXPORT_SYMBOL(geni_get_qup_hw_version);

/**
 * geni_se_get_proto() - Read the protocol configured for a serial engine
 * @base:	Base address of the serial engine's register block.
 *
 * Return:	Protocol value as configured in the serial engine.
 */
int geni_se_get_proto(void __iomem *base)
{
	int proto;

	proto = ((geni_read_reg(base, GENI_FW_REVISION_RO)
			& FW_REV_PROTOCOL_MSK) >> FW_REV_PROTOCOL_SHFT);
	return proto;
}
EXPORT_SYMBOL(geni_se_get_proto);

static int geni_se_irq_en(void __iomem *base)
{
	unsigned int common_geni_m_irq_en;
	unsigned int common_geni_s_irq_en;

	common_geni_m_irq_en = geni_read_reg(base, SE_GENI_M_IRQ_EN);
	common_geni_s_irq_en = geni_read_reg(base, SE_GENI_S_IRQ_EN);
	/* Common to all modes */
	common_geni_m_irq_en |= M_COMMON_GENI_M_IRQ_EN;
	common_geni_s_irq_en |= S_COMMON_GENI_S_IRQ_EN;

	geni_write_reg(common_geni_m_irq_en, base, SE_GENI_M_IRQ_EN);
	geni_write_reg(common_geni_s_irq_en, base, SE_GENI_S_IRQ_EN);
	return 0;
}


static void geni_se_set_rx_rfr_wm(void __iomem *base, unsigned int rx_wm,
				  unsigned int rx_rfr)
{
	geni_write_reg(rx_wm, base, SE_GENI_RX_WATERMARK_REG);
	geni_write_reg(rx_rfr, base, SE_GENI_RX_RFR_WATERMARK_REG);
}

static int geni_se_io_set_mode(void __iomem *base)
{
	unsigned int io_mode;
	unsigned int geni_dma_mode;

	io_mode = geni_read_reg(base, SE_IRQ_EN);
	geni_dma_mode = geni_read_reg(base, SE_GENI_DMA_MODE_EN);

	io_mode |= (GENI_M_IRQ_EN | GENI_S_IRQ_EN);
	io_mode |= (DMA_TX_IRQ_EN | DMA_RX_IRQ_EN);
	geni_dma_mode &= ~GENI_DMA_MODE_EN;

	geni_write_reg(io_mode, base, SE_IRQ_EN);
	geni_write_reg(geni_dma_mode, base, SE_GENI_DMA_MODE_EN);
	geni_write_reg(0, base, SE_GSI_EVENT_EN);
	return 0;
}

static void geni_se_io_init(void __iomem *base)
{
	unsigned int io_op_ctrl;
	unsigned int geni_cgc_ctrl;
	unsigned int dma_general_cfg;

	geni_cgc_ctrl = geni_read_reg(base, GENI_CGC_CTRL);
	dma_general_cfg = geni_read_reg(base, SE_DMA_GENERAL_CFG);
	geni_cgc_ctrl |= DEFAULT_CGC_EN;
	dma_general_cfg |= (AHB_SEC_SLV_CLK_CGC_ON | DMA_AHB_SLV_CFG_ON |
			DMA_TX_CLK_CGC_ON | DMA_RX_CLK_CGC_ON);
	io_op_ctrl = DEFAULT_IO_OUTPUT_CTRL_MSK;
	geni_write_reg(geni_cgc_ctrl, base, GENI_CGC_CTRL);
	geni_write_reg(dma_general_cfg, base, SE_DMA_GENERAL_CFG);

	geni_write_reg(io_op_ctrl, base, GENI_OUTPUT_CTRL);
	geni_write_reg(FORCE_DEFAULT, base, GENI_FORCE_DEFAULT_REG);
}

/**
 * geni_se_init() - Initialize the GENI Serial Engine
 * @base:	Base address of the serial engine's register block.
 * @rx_wm:	Receive watermark to be configured.
 * @rx_rfr_wm:	Ready-for-receive watermark to be configured.
 *
 * This function is used to initialize the GENI serial engine, configure
 * receive watermark and ready-for-receive watermarks.
 *
 * Return:	0 on success, standard Linux error codes on failure/error.
 */
int geni_se_init(void __iomem *base, unsigned int rx_wm, unsigned int rx_rfr)
{
	int ret;

	geni_se_io_init(base);
	ret = geni_se_io_set_mode(base);
	if (ret)
		return ret;

	geni_se_set_rx_rfr_wm(base, rx_wm, rx_rfr);
	ret = geni_se_irq_en(base);
	return ret;
}
EXPORT_SYMBOL(geni_se_init);

static int geni_se_select_fifo_mode(void __iomem *base)
{
	int proto = geni_se_get_proto(base);
	unsigned int common_geni_m_irq_en;
	unsigned int common_geni_s_irq_en;
	unsigned int geni_dma_mode;

	geni_write_reg(0, base, SE_GSI_EVENT_EN);
	geni_write_reg(0xFFFFFFFF, base, SE_GENI_M_IRQ_CLEAR);
	geni_write_reg(0xFFFFFFFF, base, SE_GENI_S_IRQ_CLEAR);
	geni_write_reg(0xFFFFFFFF, base, SE_DMA_TX_IRQ_CLR);
	geni_write_reg(0xFFFFFFFF, base, SE_DMA_RX_IRQ_CLR);
	geni_write_reg(0xFFFFFFFF, base, SE_IRQ_EN);

	common_geni_m_irq_en = geni_read_reg(base, SE_GENI_M_IRQ_EN);
	common_geni_s_irq_en = geni_read_reg(base, SE_GENI_S_IRQ_EN);
	geni_dma_mode = geni_read_reg(base, SE_GENI_DMA_MODE_EN);
	if (proto != UART) {
		common_geni_m_irq_en |=
			(M_CMD_DONE_EN | M_TX_FIFO_WATERMARK_EN |
			M_RX_FIFO_WATERMARK_EN | M_RX_FIFO_LAST_EN);
		common_geni_s_irq_en |= S_CMD_DONE_EN;
	}
	geni_dma_mode &= ~GENI_DMA_MODE_EN;

	geni_write_reg(common_geni_m_irq_en, base, SE_GENI_M_IRQ_EN);
	geni_write_reg(common_geni_s_irq_en, base, SE_GENI_S_IRQ_EN);
	geni_write_reg(geni_dma_mode, base, SE_GENI_DMA_MODE_EN);
	return 0;
}

static int geni_se_select_dma_mode(void __iomem *base)
{
	unsigned int geni_dma_mode = 0;

	geni_write_reg(0, base, SE_GSI_EVENT_EN);
	geni_write_reg(0xFFFFFFFF, base, SE_GENI_M_IRQ_CLEAR);
	geni_write_reg(0xFFFFFFFF, base, SE_GENI_S_IRQ_CLEAR);
	geni_write_reg(0xFFFFFFFF, base, SE_DMA_TX_IRQ_CLR);
	geni_write_reg(0xFFFFFFFF, base, SE_DMA_RX_IRQ_CLR);
	geni_write_reg(0xFFFFFFFF, base, SE_IRQ_EN);

	geni_dma_mode = geni_read_reg(base, SE_GENI_DMA_MODE_EN);
	geni_dma_mode |= GENI_DMA_MODE_EN;
	geni_write_reg(geni_dma_mode, base, SE_GENI_DMA_MODE_EN);
	return 0;
}

/**
 * geni_se_select_mode() - Select the serial engine transfer mode
 * @base:	Base address of the serial engine's register block.
 * @mode:	Transfer mode to be selected.
 *
 * Return:	0 on success, standard Linux error codes on failure.
 */
int geni_se_select_mode(void __iomem *base, int mode)
{
	int ret = 0;

	switch (mode) {
	case FIFO_MODE:
		geni_se_select_fifo_mode(base);
		break;
	case SE_DMA:
		geni_se_select_dma_mode(base);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}
EXPORT_SYMBOL(geni_se_select_mode);

/**
 * geni_se_setup_m_cmd() - Setup the primary sequencer
 * @base:	Base address of the serial engine's register block.
 * @cmd:	Command/Operation to setup in the primary sequencer.
 * @params:	Parameter for the sequencer command.
 *
 * This function is used to configure the primary sequencer with the
 * command and its assoicated parameters.
 */
void geni_se_setup_m_cmd(void __iomem *base, u32 cmd, u32 params)
{
	u32 m_cmd = (cmd << M_OPCODE_SHFT);

	m_cmd |= (params & M_PARAMS_MSK);
	geni_write_reg(m_cmd, base, SE_GENI_M_CMD0);
}
EXPORT_SYMBOL(geni_se_setup_m_cmd);

/**
 * geni_se_setup_s_cmd() - Setup the secondary sequencer
 * @base:	Base address of the serial engine's register block.
 * @cmd:	Command/Operation to setup in the secondary sequencer.
 * @params:	Parameter for the sequencer command.
 *
 * This function is used to configure the secondary sequencer with the
 * command and its assoicated parameters.
 */
void geni_se_setup_s_cmd(void __iomem *base, u32 cmd, u32 params)
{
	u32 s_cmd = geni_read_reg(base, SE_GENI_S_CMD0);

	s_cmd &= ~(S_OPCODE_MSK | S_PARAMS_MSK);
	s_cmd |= (cmd << S_OPCODE_SHFT);
	s_cmd |= (params & S_PARAMS_MSK);
	geni_write_reg(s_cmd, base, SE_GENI_S_CMD0);
}
EXPORT_SYMBOL(geni_se_setup_s_cmd);

/**
 * geni_se_cancel_m_cmd() - Cancel the command configured in the primary
 *                          sequencer
 * @base:	Base address of the serial engine's register block.
 *
 * This function is used to cancel the currently configured command in the
 * primary sequencer.
 */
void geni_se_cancel_m_cmd(void __iomem *base)
{
	geni_write_reg(M_GENI_CMD_CANCEL, base, SE_GENI_M_CMD_CTRL_REG);
}
EXPORT_SYMBOL(geni_se_cancel_m_cmd);

/**
 * geni_se_cancel_s_cmd() - Cancel the command configured in the secondary
 *                          sequencer
 * @base:	Base address of the serial engine's register block.
 *
 * This function is used to cancel the currently configured command in the
 * secondary sequencer.
 */
void geni_se_cancel_s_cmd(void __iomem *base)
{
	geni_write_reg(S_GENI_CMD_CANCEL, base, SE_GENI_S_CMD_CTRL_REG);
}
EXPORT_SYMBOL(geni_se_cancel_s_cmd);

/**
 * geni_se_abort_m_cmd() - Abort the command configured in the primary sequencer
 * @base:	Base address of the serial engine's register block.
 *
 * This function is used to force abort the currently configured command in the
 * primary sequencer.
 */
void geni_se_abort_m_cmd(void __iomem *base)
{
	geni_write_reg(M_GENI_CMD_ABORT, base, SE_GENI_M_CMD_CTRL_REG);
}
EXPORT_SYMBOL(geni_se_abort_m_cmd);

/**
 * geni_se_abort_s_cmd() - Abort the command configured in the secondary
 *                         sequencer
 * @base:	Base address of the serial engine's register block.
 *
 * This function is used to force abort the currently configured command in the
 * secondary sequencer.
 */
void geni_se_abort_s_cmd(void __iomem *base)
{
	geni_write_reg(S_GENI_CMD_ABORT, base, SE_GENI_S_CMD_CTRL_REG);
}
EXPORT_SYMBOL(geni_se_abort_s_cmd);

/**
 * geni_se_get_tx_fifo_depth() - Get the TX fifo depth of the serial engine
 * @base:	Base address of the serial engine's register block.
 *
 * This function is used to get the depth i.e. number of elements in the
 * TX fifo of the serial engine.
 *
 * Return:	TX fifo depth in units of FIFO words.
 */
int geni_se_get_tx_fifo_depth(void __iomem *base)
{
	int tx_fifo_depth;

	tx_fifo_depth = ((geni_read_reg(base, SE_HW_PARAM_0)
			& TX_FIFO_DEPTH_MSK) >> TX_FIFO_DEPTH_SHFT);
	return tx_fifo_depth;
}
EXPORT_SYMBOL(geni_se_get_tx_fifo_depth);

/**
 * geni_se_get_tx_fifo_width() - Get the TX fifo width of the serial engine
 * @base:	Base address of the serial engine's register block.
 *
 * This function is used to get the width i.e. word size per element in the
 * TX fifo of the serial engine.
 *
 * Return:	TX fifo width in bits
 */
int geni_se_get_tx_fifo_width(void __iomem *base)
{
	int tx_fifo_width;

	tx_fifo_width = ((geni_read_reg(base, SE_HW_PARAM_0)
			& TX_FIFO_WIDTH_MSK) >> TX_FIFO_WIDTH_SHFT);
	return tx_fifo_width;
}
EXPORT_SYMBOL(geni_se_get_tx_fifo_width);

/**
 * geni_se_get_rx_fifo_depth() - Get the RX fifo depth of the serial engine
 * @base:	Base address of the serial engine's register block.
 *
 * This function is used to get the depth i.e. number of elements in the
 * RX fifo of the serial engine.
 *
 * Return:	RX fifo depth in units of FIFO words
 */
int geni_se_get_rx_fifo_depth(void __iomem *base)
{
	int rx_fifo_depth;

	rx_fifo_depth = ((geni_read_reg(base, SE_HW_PARAM_1)
			& RX_FIFO_DEPTH_MSK) >> RX_FIFO_DEPTH_SHFT);
	return rx_fifo_depth;
}
EXPORT_SYMBOL(geni_se_get_rx_fifo_depth);

/**
 * geni_se_get_packing_config() - Get the packing configuration based on input
 * @bpw:	Bits of data per transfer word.
 * @pack_words:	Number of words per fifo element.
 * @msb_to_lsb:	Transfer from MSB to LSB or vice-versa.
 * @cfg0:	Output buffer to hold the first half of configuration.
 * @cfg1:	Output buffer to hold the second half of configuration.
 *
 * This function is used to calculate the packing configuration based on
 * the input packing requirement and the configuration logic.
 */
void geni_se_get_packing_config(int bpw, int pack_words, bool msb_to_lsb,
				unsigned long *cfg0, unsigned long *cfg1)
{
	u32 cfg[4] = {0};
	int len;
	int temp_bpw = bpw;
	int idx_start = (msb_to_lsb ? (bpw - 1) : 0);
	int idx = idx_start;
	int idx_delta = (msb_to_lsb ? -BITS_PER_BYTE : BITS_PER_BYTE);
	int ceil_bpw = ((bpw & (BITS_PER_BYTE - 1)) ?
			((bpw & ~(BITS_PER_BYTE - 1)) + BITS_PER_BYTE) : bpw);
	int iter = (ceil_bpw * pack_words) >> 3;
	int i;

	if (unlikely(iter <= 0 || iter > 4)) {
		*cfg0 = 0;
		*cfg1 = 0;
		return;
	}

	for (i = 0; i < iter; i++) {
		len = (temp_bpw < BITS_PER_BYTE) ?
				(temp_bpw - 1) : BITS_PER_BYTE - 1;
		cfg[i] = ((idx << 5) | (msb_to_lsb << 4) | (len << 1));
		idx = ((temp_bpw - BITS_PER_BYTE) <= 0) ?
				((i + 1) * BITS_PER_BYTE) + idx_start :
				idx + idx_delta;
		temp_bpw = ((temp_bpw - BITS_PER_BYTE) <= 0) ?
				bpw : (temp_bpw - BITS_PER_BYTE);
	}
	cfg[iter - 1] |= 1;
	*cfg0 = cfg[0] | (cfg[1] << 10);
	*cfg1 = cfg[2] | (cfg[3] << 10);
}
EXPORT_SYMBOL(geni_se_get_packing_config);

/**
 * geni_se_config_packing() - Packing configuration of the serial engine
 * @base:	Base address of the serial engine's register block.
 * @bpw:	Bits of data per transfer word.
 * @pack_words:	Number of words per fifo element.
 * @msb_to_lsb:	Transfer from MSB to LSB or vice-versa.
 *
 * This function is used to configure the packing rules for the current
 * transfer.
 */
void geni_se_config_packing(void __iomem *base, int bpw,
			    int pack_words, bool msb_to_lsb)
{
	unsigned long cfg0, cfg1;

	geni_se_get_packing_config(bpw, pack_words, msb_to_lsb, &cfg0, &cfg1);
	geni_write_reg(cfg0, base, SE_GENI_TX_PACKING_CFG0);
	geni_write_reg(cfg1, base, SE_GENI_TX_PACKING_CFG1);
	geni_write_reg(cfg0, base, SE_GENI_RX_PACKING_CFG0);
	geni_write_reg(cfg1, base, SE_GENI_RX_PACKING_CFG1);
	if (pack_words || bpw == 32)
		geni_write_reg((bpw >> 4), base, SE_GENI_BYTE_GRAN);
}
EXPORT_SYMBOL(geni_se_config_packing);

static void geni_se_clks_off(struct geni_se_rsc *rsc)
{
	struct geni_se_device *geni_se_dev;

	if (unlikely(!rsc || !rsc->wrapper_dev))
		return;

	geni_se_dev = dev_get_drvdata(rsc->wrapper_dev);
	if (unlikely(!geni_se_dev))
		return;

	clk_disable_unprepare(rsc->se_clk);
	clk_disable_unprepare(geni_se_dev->s_ahb_clk);
	clk_disable_unprepare(geni_se_dev->m_ahb_clk);
}

/**
 * geni_se_resources_off() - Turn off resources associated with the serial
 *                           engine
 * @rsc:	Handle to resources associated with the serial engine.
 *
 * Return:	0 on success, standard Linux error codes on failure/error.
 */
int geni_se_resources_off(struct geni_se_rsc *rsc)
{
	int ret = 0;
	struct geni_se_device *geni_se_dev;

	if (unlikely(!rsc || !rsc->wrapper_dev))
		return -EINVAL;

	geni_se_dev = dev_get_drvdata(rsc->wrapper_dev);
	if (unlikely(!geni_se_dev))
		return -ENODEV;

	ret = pinctrl_select_state(rsc->geni_pinctrl, rsc->geni_gpio_sleep);
	if (ret)
		return ret;

	geni_se_clks_off(rsc);
	return 0;
}
EXPORT_SYMBOL(geni_se_resources_off);

static int geni_se_clks_on(struct geni_se_rsc *rsc)
{
	int ret;
	struct geni_se_device *geni_se_dev;

	if (unlikely(!rsc || !rsc->wrapper_dev))
		return -EINVAL;

	geni_se_dev = dev_get_drvdata(rsc->wrapper_dev);
	if (unlikely(!geni_se_dev))
		return -EPROBE_DEFER;

	ret = clk_prepare_enable(geni_se_dev->m_ahb_clk);
	if (ret)
		return ret;

	ret = clk_prepare_enable(geni_se_dev->s_ahb_clk);
	if (ret) {
		clk_disable_unprepare(geni_se_dev->m_ahb_clk);
		return ret;
	}

	ret = clk_prepare_enable(rsc->se_clk);
	if (ret) {
		clk_disable_unprepare(geni_se_dev->s_ahb_clk);
		clk_disable_unprepare(geni_se_dev->m_ahb_clk);
	}
	return ret;
}

/**
 * geni_se_resources_on() - Turn on resources associated with the serial
 *                          engine
 * @rsc:	Handle to resources associated with the serial engine.
 *
 * Return:	0 on success, standard Linux error codes on failure/error.
 */
int geni_se_resources_on(struct geni_se_rsc *rsc)
{
	int ret = 0;
	struct geni_se_device *geni_se_dev;

	if (unlikely(!rsc || !rsc->wrapper_dev))
		return -EINVAL;

	geni_se_dev = dev_get_drvdata(rsc->wrapper_dev);
	if (unlikely(!geni_se_dev))
		return -EPROBE_DEFER;

	ret = geni_se_clks_on(rsc);
	if (ret)
		return ret;

	ret = pinctrl_select_state(rsc->geni_pinctrl, rsc->geni_gpio_active);
	if (ret)
		geni_se_clks_off(rsc);

	return ret;
}
EXPORT_SYMBOL(geni_se_resources_on);

/**
 * geni_se_clk_tbl_get() - Get the clock table to program DFS
 * @rsc:	Resource for which the clock table is requested.
 * @tbl:	Table in which the output is returned.
 *
 * This function is called by the protocol drivers to determine the different
 * clock frequencies supported by Serail Engine Core Clock. The protocol
 * drivers use the output to determine the clock frequency index to be
 * programmed into DFS.
 *
 * Return:	number of valid performance levels in the table on success,
 *		standard Linux error codes on failure.
 */
int geni_se_clk_tbl_get(struct geni_se_rsc *rsc, unsigned long **tbl)
{
	struct geni_se_device *geni_se_dev;
	int i;
	unsigned long prev_freq = 0;
	int ret = 0;

	if (unlikely(!rsc || !rsc->wrapper_dev || !rsc->se_clk || !tbl))
		return -EINVAL;

	*tbl = NULL;
	geni_se_dev = dev_get_drvdata(rsc->wrapper_dev);
	if (unlikely(!geni_se_dev))
		return -EPROBE_DEFER;

	mutex_lock(&geni_se_dev->geni_dev_lock);
	if (geni_se_dev->clk_perf_tbl) {
		*tbl = geni_se_dev->clk_perf_tbl;
		ret = geni_se_dev->num_clk_levels;
		goto exit_se_clk_tbl_get;
	}

	geni_se_dev->clk_perf_tbl = kzalloc(sizeof(*geni_se_dev->clk_perf_tbl) *
						MAX_CLK_PERF_LEVEL, GFP_KERNEL);
	if (!geni_se_dev->clk_perf_tbl) {
		ret = -ENOMEM;
		goto exit_se_clk_tbl_get;
	}

	for (i = 0; i < MAX_CLK_PERF_LEVEL; i++) {
		geni_se_dev->clk_perf_tbl[i] = clk_round_rate(rsc->se_clk,
								prev_freq + 1);
		if (geni_se_dev->clk_perf_tbl[i] == prev_freq) {
			geni_se_dev->clk_perf_tbl[i] = 0;
			break;
		}
		prev_freq = geni_se_dev->clk_perf_tbl[i];
	}
	geni_se_dev->num_clk_levels = i;
	*tbl = geni_se_dev->clk_perf_tbl;
	ret = geni_se_dev->num_clk_levels;
exit_se_clk_tbl_get:
	mutex_unlock(&geni_se_dev->geni_dev_lock);
	return ret;
}
EXPORT_SYMBOL(geni_se_clk_tbl_get);

/**
 * geni_se_clk_freq_match() - Get the matching or closest SE clock frequency
 * @rsc:	Resource for which the clock frequency is requested.
 * @req_freq:	Requested clock frequency.
 * @index:	Index of the resultant frequency in the table.
 * @res_freq:	Resultant frequency which matches or is closer to the
 *		requested frequency.
 * @exact:	Flag to indicate exact multiple requirement of the requested
 *		frequency .
 *
 * This function is called by the protocol drivers to determine the matching
 * or closest frequency of the Serial Engine clock to be selected in order
 * to meet the performance requirements.
 *
 * Return:	0 on success, standard Linux error codes on failure.
 */
int geni_se_clk_freq_match(struct geni_se_rsc *rsc, unsigned long req_freq,
			   unsigned int *index, unsigned long *res_freq,
			   bool exact)
{
	unsigned long *tbl;
	int num_clk_levels;
	int i;

	num_clk_levels = geni_se_clk_tbl_get(rsc, &tbl);
	if (num_clk_levels < 0)
		return num_clk_levels;

	if (num_clk_levels == 0)
		return -EFAULT;

	*res_freq = 0;
	for (i = 0; i < num_clk_levels; i++) {
		if (!(tbl[i] % req_freq)) {
			*index = i;
			*res_freq = tbl[i];
			return 0;
		}

		if (!(*res_freq) || ((tbl[i] > *res_freq) &&
				     (tbl[i] < req_freq))) {
			*index = i;
			*res_freq = tbl[i];
		}
	}

	if (exact || !(*res_freq))
		return -ENOKEY;

	return 0;
}
EXPORT_SYMBOL(geni_se_clk_freq_match);

/**
 * geni_se_tx_dma_prep() - Prepare the Serial Engine for TX DMA transfer
 * @wrapper_dev:	QUP Wrapper Device to which the TX buffer is mapped.
 * @base:		Base address of the SE register block.
 * @tx_buf:		Pointer to the TX buffer.
 * @tx_len:		Length of the TX buffer.
 * @tx_dma:		Pointer to store the mapped DMA address.
 *
 * This function is used to prepare the buffers for DMA TX.
 *
 * Return:	0 on success, standard Linux error codes on error/failure.
 */
int geni_se_tx_dma_prep(struct device *wrapper_dev, void __iomem *base,
			void *tx_buf, int tx_len, dma_addr_t *tx_dma)
{
	int ret;

	if (unlikely(!wrapper_dev || !base || !tx_buf || !tx_len || !tx_dma))
		return -EINVAL;

	ret = geni_se_map_buf(wrapper_dev, tx_dma, tx_buf, tx_len,
				    DMA_TO_DEVICE);
	if (ret)
		return ret;

	geni_write_reg(7, base, SE_DMA_TX_IRQ_EN_SET);
	geni_write_reg((u32)(*tx_dma), base, SE_DMA_TX_PTR_L);
	geni_write_reg((u32)((*tx_dma) >> 32), base, SE_DMA_TX_PTR_H);
	geni_write_reg(1, base, SE_DMA_TX_ATTR);
	geni_write_reg(tx_len, base, SE_DMA_TX_LEN);
	return 0;
}
EXPORT_SYMBOL(geni_se_tx_dma_prep);

/**
 * geni_se_rx_dma_prep() - Prepare the Serial Engine for RX DMA transfer
 * @wrapper_dev:	QUP Wrapper Device to which the RX buffer is mapped.
 * @base:		Base address of the SE register block.
 * @rx_buf:		Pointer to the RX buffer.
 * @rx_len:		Length of the RX buffer.
 * @rx_dma:		Pointer to store the mapped DMA address.
 *
 * This function is used to prepare the buffers for DMA RX.
 *
 * Return:	0 on success, standard Linux error codes on error/failure.
 */
int geni_se_rx_dma_prep(struct device *wrapper_dev, void __iomem *base,
			void *rx_buf, int rx_len, dma_addr_t *rx_dma)
{
	int ret;

	if (unlikely(!wrapper_dev || !base || !rx_buf || !rx_len || !rx_dma))
		return -EINVAL;

	ret = geni_se_map_buf(wrapper_dev, rx_dma, rx_buf, rx_len,
				    DMA_FROM_DEVICE);
	if (ret)
		return ret;

	geni_write_reg(7, base, SE_DMA_RX_IRQ_EN_SET);
	geni_write_reg((u32)(*rx_dma), base, SE_DMA_RX_PTR_L);
	geni_write_reg((u32)((*rx_dma) >> 32), base, SE_DMA_RX_PTR_H);
	/* RX does not have EOT bit */
	geni_write_reg(0, base, SE_DMA_RX_ATTR);
	geni_write_reg(rx_len, base, SE_DMA_RX_LEN);
	return 0;
}
EXPORT_SYMBOL(geni_se_rx_dma_prep);

/**
 * geni_se_tx_dma_unprep() - Unprepare the Serial Engine after TX DMA transfer
 * @wrapper_dev:	QUP Wrapper Device to which the RX buffer is mapped.
 * @tx_dma:		DMA address of the TX buffer.
 * @tx_len:		Length of the TX buffer.
 *
 * This function is used to unprepare the DMA buffers after DMA TX.
 */
void geni_se_tx_dma_unprep(struct device *wrapper_dev,
			   dma_addr_t tx_dma, int tx_len)
{
	if (tx_dma)
		geni_se_unmap_buf(wrapper_dev, &tx_dma, tx_len,
						DMA_TO_DEVICE);
}
EXPORT_SYMBOL(geni_se_tx_dma_unprep);

/**
 * geni_se_rx_dma_unprep() - Unprepare the Serial Engine after RX DMA transfer
 * @wrapper_dev:	QUP Wrapper Device to which the RX buffer is mapped.
 * @rx_dma:		DMA address of the RX buffer.
 * @rx_len:		Length of the RX buffer.
 *
 * This function is used to unprepare the DMA buffers after DMA RX.
 */
void geni_se_rx_dma_unprep(struct device *wrapper_dev,
			   dma_addr_t rx_dma, int rx_len)
{
	if (rx_dma)
		geni_se_unmap_buf(wrapper_dev, &rx_dma, rx_len,
						DMA_FROM_DEVICE);
}
EXPORT_SYMBOL(geni_se_rx_dma_unprep);

/**
 * geni_se_map_buf() - Map a single buffer into QUP wrapper device
 * @wrapper_dev:	Pointer to the corresponding QUP wrapper core.
 * @iova:		Pointer in which the mapped virtual address is stored.
 * @buf:		Address of the buffer that needs to be mapped.
 * @size:		Size of the buffer.
 * @dir:		Direction of the DMA transfer.
 *
 * This function is used to map an already allocated buffer into the
 * QUP device space.
 *
 * Return:	0 on success, standard Linux error codes on failure/error.
 */
int geni_se_map_buf(struct device *wrapper_dev, dma_addr_t *iova,
		    void *buf, size_t size, enum dma_data_direction dir)
{
	struct device *dev_p;
	struct geni_se_device *geni_se_dev;

	if (!wrapper_dev || !iova || !buf || !size)
		return -EINVAL;

	geni_se_dev = dev_get_drvdata(wrapper_dev);
	if (!geni_se_dev || !geni_se_dev->dev)
		return -ENODEV;

	dev_p = geni_se_dev->dev;

	*iova = dma_map_single(dev_p, buf, size, dir);
	if (dma_mapping_error(dev_p, *iova))
		return -EIO;
	return 0;
}
EXPORT_SYMBOL(geni_se_map_buf);

/**
 * geni_se_unmap_buf() - Unmap a single buffer from QUP wrapper device
 * @wrapper_dev:	Pointer to the corresponding QUP wrapper core.
 * @iova:		Pointer in which the mapped virtual address is stored.
 * @size:		Size of the buffer.
 * @dir:		Direction of the DMA transfer.
 *
 * This function is used to unmap an already mapped buffer from the
 * QUP device space.
 *
 * Return:	0 on success, standard Linux error codes on failure/error.
 */
int geni_se_unmap_buf(struct device *wrapper_dev, dma_addr_t *iova,
		      size_t size, enum dma_data_direction dir)
{
	struct device *dev_p;
	struct geni_se_device *geni_se_dev;

	if (!wrapper_dev || !iova || !size)
		return -EINVAL;

	geni_se_dev = dev_get_drvdata(wrapper_dev);
	if (!geni_se_dev || !geni_se_dev->dev)
		return -ENODEV;

	dev_p = geni_se_dev->dev;
	dma_unmap_single(dev_p, *iova, size, dir);
	return 0;
}
EXPORT_SYMBOL(geni_se_unmap_buf);

static const struct of_device_id geni_se_dt_match[] = {
	{ .compatible = "qcom,geni-se-qup", },
	{}
};

static int geni_se_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct resource *res;
	struct geni_se_device *geni_se_dev;
	int ret = 0;

	geni_se_dev = devm_kzalloc(dev, sizeof(*geni_se_dev), GFP_KERNEL);
	if (!geni_se_dev)
		return -ENOMEM;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!res) {
		dev_err(dev, "%s: Mandatory resource info not found\n",
			__func__);
		devm_kfree(dev, geni_se_dev);
		return -EINVAL;
	}

	geni_se_dev->base = devm_ioremap_resource(dev, res);
	if (IS_ERR_OR_NULL(geni_se_dev->base)) {
		dev_err(dev, "%s: Error mapping the resource\n", __func__);
		devm_kfree(dev, geni_se_dev);
		return -EFAULT;
	}

	geni_se_dev->m_ahb_clk = devm_clk_get(dev, "m-ahb");
	if (IS_ERR(geni_se_dev->m_ahb_clk)) {
		ret = PTR_ERR(geni_se_dev->m_ahb_clk);
		dev_err(dev, "Err getting M AHB clk %d\n", ret);
		devm_iounmap(dev, geni_se_dev->base);
		devm_kfree(dev, geni_se_dev);
		return ret;
	}

	geni_se_dev->s_ahb_clk = devm_clk_get(dev, "s-ahb");
	if (IS_ERR(geni_se_dev->s_ahb_clk)) {
		ret = PTR_ERR(geni_se_dev->s_ahb_clk);
		dev_err(dev, "Err getting S AHB clk %d\n", ret);
		devm_clk_put(dev, geni_se_dev->m_ahb_clk);
		devm_iounmap(dev, geni_se_dev->base);
		devm_kfree(dev, geni_se_dev);
		return ret;
	}

	geni_se_dev->dev = dev;
	mutex_init(&geni_se_dev->geni_dev_lock);
	dev_set_drvdata(dev, geni_se_dev);
	dev_dbg(dev, "GENI SE Driver probed\n");
	return of_platform_populate(pdev->dev.of_node, NULL, NULL, &pdev->dev);
}

static int geni_se_remove(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct geni_se_device *geni_se_dev = dev_get_drvdata(dev);

	devm_clk_put(dev, geni_se_dev->s_ahb_clk);
	devm_clk_put(dev, geni_se_dev->m_ahb_clk);
	devm_iounmap(dev, geni_se_dev->base);
	devm_kfree(dev, geni_se_dev);
	return 0;
}

static struct platform_driver geni_se_driver = {
	.driver = {
		.name = "geni_se_qup",
		.of_match_table = geni_se_dt_match,
	},
	.probe = geni_se_probe,
	.remove = geni_se_remove,
};

static int __init geni_se_driver_init(void)
{
	return platform_driver_register(&geni_se_driver);
}
arch_initcall(geni_se_driver_init);

static void __exit geni_se_driver_exit(void)
{
	platform_driver_unregister(&geni_se_driver);
}
module_exit(geni_se_driver_exit);

MODULE_DESCRIPTION("GENI Serial Engine Driver");
MODULE_LICENSE("GPL v2");
