/*
 * Copyright (c) 2017-2018, The Linux foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/bitmap.h>
#include <linux/bitops.h>
#include <linux/delay.h>
#include <linux/console.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/platform_device.h>
#include <linux/qcom-geni-se.h>
#include <linux/serial.h>
#include <linux/serial_core.h>
#include <linux/slab.h>
#include <linux/tty.h>
#include <linux/tty_flip.h>

/* UART specific GENI registers */
#define SE_UART_TX_TRANS_CFG		(0x25C)
#define SE_UART_TX_WORD_LEN		(0x268)
#define SE_UART_TX_STOP_BIT_LEN		(0x26C)
#define SE_UART_TX_TRANS_LEN		(0x270)
#define SE_UART_RX_TRANS_CFG		(0x280)
#define SE_UART_RX_WORD_LEN		(0x28C)
#define SE_UART_RX_STALE_CNT		(0x294)
#define SE_UART_TX_PARITY_CFG		(0x2A4)
#define SE_UART_RX_PARITY_CFG		(0x2A8)

/* SE_UART_TRANS_CFG */
#define UART_TX_PAR_EN		(BIT(0))
#define UART_CTS_MASK		(BIT(1))

/* SE_UART_TX_WORD_LEN */
#define TX_WORD_LEN_MSK		(GENMASK(9, 0))

/* SE_UART_TX_STOP_BIT_LEN */
#define TX_STOP_BIT_LEN_MSK	(GENMASK(23, 0))
#define TX_STOP_BIT_LEN_1	(0)
#define TX_STOP_BIT_LEN_1_5	(1)
#define TX_STOP_BIT_LEN_2	(2)

/* SE_UART_TX_TRANS_LEN */
#define TX_TRANS_LEN_MSK	(GENMASK(23, 0))

/* SE_UART_RX_TRANS_CFG */
#define UART_RX_INS_STATUS_BIT	(BIT(2))
#define UART_RX_PAR_EN		(BIT(3))

/* SE_UART_RX_WORD_LEN */
#define RX_WORD_LEN_MASK	(GENMASK(9, 0))

/* SE_UART_RX_STALE_CNT */
#define RX_STALE_CNT		(GENMASK(23, 0))

/* SE_UART_TX_PARITY_CFG/RX_PARITY_CFG */
#define PAR_CALC_EN		(BIT(0))
#define PAR_MODE_MSK		(GENMASK(2, 1))
#define PAR_MODE_SHFT		(1)
#define PAR_EVEN		(0x00)
#define PAR_ODD			(0x01)
#define PAR_SPACE		(0x10)
#define PAR_MARK		(0x11)

/* UART M_CMD OP codes */
#define UART_START_TX		(0x1)
#define UART_START_BREAK	(0x4)
#define UART_STOP_BREAK		(0x5)
/* UART S_CMD OP codes */
#define UART_START_READ		(0x1)
#define UART_PARAM		(0x1)

#define UART_OVERSAMPLING	(32)
#define STALE_TIMEOUT		(16)
#define DEFAULT_BITS_PER_CHAR	(10)
#define GENI_UART_NR_PORTS	(15)
#define GENI_UART_CONS_PORTS	(1)
#define DEF_FIFO_DEPTH_WORDS	(16)
#define DEF_TX_WM		(2)
#define DEF_FIFO_WIDTH_BITS	(32)
#define UART_CORE2X_VOTE	(10000)
#define UART_CONSOLE_RX_WM	(2)

static int owr;
module_param(owr, int, 0644);

struct qcom_geni_serial_port {
	struct uart_port uport;
	char name[20];
	unsigned int tx_fifo_depth;
	unsigned int tx_fifo_width;
	unsigned int rx_fifo_depth;
	unsigned int tx_wm;
	unsigned int rx_wm;
	unsigned int rx_rfr;
	int xfer_mode;
	bool port_setup;
	unsigned int *rx_fifo;
	int (*handle_rx)(struct uart_port *uport,
			unsigned int rx_fifo_wc,
			unsigned int rx_last_byte_valid,
			unsigned int rx_last,
			bool drop_rx);
	struct device *wrapper_dev;
	struct geni_se_rsc serial_rsc;
	unsigned int xmit_size;
	void *rx_buf;
	unsigned int cur_baud;
};

static const struct uart_ops qcom_geni_serial_pops;
static struct uart_driver qcom_geni_console_driver;
static int handle_rx_console(struct uart_port *uport,
			unsigned int rx_fifo_wc,
			unsigned int rx_last_byte_valid,
			unsigned int rx_last,
			bool drop_rx);
static unsigned int qcom_geni_serial_tx_empty(struct uart_port *port);
static int qcom_geni_serial_poll_bit(struct uart_port *uport,
				int offset, int bit_field, bool set);
static void qcom_geni_serial_stop_rx(struct uart_port *uport);

static atomic_t uart_line_id = ATOMIC_INIT(0);

#define GET_DEV_PORT(uport) \
	container_of(uport, struct qcom_geni_serial_port, uport)

static struct qcom_geni_serial_port qcom_geni_console_port;

static void qcom_geni_serial_config_port(struct uart_port *uport, int cfg_flags)
{
	if (cfg_flags & UART_CONFIG_TYPE)
		uport->type = PORT_MSM;
}

static unsigned int qcom_geni_cons_get_mctrl(struct uart_port *uport)
{
	return TIOCM_DSR | TIOCM_CAR | TIOCM_CTS;
}

static void qcom_geni_cons_set_mctrl(struct uart_port *uport,
							unsigned int mctrl)
{
}

static const char *qcom_geni_serial_get_type(struct uart_port *uport)
{
	return "MSM";
}

static struct qcom_geni_serial_port *get_port_from_line(int line)
{
	struct qcom_geni_serial_port *port = NULL;

	if ((line < 0) || (line >= GENI_UART_CONS_PORTS))
		port = ERR_PTR(-ENXIO);
	port = &qcom_geni_console_port;
	return port;
}

static int qcom_geni_serial_poll_bit(struct uart_port *uport,
				int offset, int bit_field, bool set)
{
	int iter = 0;
	unsigned int reg;
	bool met = false;
	struct qcom_geni_serial_port *port = NULL;
	bool cond = false;
	unsigned int baud = 115200;
	unsigned int fifo_bits = DEF_FIFO_DEPTH_WORDS * DEF_FIFO_WIDTH_BITS;
	unsigned long total_iter = 2000;


	if (uport->private_data) {
		port = GET_DEV_PORT(uport);
		baud = (port->cur_baud ? port->cur_baud : 115200);
		fifo_bits = port->tx_fifo_depth * port->tx_fifo_width;
		/*
		 * Total polling iterations based on FIFO worth of bytes to be
		 * sent at current baud .Add a little fluff to the wait.
		 */
		total_iter = ((fifo_bits * USEC_PER_SEC) / baud) / 10;
		total_iter += 50;
	}

	while (iter < total_iter) {
		reg = geni_read_reg_nolog(uport->membase, offset);
		cond = reg & bit_field;
		if (cond == set) {
			met = true;
			break;
		}
		udelay(10);
		iter++;
	}
	return met;
}

static void qcom_geni_serial_setup_tx(struct uart_port *uport,
				unsigned int xmit_size)
{
	u32 m_cmd = 0;

	geni_write_reg_nolog(xmit_size, uport->membase, SE_UART_TX_TRANS_LEN);
	m_cmd |= (UART_START_TX << M_OPCODE_SHFT);
	geni_write_reg_nolog(m_cmd, uport->membase, SE_GENI_M_CMD0);
	/*
	 * Writes to enable the primary sequencer should go through before
	 * exiting this function.
	 */
	mb();
}

static void qcom_geni_serial_poll_cancel_tx(struct uart_port *uport)
{
	int done = 0;
	unsigned int irq_clear = M_CMD_DONE_EN;
	unsigned int geni_status = 0;

	done = qcom_geni_serial_poll_bit(uport, SE_GENI_M_IRQ_STATUS,
						M_CMD_DONE_EN, true);
	if (!done) {
		geni_write_reg_nolog(M_GENI_CMD_ABORT, uport->membase,
					SE_GENI_M_CMD_CTRL_REG);
		owr++;
		irq_clear |= M_CMD_ABORT_EN;
		qcom_geni_serial_poll_bit(uport, SE_GENI_M_IRQ_STATUS,
							M_CMD_ABORT_EN, true);
	}
	geni_status = geni_read_reg_nolog(uport->membase,
						  SE_GENI_STATUS);
	if (geni_status & M_GENI_CMD_ACTIVE)
		owr++;
	geni_write_reg_nolog(irq_clear, uport->membase, SE_GENI_M_IRQ_CLEAR);
}

static void qcom_geni_serial_abort_rx(struct uart_port *uport)
{
	unsigned int irq_clear = S_CMD_DONE_EN;

	geni_se_abort_s_cmd(uport->membase);
	/* Ensure this goes through before polling. */
	mb();
	irq_clear |= S_CMD_ABORT_EN;
	qcom_geni_serial_poll_bit(uport, SE_GENI_S_CMD_CTRL_REG,
					S_GENI_CMD_ABORT, false);
	geni_write_reg_nolog(irq_clear, uport->membase, SE_GENI_S_IRQ_CLEAR);
	geni_write_reg(FORCE_DEFAULT, uport->membase, GENI_FORCE_DEFAULT_REG);
}

#ifdef CONFIG_CONSOLE_POLL
static int qcom_geni_serial_get_char(struct uart_port *uport)
{
	unsigned int rx_fifo;
	unsigned int m_irq_status;
	unsigned int s_irq_status;

	if (!(qcom_geni_serial_poll_bit(uport, SE_GENI_M_IRQ_STATUS,
			M_SEC_IRQ_EN, true)))
		return -ENXIO;

	m_irq_status = geni_read_reg_nolog(uport->membase,
						SE_GENI_M_IRQ_STATUS);
	s_irq_status = geni_read_reg_nolog(uport->membase,
						SE_GENI_S_IRQ_STATUS);
	geni_write_reg_nolog(m_irq_status, uport->membase,
						SE_GENI_M_IRQ_CLEAR);
	geni_write_reg_nolog(s_irq_status, uport->membase,
						SE_GENI_S_IRQ_CLEAR);

	if (!(qcom_geni_serial_poll_bit(uport, SE_GENI_RX_FIFO_STATUS,
			RX_FIFO_WC_MSK, true)))
		return -ENXIO;

	/*
	 * Read the Rx FIFO only after clearing the interrupt registers and
	 * getting valid RX fifo status.
	 */
	mb();
	rx_fifo = geni_read_reg_nolog(uport->membase, SE_GENI_RX_FIFOn);
	rx_fifo &= 0xFF;
	return rx_fifo;
}

static void qcom_geni_serial_poll_put_char(struct uart_port *uport,
					unsigned char c)
{
	int b = (int) c;
	struct qcom_geni_serial_port *port = GET_DEV_PORT(uport);

	geni_write_reg_nolog(port->tx_wm, uport->membase,
					SE_GENI_TX_WATERMARK_REG);
	qcom_geni_serial_setup_tx(uport, 1);
	if (!qcom_geni_serial_poll_bit(uport, SE_GENI_M_IRQ_STATUS,
				M_TX_FIFO_WATERMARK_EN, true))
		WARN_ON(1);
	geni_write_reg_nolog(b, uport->membase, SE_GENI_TX_FIFOn);
	geni_write_reg_nolog(M_TX_FIFO_WATERMARK_EN, uport->membase,
							SE_GENI_M_IRQ_CLEAR);
	/*
	 * Ensure FIFO write goes through before polling for status but.
	 */
	mb();
	qcom_geni_serial_poll_cancel_tx(uport);
}
#endif

#if defined(CONFIG_SERIAL_CORE_CONSOLE) || defined(CONFIG_CONSOLE_POLL)
static void qcom_geni_serial_wr_char(struct uart_port *uport, int ch)
{
	geni_write_reg_nolog(ch, uport->membase, SE_GENI_TX_FIFOn);
	/*
	 * Ensure FIFO write clear goes through before
	 * next iteration.
	 */
	mb();

}

static void
__qcom_geni_serial_console_write(struct uart_port *uport, const char *s,
				unsigned int count)
{
	int new_line = 0;
	int i;
	int bytes_to_send = count;
	int fifo_depth = DEF_FIFO_DEPTH_WORDS;
	int tx_wm = DEF_TX_WM;

	for (i = 0; i < count; i++) {
		if (s[i] == '\n')
			new_line++;
	}

	bytes_to_send += new_line;
	geni_write_reg_nolog(tx_wm, uport->membase,
					SE_GENI_TX_WATERMARK_REG);
	qcom_geni_serial_setup_tx(uport, bytes_to_send);
	i = 0;
	while (i < count) {
		u32 chars_to_write = 0;
		u32 avail_fifo_bytes = (fifo_depth - tx_wm);

		/*
		 * If the WM bit never set, then the Tx state machine is not
		 * in a valid state, so break, cancel/abort any existing
		 * command. Unfortunately the current data being written is
		 * lost.
		 */
		while (!qcom_geni_serial_poll_bit(uport, SE_GENI_M_IRQ_STATUS,
						M_TX_FIFO_WATERMARK_EN, true))
			break;
		chars_to_write = min((unsigned int)(count - i),
							avail_fifo_bytes);
		if ((chars_to_write << 1) > avail_fifo_bytes)
			chars_to_write = (avail_fifo_bytes >> 1);
		uart_console_write(uport, (s + i), chars_to_write,
						qcom_geni_serial_wr_char);
		geni_write_reg_nolog(M_TX_FIFO_WATERMARK_EN, uport->membase,
							SE_GENI_M_IRQ_CLEAR);
		/* Ensure this goes through before polling for WM IRQ again.*/
		mb();
		i += chars_to_write;
	}
	qcom_geni_serial_poll_cancel_tx(uport);
}

static void qcom_geni_serial_console_write(struct console *co, const char *s,
			      unsigned int count)
{
	struct uart_port *uport;
	struct qcom_geni_serial_port *port;
	int locked = 1;
	unsigned long flags;

	WARN_ON(co->index < 0 || co->index >= GENI_UART_NR_PORTS);

	port = get_port_from_line(co->index);
	if (IS_ERR_OR_NULL(port))
		return;

	uport = &port->uport;
	if (oops_in_progress)
		locked = spin_trylock_irqsave(&uport->lock, flags);
	else
		spin_lock_irqsave(&uport->lock, flags);

	if (locked) {
		__qcom_geni_serial_console_write(uport, s, count);
		spin_unlock_irqrestore(&uport->lock, flags);
	}
}

static int handle_rx_console(struct uart_port *uport,
			unsigned int rx_fifo_wc,
			unsigned int rx_last_byte_valid,
			unsigned int rx_last,
			bool drop_rx)
{
	int i, c;
	unsigned char *rx_char;
	struct tty_port *tport;
	struct qcom_geni_serial_port *qcom_port = GET_DEV_PORT(uport);

	tport = &uport->state->port;
	for (i = 0; i < rx_fifo_wc; i++) {
		int bytes = 4;

		*(qcom_port->rx_fifo) =
			geni_read_reg_nolog(uport->membase, SE_GENI_RX_FIFOn);
		if (drop_rx)
			continue;
		rx_char = (unsigned char *)qcom_port->rx_fifo;

		if (i == (rx_fifo_wc - 1)) {
			if (rx_last && rx_last_byte_valid)
				bytes = rx_last_byte_valid;
		}
		for (c = 0; c < bytes; c++) {
			char flag = TTY_NORMAL;
			int sysrq;

			uport->icount.rx++;
			sysrq = uart_handle_sysrq_char(uport, rx_char[c]);
			if (!sysrq)
				tty_insert_flip_char(tport, rx_char[c], flag);
		}
	}
	if (!drop_rx)
		tty_flip_buffer_push(tport);
	return 0;
}
#else
static int handle_rx_console(struct uart_port *uport,
			unsigned int rx_fifo_wc,
			unsigned int rx_last_byte_valid,
			unsigned int rx_last,
			bool drop_rx)
{
	return -EPERM;
}

#endif /* (CONFIG_SERIAL_CORE_CONSOLE) || defined(CONFIG_CONSOLE_POLL)) */

static void qcom_geni_serial_start_tx(struct uart_port *uport)
{
	unsigned int geni_m_irq_en;
	struct qcom_geni_serial_port *qcom_port = GET_DEV_PORT(uport);
	unsigned int geni_status;

	if (qcom_port->xfer_mode == FIFO_MODE) {
		geni_status = geni_read_reg_nolog(uport->membase,
						  SE_GENI_STATUS);
		if (geni_status & M_GENI_CMD_ACTIVE)
			goto exit_start_tx;

		if (!qcom_geni_serial_tx_empty(uport))
			goto exit_start_tx;

		geni_m_irq_en = geni_read_reg_nolog(uport->membase,
						    SE_GENI_M_IRQ_EN);
		geni_m_irq_en |= (M_TX_FIFO_WATERMARK_EN | M_CMD_DONE_EN);

		geni_write_reg_nolog(qcom_port->tx_wm, uport->membase,
						SE_GENI_TX_WATERMARK_REG);
		geni_write_reg_nolog(geni_m_irq_en, uport->membase,
							SE_GENI_M_IRQ_EN);
		/* Geni command setup should complete before returning.*/
		mb();
	}
exit_start_tx:
	return;
}

static void stop_tx_sequencer(struct uart_port *uport)
{
	unsigned int geni_m_irq_en;
	unsigned int geni_status;
	struct qcom_geni_serial_port *port = GET_DEV_PORT(uport);

	geni_m_irq_en = geni_read_reg_nolog(uport->membase, SE_GENI_M_IRQ_EN);
	geni_m_irq_en &= ~M_CMD_DONE_EN;
	if (port->xfer_mode == FIFO_MODE) {
		geni_m_irq_en &= ~M_TX_FIFO_WATERMARK_EN;
		geni_write_reg_nolog(0, uport->membase,
				     SE_GENI_TX_WATERMARK_REG);
	}
	port->xmit_size = 0;
	geni_write_reg_nolog(geni_m_irq_en, uport->membase, SE_GENI_M_IRQ_EN);
	geni_status = geni_read_reg_nolog(uport->membase,
						SE_GENI_STATUS);
	/* Possible stop tx is called multiple times. */
	if (!(geni_status & M_GENI_CMD_ACTIVE))
		return;

	geni_se_cancel_m_cmd(uport->membase);
	if (!qcom_geni_serial_poll_bit(uport, SE_GENI_M_IRQ_STATUS,
						M_CMD_CANCEL_EN, true)) {
		geni_se_abort_m_cmd(uport->membase);
		qcom_geni_serial_poll_bit(uport, SE_GENI_M_IRQ_STATUS,
						M_CMD_ABORT_EN, true);
		geni_write_reg_nolog(M_CMD_ABORT_EN, uport->membase,
							SE_GENI_M_IRQ_CLEAR);
	}
	geni_write_reg_nolog(M_CMD_CANCEL_EN, uport, SE_GENI_M_IRQ_CLEAR);
}

static void qcom_geni_serial_stop_tx(struct uart_port *uport)
{
	stop_tx_sequencer(uport);
}

static void start_rx_sequencer(struct uart_port *uport)
{
	unsigned int geni_s_irq_en;
	unsigned int geni_m_irq_en;
	unsigned int geni_status;
	struct qcom_geni_serial_port *port = GET_DEV_PORT(uport);

	geni_status = geni_read_reg_nolog(uport->membase, SE_GENI_STATUS);
	if (geni_status & S_GENI_CMD_ACTIVE)
		qcom_geni_serial_stop_rx(uport);

	geni_se_setup_s_cmd(uport->membase, UART_START_READ, 0);

	if (port->xfer_mode == FIFO_MODE) {
		geni_s_irq_en = geni_read_reg_nolog(uport->membase,
							SE_GENI_S_IRQ_EN);
		geni_m_irq_en = geni_read_reg_nolog(uport->membase,
							SE_GENI_M_IRQ_EN);

		geni_s_irq_en |= S_RX_FIFO_WATERMARK_EN | S_RX_FIFO_LAST_EN;
		geni_m_irq_en |= M_RX_FIFO_WATERMARK_EN | M_RX_FIFO_LAST_EN;

		geni_write_reg_nolog(geni_s_irq_en, uport->membase,
							SE_GENI_S_IRQ_EN);
		geni_write_reg_nolog(geni_m_irq_en, uport->membase,
							SE_GENI_M_IRQ_EN);
	}
	/*
	 * Ensure the writes to the secondary sequencer and interrupt enables
	 * go through.
	 */
	mb();
	geni_status = geni_read_reg_nolog(uport->membase, SE_GENI_STATUS);
}

static void qcom_geni_serial_start_rx(struct uart_port *uport)
{
	start_rx_sequencer(uport);
}

static void stop_rx_sequencer(struct uart_port *uport)
{
	unsigned int geni_s_irq_en;
	unsigned int geni_m_irq_en;
	unsigned int geni_status;
	struct qcom_geni_serial_port *port = GET_DEV_PORT(uport);
	u32 irq_clear = S_CMD_DONE_EN;
	bool done;

	if (port->xfer_mode == FIFO_MODE) {
		geni_s_irq_en = geni_read_reg_nolog(uport->membase,
							SE_GENI_S_IRQ_EN);
		geni_m_irq_en = geni_read_reg_nolog(uport->membase,
							SE_GENI_M_IRQ_EN);
		geni_s_irq_en &= ~(S_RX_FIFO_WATERMARK_EN | S_RX_FIFO_LAST_EN);
		geni_m_irq_en &= ~(M_RX_FIFO_WATERMARK_EN | M_RX_FIFO_LAST_EN);

		geni_write_reg_nolog(geni_s_irq_en, uport->membase,
							SE_GENI_S_IRQ_EN);
		geni_write_reg_nolog(geni_m_irq_en, uport->membase,
							SE_GENI_M_IRQ_EN);
	}

	geni_status = geni_read_reg_nolog(uport->membase, SE_GENI_STATUS);
	/* Possible stop rx is called multiple times. */
	if (!(geni_status & S_GENI_CMD_ACTIVE))
		return;
	geni_se_cancel_s_cmd(uport->membase);
	/*
	 * Ensure that the cancel goes through before polling for the
	 * cancel control bit.
	 */
	mb();
	done = qcom_geni_serial_poll_bit(uport, SE_GENI_S_CMD_CTRL_REG,
					S_GENI_CMD_CANCEL, false);
	geni_status = geni_read_reg_nolog(uport->membase, SE_GENI_STATUS);
	geni_write_reg_nolog(irq_clear, uport->membase, SE_GENI_S_IRQ_CLEAR);
	if ((geni_status & S_GENI_CMD_ACTIVE))
		qcom_geni_serial_abort_rx(uport);
}

static void qcom_geni_serial_stop_rx(struct uart_port *uport)
{
	stop_rx_sequencer(uport);
}

static int qcom_geni_serial_handle_rx(struct uart_port *uport, bool drop_rx)
{
	int ret = 0;
	unsigned int rx_fifo_status;
	unsigned int rx_fifo_wc = 0;
	unsigned int rx_last_byte_valid = 0;
	unsigned int rx_last = 0;
	struct tty_port *tport;
	struct qcom_geni_serial_port *port = GET_DEV_PORT(uport);

	tport = &uport->state->port;
	rx_fifo_status = geni_read_reg_nolog(uport->membase,
				SE_GENI_RX_FIFO_STATUS);
	rx_fifo_wc = rx_fifo_status & RX_FIFO_WC_MSK;
	rx_last_byte_valid = ((rx_fifo_status & RX_LAST_BYTE_VALID_MSK) >>
						RX_LAST_BYTE_VALID_SHFT);
	rx_last = rx_fifo_status & RX_LAST;
	if (rx_fifo_wc)
		port->handle_rx(uport, rx_fifo_wc, rx_last_byte_valid,
							rx_last, drop_rx);
	return ret;
}

static int qcom_geni_serial_handle_tx(struct uart_port *uport)
{
	int ret = 0;
	struct qcom_geni_serial_port *qcom_port = GET_DEV_PORT(uport);
	struct circ_buf *xmit = &uport->state->xmit;
	unsigned int avail_fifo_bytes = 0;
	unsigned int bytes_remaining = 0;
	int i = 0;
	unsigned int tx_fifo_status;
	unsigned int xmit_size;
	unsigned int fifo_width_bytes = 1;
	int temp_tail = 0;

	xmit_size = uart_circ_chars_pending(xmit);
	tx_fifo_status = geni_read_reg_nolog(uport->membase,
					SE_GENI_TX_FIFO_STATUS);
	/* Both FIFO and framework buffer are drained */
	if ((xmit_size == qcom_port->xmit_size) && !tx_fifo_status) {
		qcom_port->xmit_size = 0;
		uart_circ_clear(xmit);
		qcom_geni_serial_stop_tx(uport);
		goto exit_handle_tx;
	}
	xmit_size -= qcom_port->xmit_size;

	avail_fifo_bytes = (qcom_port->tx_fifo_depth - qcom_port->tx_wm) *
							fifo_width_bytes;
	temp_tail = (xmit->tail + qcom_port->xmit_size) & (UART_XMIT_SIZE - 1);
	if (xmit_size > (UART_XMIT_SIZE - temp_tail))
		xmit_size = (UART_XMIT_SIZE - temp_tail);
	if (xmit_size > avail_fifo_bytes)
		xmit_size = avail_fifo_bytes;

	if (!xmit_size)
		goto exit_handle_tx;

	qcom_geni_serial_setup_tx(uport, xmit_size);

	bytes_remaining = xmit_size;
	while (i < xmit_size) {
		unsigned int tx_bytes;
		unsigned int buf = 0;
		int c;

		tx_bytes = ((bytes_remaining < fifo_width_bytes) ?
					bytes_remaining : fifo_width_bytes);

		for (c = 0; c < tx_bytes ; c++)
			buf |= (xmit->buf[temp_tail + c] << (c * 8));
		geni_write_reg_nolog(buf, uport->membase, SE_GENI_TX_FIFOn);
		i += tx_bytes;
		temp_tail = (temp_tail + tx_bytes) & (UART_XMIT_SIZE - 1);
		uport->icount.tx += tx_bytes;
		bytes_remaining -= tx_bytes;
		/* Ensure FIFO write goes through */
		wmb();
	}
	qcom_geni_serial_poll_cancel_tx(uport);
	qcom_port->xmit_size += xmit_size;
exit_handle_tx:
	uart_write_wakeup(uport);
	return ret;
}

static irqreturn_t qcom_geni_serial_isr(int isr, void *dev)
{
	unsigned int m_irq_status;
	unsigned int s_irq_status;
	struct uart_port *uport = dev;
	unsigned long flags;
	unsigned int m_irq_en;
	bool drop_rx = false;
	struct tty_port *tport = &uport->state->port;

	spin_lock_irqsave(&uport->lock, flags);
	if (uport->suspended)
		goto exit_geni_serial_isr;
	m_irq_status = geni_read_reg_nolog(uport->membase,
						SE_GENI_M_IRQ_STATUS);
	s_irq_status = geni_read_reg_nolog(uport->membase,
						SE_GENI_S_IRQ_STATUS);
	m_irq_en = geni_read_reg_nolog(uport->membase, SE_GENI_M_IRQ_EN);
	geni_write_reg_nolog(m_irq_status, uport->membase, SE_GENI_M_IRQ_CLEAR);
	geni_write_reg_nolog(s_irq_status, uport->membase, SE_GENI_S_IRQ_CLEAR);

	if ((m_irq_status & M_ILLEGAL_CMD_EN)) {
		WARN_ON(1);
		goto exit_geni_serial_isr;
	}

	if (s_irq_status & S_RX_FIFO_WR_ERR_EN) {
		uport->icount.overrun++;
		tty_insert_flip_char(tport, 0, TTY_OVERRUN);
	}

	if ((m_irq_status & m_irq_en) &
	    (M_TX_FIFO_WATERMARK_EN | M_CMD_DONE_EN))
		qcom_geni_serial_handle_tx(uport);

	if ((s_irq_status & S_GP_IRQ_0_EN) || (s_irq_status & S_GP_IRQ_1_EN)) {
		if (s_irq_status & S_GP_IRQ_0_EN)
			uport->icount.parity++;
		drop_rx = true;
	} else if ((s_irq_status & S_GP_IRQ_2_EN) ||
		(s_irq_status & S_GP_IRQ_3_EN)) {
		uport->icount.brk++;
	}

	if ((s_irq_status & S_RX_FIFO_WATERMARK_EN) ||
		(s_irq_status & S_RX_FIFO_LAST_EN))
		qcom_geni_serial_handle_rx(uport, drop_rx);

exit_geni_serial_isr:
	spin_unlock_irqrestore(&uport->lock, flags);
	return IRQ_HANDLED;
}

static int get_tx_fifo_size(struct qcom_geni_serial_port *port)
{
	struct uart_port *uport;

	if (!port)
		return -ENODEV;

	uport = &port->uport;
	port->tx_fifo_depth = geni_se_get_tx_fifo_depth(uport->membase);
	if (!port->tx_fifo_depth) {
		dev_err(uport->dev, "%s:Invalid TX FIFO depth read\n",
								__func__);
		return -ENXIO;
	}

	port->tx_fifo_width = geni_se_get_tx_fifo_width(uport->membase);
	if (!port->tx_fifo_width) {
		dev_err(uport->dev, "%s:Invalid TX FIFO width read\n",
								__func__);
		return -ENXIO;
	}

	port->rx_fifo_depth = geni_se_get_rx_fifo_depth(uport->membase);
	if (!port->rx_fifo_depth) {
		dev_err(uport->dev, "%s:Invalid RX FIFO depth read\n",
								__func__);
		return -ENXIO;
	}

	uport->fifosize =
		((port->tx_fifo_depth * port->tx_fifo_width) >> 3);
	return 0;
}

static void set_rfr_wm(struct qcom_geni_serial_port *port)
{
	/*
	 * Set RFR (Flow off) to FIFO_DEPTH - 2.
	 * RX WM level at 10% RX_FIFO_DEPTH.
	 * TX WM level at 10% TX_FIFO_DEPTH.
	 */
	port->rx_rfr = port->rx_fifo_depth - 2;
	port->rx_wm = UART_CONSOLE_RX_WM;
	port->tx_wm = 2;
}

static void qcom_geni_serial_shutdown(struct uart_port *uport)
{
	unsigned long flags;

	/* Stop the console before stopping the current tx */
	console_stop(uport->cons);

	disable_irq(uport->irq);
	free_irq(uport->irq, uport);
	spin_lock_irqsave(&uport->lock, flags);
	qcom_geni_serial_stop_tx(uport);
	qcom_geni_serial_stop_rx(uport);
	spin_unlock_irqrestore(&uport->lock, flags);
}

static int qcom_geni_serial_port_setup(struct uart_port *uport)
{
	int ret = 0;
	struct qcom_geni_serial_port *qcom_port = GET_DEV_PORT(uport);
	unsigned long cfg0, cfg1;
	unsigned int rxstale = DEFAULT_BITS_PER_CHAR * STALE_TIMEOUT;

	set_rfr_wm(qcom_port);
	geni_write_reg_nolog(rxstale, uport->membase, SE_UART_RX_STALE_CNT);
	/*
	 * Make an unconditional cancel on the main sequencer to reset
	 * it else we could end up in data loss scenarios.
	 */
	qcom_port->xfer_mode = FIFO_MODE;
	qcom_geni_serial_poll_cancel_tx(uport);
	geni_se_get_packing_config(8, 1, false, &cfg0, &cfg1);
	geni_write_reg_nolog(cfg0, uport->membase,
					SE_GENI_TX_PACKING_CFG0);
	geni_write_reg_nolog(cfg1, uport->membase,
					SE_GENI_TX_PACKING_CFG1);
	geni_se_get_packing_config(8, 4, false, &cfg0, &cfg1);
	geni_write_reg_nolog(cfg0, uport->membase,
					SE_GENI_RX_PACKING_CFG0);
	geni_write_reg_nolog(cfg1, uport->membase,
					SE_GENI_RX_PACKING_CFG1);
	ret = geni_se_init(uport->membase, qcom_port->rx_wm, qcom_port->rx_rfr);
	if (ret) {
		dev_err(uport->dev, "%s: Fail\n", __func__);
		goto exit_portsetup;
	}

	ret = geni_se_select_mode(uport->membase, qcom_port->xfer_mode);
	if (ret)
		goto exit_portsetup;

	qcom_port->port_setup = true;
	/*
	 * Ensure Port setup related IO completes before returning to
	 * framework.
	 */
	mb();
exit_portsetup:
	return ret;
}

static int qcom_geni_serial_startup(struct uart_port *uport)
{
	int ret = 0;
	struct qcom_geni_serial_port *qcom_port = GET_DEV_PORT(uport);

	scnprintf(qcom_port->name, sizeof(qcom_port->name),
		  "qcom_serial_geni%d",	uport->line);

	if (unlikely(geni_se_get_proto(uport->membase) != UART)) {
		dev_err(uport->dev, "%s: Invalid FW %d loaded.\n",
				 __func__, geni_se_get_proto(uport->membase));
		ret = -ENXIO;
		goto exit_startup;
	}

	get_tx_fifo_size(qcom_port);
	if (!qcom_port->port_setup) {
		if (qcom_geni_serial_port_setup(uport))
			goto exit_startup;
	}

	/*
	 * Ensure that all the port configuration writes complete
	 * before returning to the framework.
	 */
	mb();
	ret = request_irq(uport->irq, qcom_geni_serial_isr, IRQF_TRIGGER_HIGH,
			qcom_port->name, uport);
	if (unlikely(ret)) {
		dev_err(uport->dev, "%s: Failed to get IRQ ret %d\n",
							__func__, ret);
		goto exit_startup;
	}

exit_startup:
	return ret;
}

static int get_clk_cfg(unsigned long clk_freq, unsigned long *ser_clk)
{
	unsigned long root_freq[] = {7372800, 14745600, 19200000, 29491200,
		32000000, 48000000, 64000000, 80000000, 96000000, 100000000};
	int i;
	int match = -1;

	for (i = 0; i < ARRAY_SIZE(root_freq); i++) {
		if (clk_freq > root_freq[i])
			continue;

		if (!(root_freq[i] % clk_freq)) {
			match = i;
			break;
		}
	}
	if (match != -1)
		*ser_clk = root_freq[match];
	else
		pr_err("clk_freq %ld\n", clk_freq);
	return match;
}

static void geni_serial_write_term_regs(struct uart_port *uport,
		u32 tx_trans_cfg, u32 tx_parity_cfg, u32 rx_trans_cfg,
		u32 rx_parity_cfg, u32 bits_per_char, u32 stop_bit_len,
		u32 s_clk_cfg)
{
	geni_write_reg_nolog(tx_trans_cfg, uport->membase,
							SE_UART_TX_TRANS_CFG);
	geni_write_reg_nolog(tx_parity_cfg, uport->membase,
							SE_UART_TX_PARITY_CFG);
	geni_write_reg_nolog(rx_trans_cfg, uport->membase,
							SE_UART_RX_TRANS_CFG);
	geni_write_reg_nolog(rx_parity_cfg, uport->membase,
							SE_UART_RX_PARITY_CFG);
	geni_write_reg_nolog(bits_per_char, uport->membase,
							SE_UART_TX_WORD_LEN);
	geni_write_reg_nolog(bits_per_char, uport->membase,
							SE_UART_RX_WORD_LEN);
	geni_write_reg_nolog(stop_bit_len, uport->membase,
						SE_UART_TX_STOP_BIT_LEN);
	geni_write_reg_nolog(s_clk_cfg, uport->membase, GENI_SER_M_CLK_CFG);
	geni_write_reg_nolog(s_clk_cfg, uport->membase, GENI_SER_S_CLK_CFG);
}

static int get_clk_div_rate(unsigned int baud, unsigned long *desired_clk_rate)
{
	unsigned long ser_clk;
	int dfs_index;
	int clk_div = 0;

	*desired_clk_rate = baud * UART_OVERSAMPLING;
	dfs_index = get_clk_cfg(*desired_clk_rate, &ser_clk);
	if (dfs_index < 0) {
		pr_err("%s: Can't find matching DFS entry for baud %d\n",
								__func__, baud);
		clk_div = -EINVAL;
		goto exit_get_clk_div_rate;
	}

	clk_div = ser_clk / *desired_clk_rate;
	*desired_clk_rate = ser_clk;
exit_get_clk_div_rate:
	return clk_div;
}

static void qcom_geni_serial_set_termios(struct uart_port *uport,
				struct ktermios *termios, struct ktermios *old)
{
	unsigned int baud;
	unsigned int bits_per_char = 0;
	unsigned int tx_trans_cfg;
	unsigned int tx_parity_cfg;
	unsigned int rx_trans_cfg;
	unsigned int rx_parity_cfg;
	unsigned int stop_bit_len;
	unsigned int clk_div;
	unsigned long ser_clk_cfg = 0;
	struct qcom_geni_serial_port *port = GET_DEV_PORT(uport);
	unsigned long clk_rate;

	qcom_geni_serial_stop_rx(uport);
	/* baud rate */
	baud = uart_get_baud_rate(uport, termios, old, 300, 4000000);
	port->cur_baud = baud;
	clk_div = get_clk_div_rate(baud, &clk_rate);
	if (clk_div <= 0)
		goto exit_set_termios;

	uport->uartclk = clk_rate;
	clk_set_rate(port->serial_rsc.se_clk, clk_rate);
	ser_clk_cfg |= SER_CLK_EN;
	ser_clk_cfg |= (clk_div << CLK_DIV_SHFT);

	/* parity */
	tx_trans_cfg = geni_read_reg_nolog(uport->membase,
							SE_UART_TX_TRANS_CFG);
	tx_parity_cfg = geni_read_reg_nolog(uport->membase,
							SE_UART_TX_PARITY_CFG);
	rx_trans_cfg = geni_read_reg_nolog(uport->membase,
							SE_UART_RX_TRANS_CFG);
	rx_parity_cfg = geni_read_reg_nolog(uport->membase,
							SE_UART_RX_PARITY_CFG);
	if (termios->c_cflag & PARENB) {
		tx_trans_cfg |= UART_TX_PAR_EN;
		rx_trans_cfg |= UART_RX_PAR_EN;
		tx_parity_cfg |= PAR_CALC_EN;
		rx_parity_cfg |= PAR_CALC_EN;
		if (termios->c_cflag & PARODD) {
			tx_parity_cfg |= PAR_ODD;
			rx_parity_cfg |= PAR_ODD;
		} else if (termios->c_cflag & CMSPAR) {
			tx_parity_cfg |= PAR_SPACE;
			rx_parity_cfg |= PAR_SPACE;
		} else {
			tx_parity_cfg |= PAR_EVEN;
			rx_parity_cfg |= PAR_EVEN;
		}
	} else {
		tx_trans_cfg &= ~UART_TX_PAR_EN;
		rx_trans_cfg &= ~UART_RX_PAR_EN;
		tx_parity_cfg &= ~PAR_CALC_EN;
		rx_parity_cfg &= ~PAR_CALC_EN;
	}

	/* bits per char */
	switch (termios->c_cflag & CSIZE) {
	case CS5:
		bits_per_char = 5;
		break;
	case CS6:
		bits_per_char = 6;
		break;
	case CS7:
		bits_per_char = 7;
		break;
	case CS8:
	default:
		bits_per_char = 8;
		break;
	}

	/* stop bits */
	if (termios->c_cflag & CSTOPB)
		stop_bit_len = TX_STOP_BIT_LEN_2;
	else
		stop_bit_len = TX_STOP_BIT_LEN_1;

	/* flow control, clear the CTS_MASK bit if using flow control. */
	if (termios->c_cflag & CRTSCTS)
		tx_trans_cfg &= ~UART_CTS_MASK;
	else
		tx_trans_cfg |= UART_CTS_MASK;

	if (likely(baud))
		uart_update_timeout(uport, termios->c_cflag, baud);

	geni_serial_write_term_regs(uport, tx_trans_cfg, tx_parity_cfg,
		rx_trans_cfg, rx_parity_cfg, bits_per_char, stop_bit_len,
								ser_clk_cfg);
exit_set_termios:
	qcom_geni_serial_start_rx(uport);
	return;

}

static unsigned int qcom_geni_serial_tx_empty(struct uart_port *uport)
{
	unsigned int tx_fifo_status;
	unsigned int is_tx_empty = 1;

	tx_fifo_status = geni_read_reg_nolog(uport->membase,
						SE_GENI_TX_FIFO_STATUS);
	if (tx_fifo_status)
		is_tx_empty = 0;

	return is_tx_empty;
}

#if defined(CONFIG_SERIAL_CORE_CONSOLE) || defined(CONFIG_CONSOLE_POLL)
static int __init qcom_geni_console_setup(struct console *co, char *options)
{
	struct uart_port *uport;
	struct qcom_geni_serial_port *dev_port;
	int baud = 115200;
	int bits = 8;
	int parity = 'n';
	int flow = 'n';
	int ret = 0;

	if (unlikely(co->index >= GENI_UART_NR_PORTS  || co->index < 0))
		return -ENXIO;

	dev_port = get_port_from_line(co->index);
	if (IS_ERR_OR_NULL(dev_port)) {
		ret = PTR_ERR(dev_port);
		pr_err("Invalid line %d(%d)\n", co->index, ret);
		return ret;
	}

	uport = &dev_port->uport;

	if (unlikely(!uport->membase))
		return -ENXIO;

	if (geni_se_resources_on(&dev_port->serial_rsc))
		WARN_ON(1);

	if (unlikely(geni_se_get_proto(uport->membase) != UART)) {
		geni_se_resources_off(&dev_port->serial_rsc);
		return -ENXIO;
	}

	if (!dev_port->port_setup) {
		qcom_geni_serial_stop_rx(uport);
		qcom_geni_serial_port_setup(uport);
	}

	if (options)
		uart_parse_options(options, &baud, &parity, &bits, &flow);

	return uart_set_options(uport, co, baud, parity, bits, flow);
}

static int console_register(struct uart_driver *drv)
{
	return uart_register_driver(drv);
}
static void console_unregister(struct uart_driver *drv)
{
	uart_unregister_driver(drv);
}

static struct console cons_ops = {
	.name = "ttyMSM",
	.write = qcom_geni_serial_console_write,
	.device = uart_console_device,
	.setup = qcom_geni_console_setup,
	.flags = CON_PRINTBUFFER,
	.index = -1,
	.data = &qcom_geni_console_driver,
};

static struct uart_driver qcom_geni_console_driver = {
	.owner = THIS_MODULE,
	.driver_name = "qcom_geni_console",
	.dev_name = "ttyMSM",
	.nr =  GENI_UART_NR_PORTS,
	.cons = &cons_ops,
};
#else
static int console_register(struct uart_driver *drv)
{
	return 0;
}

static void console_unregister(struct uart_driver *drv)
{
}
#endif /* defined(CONFIG_SERIAL_CORE_CONSOLE) || defined(CONFIG_CONSOLE_POLL) */

static void qcom_geni_serial_cons_pm(struct uart_port *uport,
		unsigned int new_state, unsigned int old_state)
{
	struct qcom_geni_serial_port *qcom_port = GET_DEV_PORT(uport);

	if (unlikely(!uart_console(uport)))
		return;

	if (new_state == UART_PM_STATE_ON && old_state == UART_PM_STATE_OFF)
		geni_se_resources_on(&qcom_port->serial_rsc);
	else if (new_state == UART_PM_STATE_OFF &&
			old_state == UART_PM_STATE_ON)
		geni_se_resources_off(&qcom_port->serial_rsc);
}

static const struct uart_ops qcom_geni_console_pops = {
	.tx_empty = qcom_geni_serial_tx_empty,
	.stop_tx = qcom_geni_serial_stop_tx,
	.start_tx = qcom_geni_serial_start_tx,
	.stop_rx = qcom_geni_serial_stop_rx,
	.set_termios = qcom_geni_serial_set_termios,
	.startup = qcom_geni_serial_startup,
	.config_port = qcom_geni_serial_config_port,
	.shutdown = qcom_geni_serial_shutdown,
	.type = qcom_geni_serial_get_type,
	.set_mctrl = qcom_geni_cons_set_mctrl,
	.get_mctrl = qcom_geni_cons_get_mctrl,
#ifdef CONFIG_CONSOLE_POLL
	.poll_get_char	= qcom_geni_serial_get_char,
	.poll_put_char	= qcom_geni_serial_poll_put_char,
#endif
	.pm = qcom_geni_serial_cons_pm,
};

static const struct of_device_id qcom_geni_serial_match_table[] = {
	{ .compatible = "qcom,geni-debug-uart",
			.data = (void *)&qcom_geni_console_driver},
};

static int qcom_geni_serial_probe(struct platform_device *pdev)
{
	int ret = 0;
	int line = -1;
	struct qcom_geni_serial_port *dev_port;
	struct uart_port *uport;
	struct resource *res;
	struct uart_driver *drv;
	const struct of_device_id *id;

	id = of_match_device(qcom_geni_serial_match_table, &pdev->dev);
	if (id) {
		dev_dbg(&pdev->dev, "%s: %s\n", __func__, id->compatible);
		drv = (struct uart_driver *)id->data;
	} else {
		dev_err(&pdev->dev, "%s: No matching device found", __func__);
		return -ENODEV;
	}

	if (pdev->dev.of_node) {
		if (drv->cons)
			line = of_alias_get_id(pdev->dev.of_node, "serial");
	} else {
		line = pdev->id;
	}

	if (line < 0)
		line = atomic_inc_return(&uart_line_id) - 1;

	if ((line < 0) || (line >= GENI_UART_CONS_PORTS))
		return -ENXIO;
	dev_port = get_port_from_line(line);
	if (IS_ERR_OR_NULL(dev_port)) {
		ret = PTR_ERR(dev_port);
		dev_err(&pdev->dev, "Invalid line %d(%d)\n",
					line, ret);
		goto exit_geni_serial_probe;
	}

	uport = &dev_port->uport;

	/* Don't allow 2 drivers to access the same port */
	if (uport->private_data) {
		ret = -ENODEV;
		goto exit_geni_serial_probe;
	}

	uport->dev = &pdev->dev;
	dev_port->wrapper_dev = pdev->dev.parent;
	dev_port->serial_rsc.wrapper_dev = pdev->dev.parent;
	dev_port->serial_rsc.se_clk = devm_clk_get(&pdev->dev, "se-clk");
	if (IS_ERR(dev_port->serial_rsc.se_clk)) {
		ret = PTR_ERR(dev_port->serial_rsc.se_clk);
		dev_err(&pdev->dev, "Err getting SE Core clk %d\n", ret);
		goto exit_geni_serial_probe;
	}

	res = platform_get_resource_byname(pdev, IORESOURCE_MEM, "se-phys");
	if (!res) {
		ret = -ENXIO;
		dev_err(&pdev->dev, "Err getting IO region\n");
		goto exit_geni_serial_probe;
	}

	uport->mapbase = res->start;
	uport->membase = devm_ioremap(&pdev->dev, res->start,
						resource_size(res));
	if (!uport->membase) {
		ret = -ENOMEM;
		dev_err(&pdev->dev, "Err IO mapping serial iomem");
		goto exit_geni_serial_probe;
	}

	dev_port->serial_rsc.geni_pinctrl = devm_pinctrl_get(&pdev->dev);
	if (IS_ERR_OR_NULL(dev_port->serial_rsc.geni_pinctrl)) {
		dev_err(&pdev->dev, "No pinctrl config specified!\n");
		ret = PTR_ERR(dev_port->serial_rsc.geni_pinctrl);
		goto exit_geni_serial_probe;
	}
	dev_port->serial_rsc.geni_gpio_active =
		pinctrl_lookup_state(dev_port->serial_rsc.geni_pinctrl,
							PINCTRL_DEFAULT);
	if (IS_ERR_OR_NULL(dev_port->serial_rsc.geni_gpio_active)) {
		dev_err(&pdev->dev, "No default config specified!\n");
		ret = PTR_ERR(dev_port->serial_rsc.geni_gpio_active);
		goto exit_geni_serial_probe;
	}

	dev_port->serial_rsc.geni_gpio_sleep =
		pinctrl_lookup_state(dev_port->serial_rsc.geni_pinctrl,
							PINCTRL_SLEEP);
	if (IS_ERR_OR_NULL(dev_port->serial_rsc.geni_gpio_sleep)) {
		dev_err(&pdev->dev, "No sleep config specified!\n");
		ret = PTR_ERR(dev_port->serial_rsc.geni_gpio_sleep);
		goto exit_geni_serial_probe;
	}

	dev_port->tx_fifo_depth = DEF_FIFO_DEPTH_WORDS;
	dev_port->rx_fifo_depth = DEF_FIFO_DEPTH_WORDS;
	dev_port->tx_fifo_width = DEF_FIFO_WIDTH_BITS;
	uport->fifosize =
		((dev_port->tx_fifo_depth * dev_port->tx_fifo_width) >> 3);

	uport->irq = platform_get_irq(pdev, 0);
	if (uport->irq < 0) {
		ret = uport->irq;
		dev_err(&pdev->dev, "Failed to get IRQ %d\n", ret);
		goto exit_geni_serial_probe;
	}

	uport->private_data = (void *)drv;
	platform_set_drvdata(pdev, dev_port);
	dev_port->handle_rx = handle_rx_console;
	dev_port->rx_fifo = devm_kzalloc(uport->dev, sizeof(u32),
								GFP_KERNEL);
	dev_port->port_setup = false;
	return uart_add_one_port(drv, uport);

exit_geni_serial_probe:
	return ret;
}

static int qcom_geni_serial_remove(struct platform_device *pdev)
{
	struct qcom_geni_serial_port *port = platform_get_drvdata(pdev);
	struct uart_driver *drv =
			(struct uart_driver *)port->uport.private_data;

	uart_remove_one_port(drv, &port->uport);
	return 0;
}


#ifdef CONFIG_PM
static int qcom_geni_serial_sys_suspend_noirq(struct device *dev)
{
	struct platform_device *pdev = to_platform_device(dev);
	struct qcom_geni_serial_port *port = platform_get_drvdata(pdev);
	struct uart_port *uport = &port->uport;

	uart_suspend_port((struct uart_driver *)uport->private_data,
				uport);
	return 0;
}

static int qcom_geni_serial_sys_resume_noirq(struct device *dev)
{
	struct platform_device *pdev = to_platform_device(dev);
	struct qcom_geni_serial_port *port = platform_get_drvdata(pdev);
	struct uart_port *uport = &port->uport;

	if (console_suspend_enabled && uport->suspended) {
		uart_resume_port((struct uart_driver *)uport->private_data,
									uport);
		disable_irq(uport->irq);
	}
	return 0;
}
#else
static int qcom_geni_serial_sys_suspend_noirq(struct device *dev)
{
	return 0;
}

static int qcom_geni_serial_sys_resume_noirq(struct device *dev)
{
	return 0;
}
#endif

static const struct dev_pm_ops qcom_geni_serial_pm_ops = {
	.suspend_noirq = qcom_geni_serial_sys_suspend_noirq,
	.resume_noirq = qcom_geni_serial_sys_resume_noirq,
};

static struct platform_driver qcom_geni_serial_platform_driver = {
	.remove = qcom_geni_serial_remove,
	.probe = qcom_geni_serial_probe,
	.driver = {
		.name = "qcom_geni_serial",
		.of_match_table = qcom_geni_serial_match_table,
		.pm = &qcom_geni_serial_pm_ops,
	},
};

static int __init qcom_geni_serial_init(void)
{
	int ret = 0;
	int i;

	for (i = 0; i < GENI_UART_CONS_PORTS; i++) {
		qcom_geni_console_port.uport.iotype = UPIO_MEM;
		qcom_geni_console_port.uport.ops = &qcom_geni_console_pops;
		qcom_geni_console_port.uport.flags = UPF_BOOT_AUTOCONF;
		qcom_geni_console_port.uport.line = i;
	}

	ret = console_register(&qcom_geni_console_driver);
	if (ret)
		return ret;

	ret = platform_driver_register(&qcom_geni_serial_platform_driver);
	if (ret) {
		console_unregister(&qcom_geni_console_driver);
		return ret;
	}
	return ret;
}
module_init(qcom_geni_serial_init);

static void __exit qcom_geni_serial_exit(void)
{
	platform_driver_unregister(&qcom_geni_serial_platform_driver);
	console_unregister(&qcom_geni_console_driver);
}
module_exit(qcom_geni_serial_exit);

MODULE_DESCRIPTION("Serial driver for GENI based QUP cores");
MODULE_LICENSE("GPL v2");
MODULE_ALIAS("tty:qcom_geni_serial");
