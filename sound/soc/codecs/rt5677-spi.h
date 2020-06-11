/*
 * rt5677-spi.h  --  RT5677 ALSA SoC audio codec driver
 *
 * Copyright 2013 Realtek Semiconductor Corp.
 * Author: Oder Chiou <oder_chiou@realtek.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef __RT5677_SPI_H__
#define __RT5677_SPI_H__

#if IS_ENABLED(CONFIG_SND_SOC_RT5677_SPI)
int rt5677_spi_read(u32 addr, void *rxbuf, size_t len);
int rt5677_spi_write(u32 addr, const void *txbuf, size_t len);
int rt5677_spi_write_firmware(u32 addr, const struct firmware *fw);
void rt5677_spi_hotword_detected(void);
#else
static inline int rt5677_spi_read(u32 addr, void *rxbuf, size_t len)
{
	return -EINVAL;
}
static inline int rt5677_spi_write(u32 addr, const void *txbuf, size_t len)
{
	return -EINVAL;
}
static inline int rt5677_spi_write_firmware(u32 addr, const struct firmware *fw)
{
	return -EINVAL;
}
static inline void rt5677_spi_hotword_detected(void){}
#endif

#endif /* __RT5677_SPI_H__ */
