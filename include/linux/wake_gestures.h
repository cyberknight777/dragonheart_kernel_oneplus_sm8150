/*
 * include/linux/wake_gestures.h
 *
 * Copyright (c) 2013-19, Aaron Segaert <asegaert@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifndef _LINUX_WAKE_GESTURES_H
#define _LINUX_WAKE_GESTURES_H

#define SWEEP_RIGHT		0x01
#define SWEEP_LEFT		0x02
#define SWEEP_UP		0x04
#define SWEEP_DOWN		0x08

#include <linux/input.h>

extern bool wg_switch;
extern bool wg_switch_temp;
extern bool wg_changed;
extern int s2w_switch;
extern int dt2w_switch;
extern int wake_vibrate;

bool scr_suspended(void);
void set_vibrate(void);

#endif	/* _LINUX_WAKE_GESTURES_H */
