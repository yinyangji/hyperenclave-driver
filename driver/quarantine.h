/* SPDX-License-Identifier: GPL-2.0 */
/*
 * HyperEnclave kernel module.
 *
 * Copyright (C) 2020-2023 The HyperEnclave Project. All rights reserved.
 */

#ifndef _DRIVER_QUARANTINE_H
#define _DRIVER_QUARANTINE_H

int he_quarantine_register(void);
void he_quarantine_unregister(void);

/* Refuse enable when a candidate accelerator is bound or is the boot VGA. */
int he_precheck_takeover(void);

/* After the monitor is up, bind every DeviceList entry to he-quarantine. */
int he_reconcile_protected_devices(void);

#endif
