/* SPDX-License-Identifier: GPL-2.0 */
/*
 * HyperEnclave kernel module.
 *
 * Copyright (C) 2020-2023 The HyperEnclave Project. All rights reserved.
 */

#ifndef _DRIVER_IVM_H
#define _DRIVER_IVM_H

#include <linux/fs.h>

int he_ivm_open(struct inode *inode, struct file *file);
int he_ivm_release(struct inode *inode, struct file *file);
long he_ivm_ioctl(struct file *file, unsigned long arg);

#endif
