// SPDX-License-Identifier: GPL-2.0
/*
 * HyperEnclave kernel module.
 *
 * Copyright (C) 2020-2023 The HyperEnclave Project. All rights reserved.
 *
 * Takeover precheck and the he-quarantine placeholder (G13). The driver
 * claims a protected device and does not touch its BARs or command bits.
 * Binding is only through driver_override, after the monitor's DeviceList.
 */

#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/vgaarb.h>

#include <hyperenclave/hypercall.h>
#include <hyperenclave/log.h>

#include "quarantine.h"

#define HE_QUARANTINE_NAME "he-quarantine"
#define HE_DEVICE_LIST_MAX 32

/* Display (0x03) and processing accelerators (0x12). */
#define HE_CLASS_DISPLAY 0x03
#define HE_CLASS_ACCEL 0x12

static char *protect_bdf;
module_param(protect_bdf, charp, 0444);
MODULE_PARM_DESC(protect_bdf,
		 "Comma-separated BDFs that must be unbound before takeover "
		 "(0000:00:05.0 or 00:05.0)");

struct he_dev_info {
	u16 bdf, vendor_id, device_id, class_code, domain_id, flags;
	u32 nr_bars;
	u64 owner;
} __packed;

struct he_dev_list {
	u32 count;
	u32 total;
	struct he_dev_info devices[HE_DEVICE_LIST_MAX];
} __packed;

static const struct pci_device_id he_quarantine_ids[] = {
	{ 0, },
};

static int he_quarantine_probe(struct pci_dev *pdev,
			       const struct pci_device_id *id)
{
	(void)id;
	pci_info(pdev, "claimed by he-quarantine, hardware left untouched\n");
	return 0;
}

static void he_quarantine_remove(struct pci_dev *pdev)
{
	pci_info(pdev, "he-quarantine released\n");
}

static struct pci_driver he_quarantine_pci = {
	.name = HE_QUARANTINE_NAME,
	.id_table = he_quarantine_ids,
	.probe = he_quarantine_probe,
	.remove = he_quarantine_remove,
};

static bool he_quarantine_registered;

int he_quarantine_register(void)
{
	int err;

	BUILD_BUG_ON(sizeof(struct he_dev_info) != 24);
	BUILD_BUG_ON(sizeof(struct he_dev_list) !=
		     8 + 24 * HE_DEVICE_LIST_MAX);

	err = pci_register_driver(&he_quarantine_pci);
	if (err)
		return err;
	he_quarantine_registered = true;
	return 0;
}

void he_quarantine_unregister(void)
{
	if (!he_quarantine_registered)
		return;
	pci_unregister_driver(&he_quarantine_pci);
	he_quarantine_registered = false;
}

static int he_precheck_one(struct pci_dev *pdev)
{
	if (vga_default_device() == pdev) {
		he_err("%s is the boot VGA; refusing takeover\n",
		       pci_name(pdev));
		return -EBUSY;
	}
	if (pdev->driver) {
		he_err("%s is bound to %s; refusing takeover\n", pci_name(pdev),
		       pdev->driver->name);
		return -EBUSY;
	}
	return 0;
}

static int he_parse_bdf(const char *s, int *domain, u16 *bdf)
{
	unsigned int d, bus, dev, fn;
	int n;

	if (sscanf(s, "%x:%x:%x.%x%n", &d, &bus, &dev, &fn, &n) == 4) {
		if (s[n] != '\0')
			return -EINVAL;
	} else if (sscanf(s, "%x:%x.%x%n", &bus, &dev, &fn, &n) == 3) {
		if (s[n] != '\0')
			return -EINVAL;
		d = 0;
	} else {
		return -EINVAL;
	}
	if (d > 0xffff || bus > 0xff || dev > 0x1f || fn > 7)
		return -EINVAL;
	*domain = d;
	*bdf = (bus << 8) | (dev << 3) | fn;
	return 0;
}

static int he_precheck_classes(void)
{
	struct pci_dev *pdev = NULL;
	int ret = 0;

	while ((pdev = pci_get_device(PCI_ANY_ID, PCI_ANY_ID, pdev))) {
		u8 base = (pdev->class >> 16) & 0xff;

		if (base != HE_CLASS_DISPLAY && base != HE_CLASS_ACCEL)
			continue;
		ret = he_precheck_one(pdev);
		if (ret) {
			pci_dev_put(pdev);
			return ret;
		}
	}
	return 0;
}

static int he_precheck_param(void)
{
	char *buf, *cursor, *tok;
	int ret = 0;

	if (!protect_bdf || !protect_bdf[0])
		return 0;
	buf = kstrdup(protect_bdf, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;
	cursor = buf;
	while ((tok = strsep(&cursor, ","))) {
		struct pci_dev *pdev;
		int domain;
		u16 bdf;

		while (*tok == ' ')
			tok++;
		if (!*tok)
			continue;
		if (he_parse_bdf(tok, &domain, &bdf)) {
			he_err("bad protect_bdf '%s'\n", tok);
			ret = -EINVAL;
			break;
		}
		pdev = pci_get_domain_bus_and_slot(domain, bdf >> 8,
						   bdf & 0xff);
		if (!pdev) {
			he_err("protect_bdf %s is not present\n", tok);
			ret = -ENODEV;
			break;
		}
		ret = he_precheck_one(pdev);
		pci_dev_put(pdev);
		if (ret)
			break;
	}
	kfree(buf);
	return ret;
}

int he_precheck_takeover(void)
{
	int ret;

	ret = he_precheck_classes();
	if (ret)
		return ret;
	return he_precheck_param();
}

static int he_bind_quarantine(struct pci_dev *pdev)
{
	char *name;
	int ret;

	if (pdev->driver) {
		if (!strcmp(pdev->driver->name, HE_QUARANTINE_NAME))
			return 0;
		he_err("%s still bound to %s\n", pci_name(pdev),
		       pdev->driver->name);
		return -EBUSY;
	}
	name = kstrdup(HE_QUARANTINE_NAME, GFP_KERNEL);
	if (!name)
		return -ENOMEM;
	device_lock(&pdev->dev);
	kfree(pdev->driver_override);
	pdev->driver_override = name;
	device_unlock(&pdev->dev);

	ret = device_attach(&pdev->dev);
	if (ret < 0)
		return ret;
	if (!pdev->driver || strcmp(pdev->driver->name, HE_QUARANTINE_NAME)) {
		he_err("failed to bind he-quarantine on %s\n", pci_name(pdev));
		return -ENODEV;
	}
	he_info("quarantine bound %s\n", pci_name(pdev));
	return 0;
}

int he_reconcile_protected_devices(void)
{
	struct he_dev_list *buf;
	int ret = 0;
	u32 i;

	buf = kzalloc(sizeof(*buf), GFP_KERNEL);
	if (!buf)
		return -ENOMEM;
	ret = hypercall_ret_1(HC_DEVICE_LIST, (unsigned long)buf);
	if (ret) {
		he_err("DeviceList hypercall returned %d\n", ret);
		ret = ret < 0 ? ret : -EIO;
		goto out;
	}
	if (buf->total != buf->count || buf->count > HE_DEVICE_LIST_MAX) {
		he_err("DeviceList truncated total=%u count=%u\n", buf->total,
		       buf->count);
		ret = -ENOSPC;
		goto out;
	}
	he_info("reconciling %u protected device(s)\n", buf->count);
	for (i = 0; i < buf->count; i++) {
		u16 bdf = buf->devices[i].bdf;
		struct pci_dev *pdev;

		pdev = pci_get_domain_bus_and_slot(0, bdf >> 8, bdf & 0xff);
		if (!pdev) {
			he_err("protected bdf %04x has no pci_dev\n", bdf);
			ret = -ENODEV;
			break;
		}
		ret = he_bind_quarantine(pdev);
		pci_dev_put(pdev);
		if (ret)
			break;
	}
out:
	kfree(buf);
	return ret;
}
