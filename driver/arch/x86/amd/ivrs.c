// SPDX-License-Identifier: GPL-2.0
/*
 * HyperEnclave kernel module.
 *
 * Copyright (C) 2020-2023 The HyperEnclave Project. All rights reserved.
 */

#include <linux/acpi.h>
#include <linux/sizes.h>

#include <hyperenclave/log.h>

#include "ivrs.h"

static int __init check_ivrs_checksum(struct acpi_table_header *table)
{
	int i;
	u8 checksum = 0, *p = (u8 *)table;

	for (i = 0; i < table->length; ++i)
		checksum += p[i];
	if (checksum != 0) {
		/* ACPI table corrupt */
		he_err(FW_BUG "IVRS invalid checksum\n");
		return -ENODEV;
	}
	return 0;
}

/*
 * Record every IVHD of `want`. Type 0x10 and 0x11 share the prefix this
 * function reads (type, length, mmio_phys); the walk advances by h->length
 * so the shorter type 0x10 entry is not overrun. Returns 0, or a
 * negative errno. The number of units is accumulated in `count`.
 */
static int append_ivhd(struct iommu_info *iommu_info, int *count, u8 want,
		       u8 *p, u8 *end)
{
	while (p < end) {
		struct ivhd_header *h = (struct ivhd_header *)p;
		void *mmio_base;
		u32 extended_feature;

		if (p + 4 > end || h->length < 16 || p + h->length > end) {
			he_err("IVHD entry overruns the IVRS table\n");
			return -EINVAL;
		}
		if (h->type == want) {
			if (*count >= HYPERENCLAVE_MAX_IOMMU_UNITS) {
				he_err("too many IOMMU units\n");
				return -ENOSPC;
			}
			iommu_info->iommu_units[*count].base = h->mmio_phys;
			/*
			 * AMD IOMMU spec, Capability Offset 04h: IOMMU Base
			 * Address Low. MMIO offset 0x30 bit 9 selects
			 * 512KB vs 16KB.
			 */
			mmio_base = ioremap(h->mmio_phys, SZ_4K);
			if (!mmio_base) {
				he_err("Fail to map iommu control registers\n");
				return -ENOMEM;
			}
			extended_feature = readl(mmio_base + 0x30);
			iounmap(mmio_base);
			if (extended_feature & (1 << 9))
				iommu_info->iommu_units[*count].size = SZ_512K;
			else
				iommu_info->iommu_units[*count].size = SZ_16K;
			++*count;
		}
		p += h->length;
	}
	return 0;
}

bool parse_ivrs(struct iommu_info *iommu_info)
{
	struct acpi_table_header *ivrs_base;
	acpi_status status;
	u8 *p, *end;
	int count_iommu = 0;
	int i;
	bool ret = false;
	const char *err;
	int rc;

	status = acpi_get_table("IVRS", 0, &ivrs_base);

	if (status == AE_NOT_FOUND) {
		he_err("IVRS acpi_table AE_NOT_FOUND\n");
		goto out;
	} else if (ACPI_FAILURE(status)) {
		err = acpi_format_exception(status);
		he_err("IVRS table: %s\n", err);
		goto out;
	}

	if (check_ivrs_checksum(ivrs_base)) {
		he_err("IVRS checksum wrong\n");
		goto out;
	}
	p = (u8 *)ivrs_base;
	end = (u8 *)ivrs_base;
	p += IVRS_HEADER_LENGTH;
	end += ivrs_base->length;
	/*
	 * Prefer type 0x11. Real firmware publishes 0x10 and 0x11 for the
	 * same IOMMU; recording both would register it twice. QEMU's
	 * amd-iommu publishes type 0x10 only, so fall back when 0x11 is
	 * absent.
	 */
	rc = append_ivhd(iommu_info, &count_iommu, 0x11, p, end);
	if (rc)
		goto out;
	if (count_iommu == 0) {
		rc = append_ivhd(iommu_info, &count_iommu, 0x10, p, end);
		if (rc)
			goto out;
		if (count_iommu)
			he_info("IVRS: using IVHD type 0x10 (%d unit(s))\n",
				count_iommu);
	}
	for (i = count_iommu; i < HYPERENCLAVE_MAX_IOMMU_UNITS; ++i) {
		iommu_info->iommu_units[i].base = 0;
		iommu_info->iommu_units[i].size = 0;
	}
	ret = true;
out:
	acpi_put_table(ivrs_base);
	return ret;
}
