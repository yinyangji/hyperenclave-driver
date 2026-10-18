/* SPDX-License-Identifier: GPL-2.0 */
/*
 * HyperEnclave kernel module.
 *
 * Copyright (C) 2020-2023 The HyperEnclave Project. All rights reserved.
 */

#ifndef _DRIVER_IOCTL_H
#define _DRIVER_IOCTL_H

#include <linux/ioctl.h>
#include <linux/types.h>

struct he_encl_create {
	__u64 config_address;
};

struct he_encl_add_page {
	__u64 source_address; /* Gva of source page */
	__u64 enclave_lin_addr; /* Gva of target page */
	__u64 flags;
	__u32 attr;
};

struct he_encl_init {
	__u64 addr;
	__u64 sigstruct;
	__u64 einittoken;
};

struct he_memory_info {
	unsigned long start_addr;
	unsigned long size;
	unsigned long encl_addr;
};

struct he_encl_reset_stats {
	__u64 elrange_base_addr;
};

/**
 * struct he_edmm_enabled - parames for ioctl
 *                            %HE_IOC_EDMM_ENABLED
 * @flags:	(output) Whether EDMM is enabled, 1 for enabled, 0 for disabled
 */
struct he_edmm_enabled {
	__u64 flags;
};

/**
 * struct he_hypercall_opcode - parames for ioctl
 *                                %HE_IOC_HYPERCALL_OPCODE
 * @opcode:	(output) The operation code of hyper call on this platform
 */
struct he_hypercall_opcode {
	__u64 opcode;
};

/**
 * struct he_encl_restrict_permissions - parameters for ioctl
 *                                       %HE_IOC_ENCLAVE_RESTRICT_PERMISSIONS
 * @start_addr:	starting linear address (page aligned)
 * @length:	length of memory in bytes (page aligned)
 * @permissions:new permission bits for pages in range described by @start_addr
 *              and @length
 * @result:	(output) HYPER ENCLAVE result code of ENCLS[EMODPR] function
 * @count: 	(output) bytes successfully changed (multiple of page size)
 */
struct he_encl_restrict_permissions {
	__u64 start_addr;
	__u64 length;
	__u64 permissions;
	__u64 result;
	__u64 count;
};

/**
 * struct he_encl_modify_types - parameters for ioctl
 *                               %HE_IOC_ENCLAVE_MODIFY_TYPES
 * @start_addr:	starting linear address (page aligned)
 * @length:	length of memory in bytes (page aligned)
 * @page_type:	new type for pages in range described by @addr and @length
 * @result:	(output) HYPER ENCLAVE result code of ENCLS[EMODT] function
 * @count:	(output) bytes successfully changed (multiple of page size)
 */
struct he_encl_modify_types {
	__u64 start_addr;
	__u64 length;
	__u64 page_type;
	__u64 result;
	__u64 count;
};

/**
 * struct he_encl_remove_pages - %HE_IOC_ENCLAVE_REMOVE_PAGES parameters
 * @start_addr:	starting linear address (page aligned)
 * @length:	length of memory in bytes (page aligned)
 * @count:	(output) bytes successfully changed (multiple of page size)
 *
 * Regular (PT_REG) or TCS (PT_TCS) can be removed from an initialized
 * enclave if the system supports EDMM. First, the %HE_IOC_ENCLAVE_MODIFY_TYPE
 * ioctl() should be used to change the page type to PT_TRIM. After that
 * succeeds ENCLU[EACCEPT] should be run from within the enclave and then
 * %HE_IOC_ENCLAVE_REMOVE_PAGES can be used to complete the page removal.
 */
struct he_encl_remove_pages {
	__u64 start_addr;
	__u64 length;
	__u64 count;
};

#define TEE_MAGIC (0x0)

#define HE_IOC_HYPERCALL_OPCODE _IOW(TEE_MAGIC, 0, struct he_hypercall_opcode)

#define HE_IOC_ENCLAVE_CREATE _IOW(TEE_MAGIC, 7, struct he_encl_create)
#define HE_IOC_ENCLAVE_ADD_PAGE _IOW(TEE_MAGIC, 8, struct he_encl_add_page)
#define HE_IOC_ENCLAVE_INIT _IOW(TEE_MAGIC, 9, struct he_encl_init)

#define HE_IOC_ENCLAVE_ADD_SHARED_MEMORY \
	_IOW(TEE_MAGIC, 12, struct he_memory_info)
#define HE_IOC_ENCLAVE_REMOVE_SHARED_MEMORY \
	_IOW(TEE_MAGIC, 13, struct he_memory_info)
#define HE_IOC_ENCLAVE_RESET_STATS \
	_IOW(TEE_MAGIC, 14, struct he_encl_reset_stats)

#define HE_IOC_EDMM_ENABLED _IOW(TEE_MAGIC, 0x19, struct he_edmm_enabled)
#define HE_IOC_ENCLAVE_RESTRICT_PERMISSIONS \
	_IOW(TEE_MAGIC, 0x20, struct he_encl_restrict_permissions)
#define HE_IOC_ENCLAVE_MODIFY_TYPES \
	_IOW(TEE_MAGIC, 0x21, struct he_encl_modify_types)
#define HE_IOC_ENCLAVE_REMOVE_PAGES \
	_IOW(TEE_MAGIC, 0x22, struct he_encl_remove_pages)

/*
 * Isolated-VM hypercall, run from this driver so the monitor sees CPL 0.
 * `op` is HC_DEVICE_MAP_DMA / HC_DEVICE_UNMAP_DMA (0x53/0x54) or one of
 * HC_VM_* / HC_DEV_* (0x60–0x6d). `ret` is the hypercall result: a
 * positive vm id, 0, or a negative errno.
 *
 * ADD_PAGE / ADD_SHARED: `user_addr` is one pinned 4KB page. `flags` bit 0
 * is VM_PAGE_MEASURE. Bit 1 (VM_PAGE_2M) asks the driver to allocate one
 * order-9 kernel block itself: `user_addr` must be 0, `gpa` must be
 * 2MB-aligned, and the host physical address is not returned. After a
 * successful add or remove, `digest[0]` and `digest[1]` are the bytes L1
 * reads at the two ends of that block. A non-zero `aux` smaller than 2MB
 * is added to the physical address before the hypercall so an unaligned
 * donation can be rejected; that block is not kept.
 *
 * MAP_DMA / UNMAP_DMA: `user_addr` points at a 1560-byte DeviceDmaMapReq.
 * `flags` bit 0 (only on these ops) fills maps[0].paddr from the page
 * already donated at `gpa`. The physical address is not copied back.
 *
 * After VCPU_RUN, reason/request/arg0/arg1/arg2 are ExitInfo and `aux`
 * is the exit GPA.
 *
 * Packed layout is 200 bytes. cloud-hypervisor/ivm_launch/he_ivm.h
 * must match.
 */
struct he_ivm_call {
	__u32 op;
	__u32 idx;
	__s64 ret;
	__u64 vm_id;
	__u64 gpa;
	__u64 user_addr;
	__u32 flags;
	__u32 vector;
	__u64 aux;
	__u64 rip;
	__u64 rsp;
	__u64 cr3;
	__u64 gdtr_base;
	__u64 gdtr_limit;
	__u64 idtr_base;
	__u64 idtr_limit;
	__u64 exit_gpa;
	__u32 reason;
	__u32 request;
	__u64 arg0;
	__u64 arg1;
	__u64 arg2;
	__u64 bdf;
	__u32 bar;
	__u32 _pad;
	__u8 digest[32];
} __packed;

#define HE_IOC_IVM _IOWR(TEE_MAGIC, 0x30, struct he_ivm_call)

#endif /* !_DRIVER_IOCTL_H */
