// SPDX-License-Identifier: GPL-2.0
/*
 * HyperEnclave kernel module.
 *
 * Copyright (C) 2020-2023 The HyperEnclave Project. All rights reserved.
 *
 * Ring-3 access to the isolated-VM hypercalls. The monitor accepts them
 * only at CPL 0 and reads argument structs through the current guest page
 * tables, so the structs live in kernel memory. User pages being donated
 * are pinned; their host physical address is what the monitor calls a PFN.
 */

#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include <hyperenclave/hypercall.h>
#include <hyperenclave/log.h>
#include <hyperenclave/util.h>

#include "ioctl.h"
#include "ivm.h"

#define HE_IVM_MAX_PAGES 4096
#define HE_IVM_PAGE_MEASURE 1u

struct he_vm_add_page_req {
	u64 vm_id;
	u64 gpa;
	u64 pfn;
	u32 flags;
	u32 reserved;
} __packed;

struct he_vcpu_create_req {
	u64 vm_id;
	u32 idx;
	u32 pad;
	u64 rip, rsp, cr3;
	u64 gdtr_base, gdtr_limit;
	u64 idtr_base, idtr_limit;
	u64 exit_gpa;
} __packed;

struct he_vcpu_timer_req {
	u64 vm_id;
	u32 idx;
	u32 vector;
	u64 deadline;
} __packed;

struct he_dev_map_bar_req {
	u64 vm_id;
	u16 bdf;
	u16 bar;
	u32 pad;
	u64 gpa;
} __packed;

struct he_ivm_exit {
	u32 reason;
	u32 request;
	u64 gpa;
	u64 arg0;
	u64 arg1;
	u64 arg2;
} __packed;

struct he_ivm_page {
	struct list_head link;
	u64 vm_id;
	u64 gpa;
	struct page *page;
};

struct he_ivm_vcpu {
	struct list_head link;
	u64 vm_id;
	u32 idx;
	u64 exit_gpa;
};

struct he_ivm_vm {
	struct list_head link;
	u64 id;
};

struct he_ivm_file {
	struct mutex lock;
	struct list_head pages;
	struct list_head vcpus;
	struct list_head vms;
	unsigned int nr_pages;
};

static LIST_HEAD(he_ivm_orphans);
static DEFINE_MUTEX(he_ivm_orphan_lock);
static bool he_ivm_orphan_held;

static struct he_ivm_page *he_ivm_find_page(struct he_ivm_file *f, u64 vm,
					    u64 gpa)
{
	struct he_ivm_page *p;

	list_for_each_entry(p, &f->pages, link) {
		if (p->vm_id == vm && p->gpa == gpa)
			return p;
	}
	return NULL;
}

static void he_ivm_drop_page(struct he_ivm_file *f, struct he_ivm_page *p)
{
	list_del(&p->link);
	f->nr_pages--;
	put_page(p->page);
	kfree(p);
}

static void he_ivm_drop_vm(struct he_ivm_file *f, u64 vm)
{
	struct he_ivm_page *p, *pn;
	struct he_ivm_vcpu *v, *vn;
	struct he_ivm_vm *m, *mn;

	list_for_each_entry_safe(p, pn, &f->pages, link) {
		if (p->vm_id == vm)
			he_ivm_drop_page(f, p);
	}
	list_for_each_entry_safe(v, vn, &f->vcpus, link) {
		if (v->vm_id == vm) {
			list_del(&v->link);
			kfree(v);
		}
	}
	list_for_each_entry_safe(m, mn, &f->vms, link) {
		if (m->id == vm) {
			list_del(&m->link);
			kfree(m);
		}
	}
}

static int he_ivm_pin(struct he_ivm_file *f, u64 vm, u64 gpa, u64 uaddr,
		      struct he_ivm_page **out)
{
	struct he_ivm_page *p;
	struct page *page;
	long got;

	if (!uaddr || (uaddr & ~PAGE_MASK) || (gpa & ~PAGE_MASK))
		return -EINVAL;
	if (f->nr_pages >= HE_IVM_MAX_PAGES)
		return -ENOMEM;
	if (he_ivm_find_page(f, vm, gpa))
		return -EEXIST;
	got = get_user_pages_fast(uaddr, 1, FOLL_WRITE, &page);
	if (got != 1)
		return got < 0 ? got : -EFAULT;
	p = kzalloc(sizeof(*p), GFP_KERNEL);
	if (!p) {
		put_page(page);
		return -ENOMEM;
	}
	p->vm_id = vm;
	p->gpa = gpa;
	p->page = page;
	list_add(&p->link, &f->pages);
	f->nr_pages++;
	*out = p;
	return 0;
}

static int he_ivm_add(struct he_ivm_file *f, struct he_ivm_call *call,
		      bool shared)
{
	struct he_ivm_page *p;
	struct he_vm_add_page_req *req;
	int err;

	if (shared) {
		if (call->flags)
			return -EINVAL;
	} else if (call->flags & ~HE_IVM_PAGE_MEASURE) {
		return -EINVAL;
	}
	err = he_ivm_pin(f, call->vm_id, call->gpa, call->user_addr, &p);
	if (err)
		return err;
	req = kzalloc(sizeof(*req), GFP_KERNEL);
	if (!req) {
		he_ivm_drop_page(f, p);
		return -ENOMEM;
	}
	req->vm_id = call->vm_id;
	req->gpa = call->gpa;
	req->pfn = page_to_phys(p->page);
	req->flags = shared ? 0 : call->flags;
	call->ret = hypercall_ret_1(shared ? HC_VM_ADD_SHARED : HC_VM_ADD_PAGE,
				    (unsigned long)req);
	kfree(req);
	if (call->ret)
		he_ivm_drop_page(f, p);
	return 0;
}

static int he_ivm_note_vm(struct he_ivm_file *f, u64 id)
{
	struct he_ivm_vm *vm;

	vm = kzalloc(sizeof(*vm), GFP_KERNEL);
	if (!vm)
		return -ENOMEM;
	vm->id = id;
	list_add(&vm->link, &f->vms);
	return 0;
}

static struct he_ivm_vcpu *he_ivm_find_vcpu(struct he_ivm_file *f, u64 vm,
					    u32 idx)
{
	struct he_ivm_vcpu *v;

	list_for_each_entry(v, &f->vcpus, link) {
		if (v->vm_id == vm && v->idx == idx)
			return v;
	}
	return NULL;
}

static int he_ivm_dispatch(struct he_ivm_file *f, struct he_ivm_call *call)
{
	switch (call->op) {
	case HC_VM_CREATE: {
		int err;

		call->ret = hypercall_ret_0(HC_VM_CREATE);
		if (call->ret <= 0)
			return 0;
		err = he_ivm_note_vm(f, call->ret);
		if (err) {
			hypercall_ret_1(HC_VM_DESTROY, call->ret);
			return err;
		}
		call->vm_id = call->ret;
		return 0;
	}
	case HC_VM_DESTROY:
		call->ret = hypercall_ret_1(HC_VM_DESTROY, call->vm_id);
		if (!call->ret)
			he_ivm_drop_vm(f, call->vm_id);
		return 0;
	case HC_VM_FINALIZE:
		call->ret = hypercall_ret_1(HC_VM_FINALIZE, call->vm_id);
		return 0;
	case HC_VM_ADD_PAGE:
		return he_ivm_add(f, call, false);
	case HC_VM_ADD_SHARED:
		return he_ivm_add(f, call, true);
	case HC_VM_REMOVE_PAGE: {
		struct he_ivm_page *p;

		call->ret = hypercall_ret_2(HC_VM_REMOVE_PAGE, call->vm_id,
					    call->gpa);
		if (!call->ret) {
			p = he_ivm_find_page(f, call->vm_id, call->gpa);
			if (p)
				he_ivm_drop_page(f, p);
		}
		return 0;
	}
	case HC_VM_VCPU_CREATE: {
		struct he_vcpu_create_req *req;
		struct he_ivm_vcpu *vcpu;

		if (he_ivm_find_vcpu(f, call->vm_id, call->idx))
			return -EEXIST;
		req = kzalloc(sizeof(*req), GFP_KERNEL);
		vcpu = kzalloc(sizeof(*vcpu), GFP_KERNEL);
		if (!req || !vcpu) {
			kfree(req);
			kfree(vcpu);
			return -ENOMEM;
		}
		req->vm_id = call->vm_id;
		req->idx = call->idx;
		req->rip = call->rip;
		req->rsp = call->rsp;
		req->cr3 = call->cr3;
		req->gdtr_base = call->gdtr_base;
		req->gdtr_limit = call->gdtr_limit;
		req->idtr_base = call->idtr_base;
		req->idtr_limit = call->idtr_limit;
		req->exit_gpa = call->exit_gpa;
		call->ret = hypercall_ret_1(HC_VM_VCPU_CREATE,
					    (unsigned long)req);
		kfree(req);
		if (call->ret) {
			kfree(vcpu);
			return 0;
		}
		vcpu->vm_id = call->vm_id;
		vcpu->idx = call->idx;
		vcpu->exit_gpa = call->exit_gpa;
		list_add(&vcpu->link, &f->vcpus);
		return 0;
	}
	case HC_VM_VCPU_RUN: {
		struct he_ivm_vcpu *vcpu;
		struct he_ivm_page *page;
		void *kaddr;
		struct he_ivm_exit info;

		vcpu = he_ivm_find_vcpu(f, call->vm_id, call->idx);
		if (!vcpu)
			return -ENOENT;
		page = he_ivm_find_page(f, call->vm_id, vcpu->exit_gpa);
		if (!page)
			return -ENOENT;
		call->ret = hypercall_ret_2(HC_VM_VCPU_RUN, call->vm_id,
					    call->idx);
		if (call->ret)
			return 0;
		kaddr = page_address(page->page);
		if (!kaddr)
			return -EFAULT;
		memcpy(&info, kaddr, sizeof(info));
		call->reason = info.reason;
		call->request = info.request;
		call->arg0 = info.arg0;
		call->arg1 = info.arg1;
		call->arg2 = info.arg2;
		call->aux = info.gpa;
		return 0;
	}
	case HC_VM_VCPU_INJECT: {
		u64 packed = ((u64)call->vector << 32) | call->idx;

		call->ret = hypercall_ret_2(HC_VM_VCPU_INJECT, call->vm_id,
					    packed);
		return 0;
	}
	case HC_VM_VCPU_SET_TIMER: {
		struct he_vcpu_timer_req req;

		memset(&req, 0, sizeof(req));
		req.vm_id = call->vm_id;
		req.idx = call->idx;
		req.vector = call->vector;
		req.deadline = call->aux;
		call->ret = hypercall_ret_1(HC_VM_VCPU_SET_TIMER,
					    (unsigned long)&req);
		return 0;
	}
	case HC_DEV_ATTACH:
		call->ret = hypercall_ret_2(HC_DEV_ATTACH, call->bdf,
					    call->vm_id);
		return 0;
	case HC_DEV_DETACH:
		call->ret = hypercall_ret_2(HC_DEV_DETACH, call->bdf,
					    call->vm_id);
		return 0;
	case HC_DEV_MAP_BAR: {
		struct he_dev_map_bar_req req;

		memset(&req, 0, sizeof(req));
		req.vm_id = call->vm_id;
		req.bdf = call->bdf;
		req.bar = call->bar;
		req.gpa = call->gpa;
		call->ret = hypercall_ret_1(HC_DEV_MAP_BAR,
					    (unsigned long)&req);
		return 0;
	}
	case HC_VM_MEASURE: {
		u8 *digest;

		digest = kzalloc(32, GFP_KERNEL);
		if (!digest)
			return -ENOMEM;
		call->ret = hypercall_ret_2(HC_VM_MEASURE, call->vm_id,
					    (unsigned long)digest);
		if (!call->ret)
			memcpy(call->digest, digest, 32);
		kfree(digest);
		return 0;
	}
	default:
		return -EINVAL;
	}
}

static void he_ivm_orphan_pages(struct he_ivm_file *f)
{
	if (list_empty(&f->pages))
		return;
	he_err("isolated VM pages stay pinned; destroy did not finish\n");
	mutex_lock(&he_ivm_orphan_lock);
	list_splice_init(&f->pages, &he_ivm_orphans);
	f->nr_pages = 0;
	if (!he_ivm_orphan_held) {
		he_ivm_orphan_held = try_module_get(THIS_MODULE);
	}
	mutex_unlock(&he_ivm_orphan_lock);
}

static void he_ivm_close_vms(struct he_ivm_file *f)
{
	struct he_ivm_vm *m, *mn;

	list_for_each_entry_safe(m, mn, &f->vms, link) {
		int ret = 0;

		if (hyper_enclave_enabled)
			ret = hypercall_ret_1(HC_VM_DESTROY, m->id);
		if (!ret)
			he_ivm_drop_vm(f, m->id);
	}
	if (!list_empty(&f->pages))
		he_ivm_orphan_pages(f);
	/* Trackers for vcpus whose VM is gone. */
	{
		struct he_ivm_vcpu *v, *vn;

		list_for_each_entry_safe(v, vn, &f->vcpus, link) {
			list_del(&v->link);
			kfree(v);
		}
	}
}

int he_ivm_open(struct inode *inode, struct file *file)
{
	struct he_ivm_file *f;

	f = kzalloc(sizeof(*f), GFP_KERNEL);
	if (!f)
		return -ENOMEM;
	mutex_init(&f->lock);
	INIT_LIST_HEAD(&f->pages);
	INIT_LIST_HEAD(&f->vcpus);
	INIT_LIST_HEAD(&f->vms);
	file->private_data = f;
	return 0;
}

int he_ivm_release(struct inode *inode, struct file *file)
{
	struct he_ivm_file *f = file->private_data;

	if (!f)
		return 0;
	mutex_lock(&f->lock);
	he_ivm_close_vms(f);
	mutex_unlock(&f->lock);
	file->private_data = NULL;
	kfree(f);
	return 0;
}

long he_ivm_ioctl(struct file *file, unsigned long arg)
{
	struct he_ivm_call call;
	struct he_ivm_file *f = file->private_data;
	int err;

	BUILD_BUG_ON(sizeof(struct he_ivm_call) != 200);
	BUILD_BUG_ON(sizeof(struct he_vm_add_page_req) != 32);
	BUILD_BUG_ON(sizeof(struct he_vcpu_create_req) != 80);
	BUILD_BUG_ON(sizeof(struct he_vcpu_timer_req) != 24);
	BUILD_BUG_ON(sizeof(struct he_dev_map_bar_req) != 24);
	BUILD_BUG_ON(sizeof(struct he_ivm_exit) != 40);

	if (!f)
		return -EINVAL;
	if (copy_from_user(&call, (void __user *)arg, sizeof(call)))
		return -EFAULT;
	if (!hyper_enclave_enabled)
		return -ENODEV;
	if (mutex_lock_interruptible(&f->lock))
		return -EINTR;
	err = he_ivm_dispatch(f, &call);
	mutex_unlock(&f->lock);
	if (err)
		return err;
	if (copy_to_user((void __user *)arg, &call, sizeof(call)))
		return -EFAULT;
	return 0;
}
