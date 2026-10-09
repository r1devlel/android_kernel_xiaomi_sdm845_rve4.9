// SPDX-License-Identifier: GPL-2.0
/*
 * Compatibility stubs for BPF trampolines on this 4.9-based kernel.
 *
 * The upstream implementation requires newer RCU-trace, direct-ftrace,
 * executable-memory permission-reset and perf ksymbol APIs which are not
 * available in this tree. Keep the symbols needed by the BPF core, but
 * report trampoline attachment as unsupported instead of pretending the
 * newer implementation can run safely here.
 */
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/errno.h>
#include <linux/mm.h>

const struct bpf_verifier_ops bpf_extension_verifier_ops = {
};

const struct bpf_prog_ops bpf_extension_prog_ops = {
};

void *bpf_jit_alloc_exec_page(void)
{
	return bpf_jit_alloc_exec(PAGE_SIZE);
}

void bpf_image_ksym_add(void *data, struct bpf_ksym *ksym)
{
	ksym->start = (unsigned long)data;
	ksym->end = ksym->start + PAGE_SIZE;
	bpf_ksym_add(ksym);
}

void bpf_image_ksym_del(struct bpf_ksym *ksym)
{
	bpf_ksym_del(ksym);
}

int bpf_trampoline_link_prog(struct bpf_prog *prog, struct bpf_trampoline *tr)
{
	return -EOPNOTSUPP;
}

int bpf_trampoline_unlink_prog(struct bpf_prog *prog, struct bpf_trampoline *tr)
{
	return -EOPNOTSUPP;
}

struct bpf_trampoline *bpf_trampoline_get(u64 key,
					  struct bpf_attach_target_info *tgt_info)
{
	return NULL;
}

void bpf_trampoline_put(struct bpf_trampoline *tr)
{
}
