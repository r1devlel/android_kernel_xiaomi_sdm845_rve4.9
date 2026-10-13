/* Copyright (c) 2011-2014 PLUMgrid, http://plumgrid.com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 */
#include <linux/bpf.h>
#include <linux/rcupdate.h>
#include <linux/random.h>
#include <linux/smp.h>
#include <linux/ktime.h>
#include <linux/sched.h>
#include <linux/uidgid.h>
#include <linux/filter.h>
#include <linux/ctype.h>
#include <linux/kernel.h>

/* If kernel subsystem is allowing eBPF programs to call this function,
 * inside its own verifier_ops->get_func_proto() callback it should return
 * bpf_map_lookup_elem_proto, so that verifier can properly check the arguments
 *
 * Different map implementations will rely on rcu in map methods
 * lookup/update/delete, therefore eBPF programs must run under rcu lock
 * if program is allowed to access maps, so check rcu_read_lock_held in
 * all three functions.
 */
BPF_CALL_2(bpf_map_lookup_elem, struct bpf_map *, map, void *, key)
{
	WARN_ON_ONCE(!rcu_read_lock_held());
	return (unsigned long) map->ops->map_lookup_elem(map, key);
}

const struct bpf_func_proto bpf_map_lookup_elem_proto = {
	.func		= bpf_map_lookup_elem,
	.gpl_only	= false,
	.pkt_access	= true,
	.ret_type	= RET_PTR_TO_MAP_VALUE_OR_NULL,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_MAP_KEY,
};

BPF_CALL_4(bpf_map_update_elem, struct bpf_map *, map, void *, key,
	   void *, value, u64, flags)
{
	WARN_ON_ONCE(!rcu_read_lock_held());
	return map->ops->map_update_elem(map, key, value, flags);
}

const struct bpf_func_proto bpf_map_update_elem_proto = {
	.func		= bpf_map_update_elem,
	.gpl_only	= false,
	.pkt_access	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_MAP_KEY,
	.arg3_type	= ARG_PTR_TO_MAP_VALUE,
	.arg4_type	= ARG_ANYTHING,
};

BPF_CALL_2(bpf_map_delete_elem, struct bpf_map *, map, void *, key)
{
	WARN_ON_ONCE(!rcu_read_lock_held());
	return map->ops->map_delete_elem(map, key);
}

const struct bpf_func_proto bpf_map_delete_elem_proto = {
	.func		= bpf_map_delete_elem,
	.gpl_only	= false,
	.pkt_access	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_MAP_KEY,
};

const struct bpf_func_proto bpf_get_prandom_u32_proto = {
	.func		= bpf_user_rnd_u32,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
};

BPF_CALL_0(bpf_get_smp_processor_id)
{
	return smp_processor_id();
}

const struct bpf_func_proto bpf_get_smp_processor_id_proto = {
	.func		= bpf_get_smp_processor_id,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
};

BPF_CALL_0(bpf_ktime_get_ns)
{
	/* NMI safe access to clock monotonic */
	return ktime_get_mono_fast_ns();
}

const struct bpf_func_proto bpf_ktime_get_ns_proto = {
	.func		= bpf_ktime_get_ns,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
};

BPF_CALL_0(bpf_get_current_pid_tgid)
{
	struct task_struct *task = current;

	if (unlikely(!task))
		return -EINVAL;

	return (u64) task->tgid << 32 | task->pid;
}

const struct bpf_func_proto bpf_get_current_pid_tgid_proto = {
	.func		= bpf_get_current_pid_tgid,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
};

BPF_CALL_0(bpf_get_current_uid_gid)
{
	struct task_struct *task = current;
	kuid_t uid;
	kgid_t gid;

	if (unlikely(!task))
		return -EINVAL;

	current_uid_gid(&uid, &gid);
	return (u64) from_kgid(&init_user_ns, gid) << 32 |
		     from_kuid(&init_user_ns, uid);
}

const struct bpf_func_proto bpf_get_current_uid_gid_proto = {
	.func		= bpf_get_current_uid_gid,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
};

BPF_CALL_2(bpf_get_current_comm, char *, buf, u32, size)
{
	struct task_struct *task = current;

	if (unlikely(!task))
		goto err_clear;

	strncpy(buf, task->comm, size);

	/* Verifier guarantees that size > 0. For task->comm exceeding
	 * size, guarantee that buf is %NUL-terminated. Unconditionally
	 * done here to save the size test.
	 */
	buf[size - 1] = 0;
	return 0;
err_clear:
	memset(buf, 0, size);
	return -EINVAL;
}

const struct bpf_func_proto bpf_get_current_comm_proto = {
	.func		= bpf_get_current_comm,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg2_type	= ARG_CONST_SIZE,
};

/*
 * Backport the value-copy helper used by maps containing bpf_spin_lock.
 * The lock word is the BPF ABI's 32-bit val field; preemption is disabled
 * while held, matching the verifier's non-sleeping lock contract.
 */
void copy_map_value_locked(struct bpf_map *map, void *dst, void *src,
			   bool lock_src)
{
	struct bpf_spin_lock *lock;
	u32 old;

	if (WARN_ON_ONCE(!map_value_has_spin_lock(map))) {
		copy_map_value(map, dst, src);
		return;
	}

	lock = (struct bpf_spin_lock *)((char *)(lock_src ? src : dst) +
					map->spin_lock_off);
	preempt_disable();
	do {
		old = cmpxchg(&lock->val, 0, 1);
		if (old)
			cpu_relax();
	} while (old);
	copy_map_value(map, dst, src);
	WRITE_ONCE(lock->val, 0);
	preempt_enable();
}

/*
 * Minimal helper dispatch for helpers implemented by this 4.9 tree.
 * Helpers without a compatible implementation remain unavailable.
 */
const struct bpf_func_proto *bpf_base_func_proto(enum bpf_func_id func_id)
{
	switch (func_id) {
	case BPF_FUNC_map_lookup_elem:
		return &bpf_map_lookup_elem_proto;
	case BPF_FUNC_map_update_elem:
		return &bpf_map_update_elem_proto;
	case BPF_FUNC_map_delete_elem:
		return &bpf_map_delete_elem_proto;
	case BPF_FUNC_get_prandom_u32:
		return &bpf_get_prandom_u32_proto;
	case BPF_FUNC_get_smp_processor_id:
		return &bpf_get_smp_processor_id_proto;
	case BPF_FUNC_ktime_get_ns:
		return &bpf_ktime_get_ns_proto;
	case BPF_FUNC_get_current_pid_tgid:
		return &bpf_get_current_pid_tgid_proto;
	case BPF_FUNC_get_current_uid_gid:
		return &bpf_get_current_uid_gid_proto;
	case BPF_FUNC_get_current_comm:
		return &bpf_get_current_comm_proto;
	default:
		return NULL;
	}
}


/*
 * Backport the bounded integer parsing helpers used by modern BPF programs.
 * Keep parsing bounded by buf_len: BPF callers do not pass a NUL-terminated
 * string contract.
 */
#define BPF_STRTOX_BASE_MASK 0x1F

static int __bpf_strtoull(const char *buf, size_t buf_len, u64 flags,
                          unsigned long long *res, bool *is_negative)
{
        unsigned int base = flags & BPF_STRTOX_BASE_MASK;
        const char *cur_buf = buf;
        size_t cur_len = buf_len;
        unsigned int consumed;
        size_t val_len;
        char str[64];

        if (!buf || !buf_len || !res || !is_negative)
                return -EINVAL;
        if (base != 0 && base != 8 && base != 10 && base != 16)
                return -EINVAL;
        if (flags & ~BPF_STRTOX_BASE_MASK)
                return -EINVAL;

        while (cur_buf < buf + buf_len && isspace(*cur_buf))
                ++cur_buf;
        *is_negative = cur_buf < buf + buf_len && *cur_buf == '-';
        if (*is_negative)
                ++cur_buf;

        consumed = cur_buf - buf;
        cur_len -= consumed;
        if (!cur_len)
                return -EINVAL;

        cur_len = min(cur_len, sizeof(str) - 1);
        memcpy(str, cur_buf, cur_len);
        str[cur_len] = '\0';
        cur_buf = str;
        cur_buf = _parse_integer_fixup_radix(cur_buf, &base);
        val_len = _parse_integer(cur_buf, base, res);
        if (val_len & KSTRTOX_OVERFLOW)
                return -ERANGE;
        if (!val_len)
                return -EINVAL;
        cur_buf += val_len;
        consumed += cur_buf - str;
        return consumed;
}

static int __bpf_strtoll(const char *buf, size_t buf_len, u64 flags,
                         long long *res)
{
        unsigned long long value;
        bool is_negative;
        int err;

        err = __bpf_strtoull(buf, buf_len, flags, &value, &is_negative);
        if (err < 0)
                return err;
        if (is_negative) {
                if ((long long)-value > 0)
                        return -ERANGE;
                *res = -value;
        } else {
                if ((long long)value < 0)
                        return -ERANGE;
                *res = value;
        }
        return err;
}

BPF_CALL_4(bpf_strtol, const char *, buf, size_t, buf_len, u64, flags,
           s64 *, res)
{
        long long value;
        int err = __bpf_strtoll(buf, buf_len, flags, &value);

        if (err < 0)
                return err;
        if (value != (long)value)
                return -ERANGE;
        *res = value;
        return err;
}

const struct bpf_func_proto bpf_strtol_proto = {
        .func           = bpf_strtol,
        .gpl_only       = false,
        .ret_type       = RET_INTEGER,
        .arg1_type      = ARG_PTR_TO_MEM,
        .arg2_type      = ARG_CONST_SIZE,
        .arg3_type      = ARG_ANYTHING,
        .arg4_type      = ARG_PTR_TO_LONG,
};

BPF_CALL_4(bpf_strtoul, const char *, buf, size_t, buf_len, u64, flags,
           u64 *, res)
{
        unsigned long long value;
        bool is_negative;
        int err;

        err = __bpf_strtoull(buf, buf_len, flags, &value, &is_negative);
        if (err < 0)
                return err;
        if (is_negative)
                return -EINVAL;
        if (value != (unsigned long)value)
                return -ERANGE;
        *res = value;
        return err;
}

const struct bpf_func_proto bpf_strtoul_proto = {
        .func           = bpf_strtoul,
        .gpl_only       = false,
        .ret_type       = RET_INTEGER,
        .arg1_type      = ARG_PTR_TO_MEM,
        .arg2_type      = ARG_CONST_SIZE,
        .arg3_type      = ARG_ANYTHING,
        .arg4_type      = ARG_PTR_TO_LONG,
};
