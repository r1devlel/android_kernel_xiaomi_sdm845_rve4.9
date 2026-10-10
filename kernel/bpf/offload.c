// SPDX-License-Identifier: GPL-2.0
/*
 * BPF device offload compatibility stubs for this 4.9-based kernel.
 *
 * The upstream offload implementation depends on netdev BPF APIs that are
 * not present in this tree (ndo_bpf, struct netdev_bpf, and related APIs).
 * This kernel does not provide the required networking integration, so keep
 * device offload explicitly unsupported while allowing core BPF to build.
 */
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/err.h>
#include <linux/netdevice.h>

int bpf_prog_offload_compile(struct bpf_prog *prog)
{
	return -EOPNOTSUPP;
}

void bpf_prog_offload_destroy(struct bpf_prog *prog)
{
}

int bpf_prog_offload_info_fill(struct bpf_prog_info *info,
			       struct bpf_prog *prog)
{
	return -EOPNOTSUPP;
}

int bpf_map_offload_info_fill(struct bpf_map_info *info, struct bpf_map *map)
{
	return -EOPNOTSUPP;
}

int bpf_map_offload_lookup_elem(struct bpf_map *map, void *key, void *value)
{
	return -EOPNOTSUPP;
}

int bpf_map_offload_update_elem(struct bpf_map *map, void *key, void *value,
				u64 flags)
{
	return -EOPNOTSUPP;
}

int bpf_map_offload_delete_elem(struct bpf_map *map, void *key)
{
	return -EOPNOTSUPP;
}

int bpf_map_offload_get_next_key(struct bpf_map *map, void *key,
				 void *next_key)
{
	return -EOPNOTSUPP;
}

bool bpf_offload_prog_map_match(struct bpf_prog *prog, struct bpf_map *map)
{
	return false;
}

struct bpf_offload_dev *
bpf_offload_dev_create(const struct bpf_prog_offload_ops *ops, void *priv)
{
	return ERR_PTR(-EOPNOTSUPP);
}

void bpf_offload_dev_destroy(struct bpf_offload_dev *offdev)
{
}

void *bpf_offload_dev_priv(struct bpf_offload_dev *offdev)
{
	return NULL;
}

int bpf_offload_dev_netdev_register(struct bpf_offload_dev *offdev,
				    struct net_device *netdev)
{
	return -EOPNOTSUPP;
}

void bpf_offload_dev_netdev_unregister(struct bpf_offload_dev *offdev,
				       struct net_device *netdev)
{
}

bool bpf_offload_dev_match(struct bpf_prog *prog, struct net_device *netdev)
{
	return false;
}

int bpf_prog_offload_init(struct bpf_prog *prog, union bpf_attr *attr)
{
	return -EOPNOTSUPP;
}

struct bpf_map *bpf_map_offload_map_alloc(union bpf_attr *attr)
{
	return ERR_PTR(-EOPNOTSUPP);
}

void bpf_map_offload_map_free(struct bpf_map *map)
{
}

/*
 * The 4.9 tree has no netdev BPF offload backend. These entry points are
 * required by the newer verifier/syscall code, but must fail closed.
 */
int bpf_prog_offload_verifier_prep(struct bpf_prog *prog)
{
	return -EOPNOTSUPP;
}

/* No offload backend is available in this 4.9 tree. Ordinary programs
 * have nothing to finalize; fail closed if an offload object ever exists.
 */
int bpf_prog_offload_finalize(struct bpf_verifier_env *env)
{
	return env->prog->aux->offload ? -EOPNOTSUPP : 0;
}

void bpf_prog_offload_replace_insn(struct bpf_verifier_env *env, u32 off,
				   struct bpf_insn *insn)
{
}

const struct bpf_prog_ops bpf_offload_prog_ops = {
};
