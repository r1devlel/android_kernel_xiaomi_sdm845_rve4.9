obj-y := core.o
CFLAGS_core.o += $(call cc-disable-warning, override-init)

obj-$(CONFIG_BPF_SYSCALL) += syscall.o verifier.o inode.o helpers.o btf.o tnum.o disasm.o
obj-$(CONFIG_BPF_SYSCALL) += hashtab.o arraymap.o percpu_freelist.o bpf_lru_list.o map_in_map.o
obj-$(CONFIG_BPF_SYSCALL) += bpf_iter.o map_iter.o offload.o lpm_trie.o queue_stack_maps.o ringbuf.o
obj-$(CONFIG_INET) += reuseport_array.o
obj-$(CONFIG_BPF_JIT) += bpf_struct_ops.o
obj-$(CONFIG_BPF_JIT) += trampoline.o
ifeq ($(CONFIG_PERF_EVENTS),y)
obj-$(CONFIG_BPF_SYSCALL) += stackmap.o
endif
obj-$(CONFIG_CGROUP_BPF) += cgroup.o local_storage.o
ifeq ($(CONFIG_NET),y)
obj-$(CONFIG_BPF_SYSCALL) += bpf_local_storage.o net_namespace.o
endif
