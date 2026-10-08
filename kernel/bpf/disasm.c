// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2011-2014 PLUMgrid, http://plumgrid.com
 * Copyright (c) 2016 Facebook
 */

#include <linux/bpf.h>
#include "disasm.h"

#define __BPF_FUNC_STR_FN(x) [BPF_FUNC_ ## x] = __stringify(bpf_ ## x)
static const char * const func_id_str[] = {
	__BPF_FUNC_MAPPER(__BPF_FUNC_STR_FN)
};
#undef __BPF_FUNC_STR_FN

const char *func_id_name(int id)
{
	if (id >= 0 && id < __BPF_FUNC_MAX_ID && func_id_str[id])
		return func_id_str[id];
	return "unknown";
}

const char *const bpf_class_string[8] = {
	[BPF_LD] = "ld", [BPF_LDX] = "ldx", [BPF_ST] = "st",
	[BPF_STX] = "stx", [BPF_ALU] = "alu", [BPF_JMP] = "jmp",
	[BPF_JMP32] = "jmp32", [BPF_ALU64] = "alu64",
};
const char *const bpf_alu_string[16] = {
	[BPF_ADD >> 4] = "+=", [BPF_SUB >> 4] = "-=", [BPF_MUL >> 4] = "*=",
	[BPF_DIV >> 4] = "/=", [BPF_OR >> 4] = "|=", [BPF_AND >> 4] = "&=",
	[BPF_LSH >> 4] = "<<=", [BPF_RSH >> 4] = ">>=", [BPF_NEG >> 4] = "neg",
	[BPF_MOD >> 4] = "%=", [BPF_XOR >> 4] = "^=", [BPF_MOV >> 4] = "=",
	[BPF_ARSH >> 4] = "s>>=", [BPF_END >> 4] = "endian",
};

void print_bpf_insn(const struct bpf_insn_cbs *cbs,
		    const struct bpf_insn *insn, bool allow_ptr_leaks)
{
	const bpf_insn_print_t verbose = cbs->cb_print;
	u8 class = BPF_CLASS(insn->code);
	char tmp[64];

	if (class == BPF_ALU || class == BPF_ALU64) {
		verbose(cbs->private_data, "(%02x) %c%d op %c%d\n",
			insn->code, class == BPF_ALU ? 'w' : 'r',
			insn->dst_reg, BPF_SRC(insn->code) == BPF_X ? 'r' : 'i',
			BPF_SRC(insn->code) == BPF_X ? insn->src_reg : insn->imm);
	} else if (class == BPF_JMP32 || class == BPF_JMP) {
		verbose(cbs->private_data, "(%02x) jmp\n", insn->code);
	} else {
		verbose(cbs->private_data, "(%02x) %s\n",
			insn->code, bpf_class_string[class]);
	}
}
