/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_ERROR_INJECTION_H
#define _LINUX_ERROR_INJECTION_H

/*
 * 4.9 compatibility for modern BPF verifier code.
 * The base kernel does not provide the error-injection framework,
 * and FUNCTION_ERROR_INJECTION is not enabled by the current config.
 */
static inline bool within_error_injection_list(unsigned long addr)
{
	return false;
}

#endif /* _LINUX_ERROR_INJECTION_H */
