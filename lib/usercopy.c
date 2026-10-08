// SPDX-License-Identifier: GPL-2.0
#include <linux/export.h>
#include <linux/uaccess.h>

/* Kept as a real exported symbol for backported kernel interfaces. */
int check_zeroed_user(const void __user *from, size_t size)
{
	unsigned long val;
	const unsigned char __user *p = from;

	if (!size)
		return 1;

	while (size >= sizeof(val)) {
		if (copy_from_user(&val, p, sizeof(val)))
			return -EFAULT;
		if (val)
			return 0;
		p += sizeof(val);
		size -= sizeof(val);
	}

	if (size) {
		val = 0;
		if (copy_from_user(&val, p, size))
			return -EFAULT;
		if (val)
			return 0;
	}

	return 1;
}
EXPORT_SYMBOL(check_zeroed_user);
