/*
 * vvar.h: Shared vDSO/kernel variable declarations
 * Copyright (c) 2011 Andy Lutomirski
 * Subject to the GNU General Public License, version 2
 *
 * A handful of variables are accessible (read-only) from userspace
 * code in the vsyscall page and the vdso.  They are declared here.
 * Some other file must define them with DEFINE_VVAR.
 *
 * In normal kernel code, they are used like any other variable.
 * In user code, they are accessed through the VVAR macro.
 *
 * These variables live in a page of kernel data that has an extra RO
 * mapping for userspace.  Each variable needs a unique offset within
 * that page; specify that offset with the DECLARE_VVAR macro.  (If
 * you mess up, the linker will catch it.)
 */

#ifndef _ASM_X86_PERCON_H
#define _ASM_X86_PERCON_H

#if defined(__PERCON_KERNEL_LDS)

/* The kernel linker script defines its own magic to put vvars in the
 * right place.
 */
#define DECLARE_PERCON(offset, type, name) \
	EMIT_PERCON(name, offset)

#else

extern char __percon_page;
extern char __percon_beginning;
extern char __percon_end;

#define DECLARE_PERCON(offset, type, name)				\
	extern type name __attribute__((visibility("hidden")));

#define PERCON(name) (name)

#define DEFINE_PERCON(type, name)						\
	type name							\
	__attribute__((section(".percon_" #name), aligned(16))) __visible

#endif

/* DECLARE_PERCON(offset, type, name) */

DECLARE_PERCON(0, struct dune_config, test_config)

#define PERCON_OFFSET_AZKFLAG	0x100
#define PERCON_OFFSET_INITTASK	0x200

#define AZK_FL_GUEST_BITPOS	0
#define AZK_FL_GUEST_MASK	(1UL << AZK_FL_GUEST_BITPOS)
#define AZK_FL_GUEST	(1UL << AZK_FL_GUEST_BITPOS)

DECLARE_PERCON(PERCON_OFFSET_AZKFLAG, uint64_t, azk_flags)

DECLARE_PERCON(PERCON_OFFSET_INITTASK, struct task_struct *, azk_init_task)

#undef DECLARE_PERCON

#endif
