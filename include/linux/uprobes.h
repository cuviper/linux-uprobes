#ifndef _LINUX_UPROBES_H
#define _LINUX_UPROBES_H
/*
 * Userspace Probes (UProbes)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Copyright (C) IBM Corporation, 2008-2010
 * Authors:
 *	Srikar Dronamraju
 *	Jim Keniston
 */

#ifdef CONFIG_ARCH_SUPPORTS_UPROBES
#include <asm/uprobes.h>
#else
/*
 * ARCH_SUPPORTS_UPROBES is not defined.
 */
typedef u8 uprobe_opcode_t;
#endif /* CONFIG_ARCH_SUPPORTS_UPROBES */

/* Post-execution fixups.  Some architectures may define others. */

/* No fixup needed */
#define UPROBES_FIX_NONE	0x0
/* Adjust IP back to vicinity of actual insn */
#define UPROBES_FIX_IP	0x1
/* Adjust the return address of a call insn */
#define UPROBES_FIX_CALL	0x2
/* Might sleep while doing Fixup */
#define UPROBES_FIX_SLEEPY	0x4

#ifndef UPROBES_FIX_DEFAULT
#define UPROBES_FIX_DEFAULT UPROBES_FIX_IP
#endif

/* Unexported functions & macros for use by arch-specific code */
#define uprobe_opcode_sz (sizeof(uprobe_opcode_t))

/*
 * Most architectures can use the default versions of @read_opcode(),
 * @set_bkpt(), @set_orig_insn(), and @is_bkpt_insn();
 *
 * @set_ip:
 *	Set the instruction pointer in @regs to @vaddr.
 * @analyze_insn:
 *	Analyze @user_bkpt->insn.  Return 0 if @user_bkpt->insn is an
 *	instruction you can probe, or a negative errno (typically -%EPERM)
 *	otherwise. Determine what sort of XOL-related fixups @post_xol()
 *	(and possibly @pre_xol()) will need to do for this instruction, and
 *	annotate @user_bkpt accordingly.  You may modify @user_bkpt->insn
 *	(e.g., the x86_64 port does this for rip-relative instructions).
 * @pre_xol:
 *	Called just before executing the instruction associated
 *	with @user_bkpt out of line.  @user_bkpt->xol_vaddr is the address
 *	in @tsk's virtual address space where @user_bkpt->insn has been
 *	copied.  @pre_xol() should at least set the instruction pointer in
 *	@regs to @user_bkpt->xol_vaddr -- which is what the default,
 *	@pre_xol(), does.
 * @post_xol:
 *	Called after executing the instruction associated with
 *	@user_bkpt out of line.  @post_xol() should perform the fixups
 *	specified in @user_bkpt->fixups, which includes ensuring that the
 *	instruction pointer in @regs points at the next instruction in
 *	the probed instruction stream.  @tskinfo is as for @pre_xol().
 *	You must provide this function.
 */
#endif	/* _LINUX_UPROBES_H */
