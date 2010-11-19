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
 * Copyright (C) IBM Corporation, 2008-2011
 * Authors:
 *	Srikar Dronamraju
 *	Jim Keniston
 */

#include <linux/rbtree.h>
#ifdef CONFIG_ARCH_SUPPORTS_UPROBES
#include <asm/uprobes.h>
struct uprobe_task_arch_info;	/* arch specific task info */
#else
/*
 * ARCH_SUPPORTS_UPROBES is not defined.
 */
typedef u8 uprobe_opcode_t;
struct uprobe_arch_info	{};		/* arch specific info*/
struct uprobe_task_arch_info {};	/* arch specific task info */
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

struct uprobe_consumer {
	int (*handler)(struct uprobe_consumer *self, struct pt_regs *regs);
	/*
	 * filter is optional; If a filter exists, handler is run
	 * if and only if filter returns true.
	 */
	bool (*filter)(struct uprobe_consumer *self, struct task_struct *task);

	struct uprobe_consumer *next;
};

struct uprobe {
	struct rb_node		rb_node;	/* node in the rb tree */
	atomic_t		ref;
	struct list_head	pending_list;
	struct rw_semaphore	consumer_rwsem;
	struct uprobe_arch_info	arch_info;	/* arch specific info if any */
	struct uprobe_consumer	*consumers;
	struct inode		*inode;		/* Also hold a ref to inode */
	loff_t			offset;
	u8			insn[MAX_UINSN_BYTES];	/* orig instruction */
	u16			fixups;
	int			copy;
};

enum uprobe_task_state {
	UTASK_RUNNING,
	UTASK_BP_HIT,
	UTASK_SSTEP
};

/*
 * uprobe_utask -- not a user-visible struct.
 * Corresponds to a thread in a probed process.
 * Guarded by uproc->mutex.
 */
struct uprobe_task {
	unsigned long xol_vaddr;
	unsigned long vaddr;

	enum uprobe_task_state state;
	struct uprobe_task_arch_info tskinfo;

	struct uprobe *active_uprobe;
};

/*
 * On a breakpoint hit, thread contests for a slot.  It free the
 * slot after singlestep.  Only definite number of slots are
 * allocated.
 */

struct uprobes_xol_area {
	spinlock_t slot_lock;	/* protects bitmap and slot (de)allocation*/
	wait_queue_head_t wq;	/* if all slots are busy */
	atomic_t slot_count;	/* currently in use slots */
	unsigned long *bitmap;	/* 0 = free slot */
	struct page *page;

	/*
	 * We keep the vma's vm_start rather than a pointer to the vma
	 * itself.  The probed process or a naughty kernel module could make
	 * the vma go away, and we must handle that reasonably gracefully.
	 */
	unsigned long vaddr;		/* Page(s) of instruction slots */
};

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

#ifdef CONFIG_UPROBES
extern int register_uprobe(struct inode *inode, loff_t offset,
				struct uprobe_consumer *consumer);
extern void unregister_uprobe(struct inode *inode, loff_t offset,
				struct uprobe_consumer *consumer);
extern void free_uprobe_utask(struct task_struct *tsk);

struct vm_area_struct;
extern int mmap_uprobe(struct vm_area_struct *vma);
extern void dup_mmap_uprobe(struct mm_struct *old_mm, struct mm_struct *mm);
extern void free_uprobes_xol_area(struct mm_struct *mm);
extern unsigned long __weak get_uprobe_bkpt_addr(struct pt_regs *regs);
extern int uprobe_post_notifier(struct pt_regs *regs);
extern int uprobe_bkpt_notifier(struct pt_regs *regs);
extern void uprobe_notify_resume(struct pt_regs *regs);
#else /* CONFIG_UPROBES is not defined */
static inline int register_uprobe(struct inode *inode, loff_t offset,
				struct uprobe_consumer *consumer)
{
	return -ENOSYS;
}
static inline void unregister_uprobe(struct inode *inode, loff_t offset,
				struct uprobe_consumer *consumer)
{
}
static inline void dup_mmap_uprobe(struct mm_struct *old_mm,
		struct mm_struct *mm)
{
}
static inline int mmap_uprobe(struct vm_area_struct *vma)
{
	return 0;
}
static inline void free_uprobe_utask(struct task_struct *tsk) {}
static inline void free_uprobes_xol_area(struct mm_struct *mm) {}
static inline void uprobe_notify_resume(struct pt_regs *regs) {}
static inline unsigned long get_uprobe_bkpt_addr(struct pt_regs *regs)
{
	return 0;
}
#endif /* CONFIG_UPROBES */
#endif	/* _LINUX_UPROBES_H */
