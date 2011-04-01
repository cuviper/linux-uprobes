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
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/ptrace.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/uprobes.h>
#include <linux/rmap.h> /* needed for anon_vma_prepare */

struct uprobe {
	u8			insn[MAX_UINSN_BYTES];
	u16			fixups;
};

/*
 * NOTE:
 * Expect the breakpoint instruction to be the smallest size instruction for
 * the architecture. If an arch has variable length instruction and the
 * breakpoint instruction is not of the smallest length instruction
 * supported by that architecture then we need to modify read_opcode /
 * write_opcode accordingly. This would never be a problem for arch's that
 * have fixed length instructions.
 */

/*
 * write_opcode - write the opcode at a given virtual address.
 * @tsk: the probed task.
 * @uprobe: the breakpointing information.
 * @vaddr: the virtual address to store the opcode.
 * @opcode: opcode to be written at @vaddr.
 *
 * Called with tsk->mm->mmap_sem held (for read and with a reference to
 * tsk->mm.
 *
 * For task @tsk, write the opcode at @vaddr.
 * Return 0 (success) or a negative errno.
 */
static int write_opcode(struct task_struct *tsk, struct uprobe * uprobe,
			unsigned long vaddr, uprobe_opcode_t opcode)
{
	struct page *old_page, *new_page;
	void *vaddr_old, *vaddr_new;
	struct vm_area_struct *vma;
	spinlock_t *ptl;
	pte_t *orig_pte;
	unsigned long addr;
	int ret;

	/* Read the page with vaddr into memory */
	ret = get_user_pages(tsk, tsk->mm, vaddr, 1, 1, 1, &old_page, &vma);
	if (ret <= 0)
		return -EINVAL;
	ret = -EINVAL;

	/*
	 * We are interested in text pages only. Our pages of interest
	 * should be mapped for read and execute only. We desist from
	 * adding probes in write mapped pages since the breakpoints
	 * might end up in the file copy.
	 */
	if ((vma->vm_flags & (VM_READ|VM_WRITE|VM_EXEC|VM_SHARED)) !=
						(VM_READ|VM_EXEC))
		goto put_out;

	/* Allocate a page */
	new_page = alloc_page_vma(GFP_HIGHUSER_MOVABLE, vma, vaddr);
	if (!new_page) {
		ret = -ENOMEM;
		goto put_out;
	}

	/*
	 * lock page will serialize against do_wp_page()'s
	 * PageAnon() handling
	 */
	lock_page(old_page);
	/* copy the page now that we've got it stable */
	vaddr_old = kmap_atomic(old_page, KM_USER0);
	vaddr_new = kmap_atomic(new_page, KM_USER1);

	memcpy(vaddr_new, vaddr_old, PAGE_SIZE);
	/* poke the new insn in, ASSUMES we don't cross page boundary */
	addr = vaddr;
	vaddr &= ~PAGE_MASK;
	memcpy(vaddr_new + vaddr, &opcode, uprobe_opcode_sz);

	kunmap_atomic(vaddr_new, KM_USER1);
	kunmap_atomic(vaddr_old, KM_USER0);

	orig_pte = page_check_address(old_page, tsk->mm, addr, &ptl, 0);
	if (!orig_pte)
		goto unlock_out;
	pte_unmap_unlock(orig_pte, ptl);

	lock_page(new_page);
	ret = anon_vma_prepare(vma);
	if (!ret)
		ret = replace_page(vma, old_page, new_page, *orig_pte);

	unlock_page(new_page);
	if (ret != 0)
		page_cache_release(new_page);
unlock_out:
	unlock_page(old_page);

put_out:
	put_page(old_page); /* we did a get_page in the beginning */
	return ret;
}

/**
 * read_opcode - read the opcode at a given virtual address.
 * @tsk: the probed task.
 * @vaddr: the virtual address to read the opcode.
 * @opcode: location to store the read opcode.
 *
 * Called with tsk->mm->mmap_sem held (for read and with a reference to
 * tsk->mm.
 *
 * For task @tsk, read the opcode at @vaddr and store it in @opcode.
 * Return 0 (success) or a negative errno.
 */
int __weak read_opcode(struct task_struct *tsk, unsigned long vaddr,
						uprobe_opcode_t *opcode)
{
	struct vm_area_struct *vma;
	struct page *page;
	void *vaddr_new;
	int ret;

	ret = get_user_pages(tsk, tsk->mm, vaddr, 1, 0, 0, &page, &vma);
	if (ret <= 0)
		return -EFAULT;
	ret = -EFAULT;

	/*
	 * We are interested in text pages only. Our pages of interest
	 * should be mapped for read and execute only. We desist from
	 * adding probes in write mapped pages since the breakpoints
	 * might end up in the file copy.
	 */
	if ((vma->vm_flags & (VM_READ|VM_WRITE|VM_EXEC|VM_SHARED)) !=
						(VM_READ|VM_EXEC))
		goto put_out;

	lock_page(page);
	vaddr_new = kmap_atomic(page, KM_USER0);
	vaddr &= ~PAGE_MASK;
	memcpy(opcode, vaddr_new + vaddr, uprobe_opcode_sz);
	kunmap_atomic(vaddr_new, KM_USER0);
	unlock_page(page);
	ret =  0;

put_out:
	put_page(page); /* we did a get_page in the beginning */
	return ret;
}

/**
 * set_bkpt - store breakpoint at a given address.
 * @tsk: the probed task.
 * @uprobe: the probepoint information.
 * @vaddr: the virtual address to insert the opcode.
 *
 * For task @tsk, store the breakpoint instruction at @vaddr.
 * Return 0 (success) or a negative errno.
 */
int __weak set_bkpt(struct task_struct *tsk, struct uprobe *uprobe,
						unsigned long vaddr)
{
	return write_opcode(tsk, uprobe, vaddr, UPROBES_BKPT_INSN);
}

/**
 * set_orig_insn - Restore the original instruction.
 * @tsk: the probed task.
 * @uprobe: the probepoint information.
 * @vaddr: the virtual address to insert the opcode.
 * @verify: if true, verify existance of breakpoint instruction.
 *
 * For task @tsk, restore the original opcode (opcode) at @vaddr.
 * Return 0 (success) or a negative errno.
 */
int __weak set_orig_insn(struct task_struct *tsk, struct uprobe *uprobe,
				unsigned long vaddr, bool verify)
{
	if (verify) {
		uprobe_opcode_t opcode;
		int result = read_opcode(tsk, vaddr, &opcode);
		if (result)
			return result;
		if (opcode != UPROBES_BKPT_INSN)
			return -EINVAL;
	}
	return write_opcode(tsk, uprobe, vaddr,
			*(uprobe_opcode_t *) uprobe->insn);
}

static void print_insert_fail(struct task_struct *tsk,
			unsigned long vaddr, const char *why)
{
	printk(KERN_ERR "Can't place breakpoint at pid %d vaddr %#lx: %s\n",
					tsk->pid, vaddr, why);
}

/*
 * uprobes_resume_can_sleep - Check if fixup might result in sleep.
 * @uprobes: the probepoint information.
 *
 * Returns true if fixup might result in sleep.
 */
static bool uprobes_resume_can_sleep(struct uprobe *uprobe)
{
	return uprobe->fixups & UPROBES_FIX_SLEEPY;
}

/**
 * is_bkpt_insn - check if instruction is breakpoint instruction.
 * @insn: instruction to be checked.
 * Default implementation of is_bkpt_insn
 * Returns true if @insn is a breakpoint instruction.
 */
bool __weak is_bkpt_insn(u8 *insn)
{
	uprobe_opcode_t opcode;

	memcpy(&opcode, insn, UPROBES_BKPT_INSN_SIZE);
	return (opcode == UPROBES_BKPT_INSN);
}
