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
#include <linux/mman.h>	/* needed for PROT_EXEC, MAP_PRIVATE */
#include <linux/file.h> /* needed for fput() */
#include <linux/kdebug.h> /* needed for notifier mechanism */

#define UINSNS_PER_PAGE	(PAGE_SIZE/UPROBES_XOL_SLOT_BYTES)
#define MAX_UPROBES_XOL_SLOTS UINSNS_PER_PAGE

/*
 * valid_vma: Verify if the specified vma is an executable vma,
 * but not an XOL vma.
 *	- Return 1 if the specified virtual address is in an
 *	  executable vma, but not in an XOL vma.
 */
static bool valid_vma(struct vm_area_struct *vma)
{
	struct uprobes_xol_area *area = vma->vm_mm->uprobes_xol_area;

	if (!vma->vm_file)
		return false;

	if (area && (area->vaddr == vma->vm_start))
			return false;

	if ((vma->vm_flags & (VM_READ|VM_WRITE|VM_EXEC|VM_SHARED)) ==
						(VM_READ|VM_EXEC))
		return true;

	return false;
}

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
	struct address_space *mapping;
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
	if (!valid_vma(vma))
		goto put_out;

	mapping = uprobe->inode->i_mapping;
	if (mapping != vma->vm_file->f_mapping)
		goto put_out;

	addr = vma->vm_start + uprobe->offset;
	addr -= vma->vm_pgoff << PAGE_SHIFT;
	if (addr > ULONG_MAX)
		goto put_out;

	if (vaddr != (unsigned long) addr)
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
	if (!valid_vma(vma))
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

static struct rb_root uprobes_tree = RB_ROOT;
static DEFINE_SPINLOCK(treelock);

static int match_inode(struct uprobe *uprobe, struct inode *inode,
						struct rb_node **p)
{
	struct rb_node *n = *p;

	if (inode < uprobe->inode)
		*p = n->rb_left;
	else if (inode > uprobe->inode)
		*p = n->rb_right;
	else
		return 1;
	return 0;
}

static int match_offset(struct uprobe *uprobe, loff_t offset,
						struct rb_node **p)
{
	struct rb_node *n = *p;

	if (offset < uprobe->offset)
		*p = n->rb_left;
	else if (offset > uprobe->offset)
		*p = n->rb_right;
	else
		return 1;
	return 0;
}


/* Called with treelock held */
static struct uprobe *__find_uprobe(struct inode * inode,
			 loff_t offset, struct rb_node **near_match)
{
	struct rb_node *n = uprobes_tree.rb_node;
	struct uprobe *uprobe, *u = NULL;

	while (n) {
		uprobe = rb_entry(n, struct uprobe, rb_node);
		if (match_inode(uprobe, inode, &n)) {
			if (near_match)
				*near_match = n;
			if (match_offset(uprobe, offset, &n)) {
				/* get access ref */
				atomic_inc(&uprobe->ref);
				u = uprobe;
				break;
			}
		}
	}
	return u;
}

/*
 * Find a uprobe corresponding to a given inode:offset
 * Acquires treelock
 */
static struct uprobe *find_uprobe(struct inode * inode, loff_t offset)
{
	struct uprobe *uprobe;
	unsigned long flags;

	spin_lock_irqsave(&treelock, flags);
	uprobe = __find_uprobe(inode, offset, NULL);
	spin_unlock_irqrestore(&treelock, flags);
	return uprobe;
}

/*
 * Acquires treelock.
 * Matching uprobe already exists in rbtree;
 *	increment (access refcount) and return the matching uprobe.
 *
 * No matching uprobe; insert the uprobe in rb_tree;
 *	get a double refcount (access + creation) and return NULL.
 */
static struct uprobe *insert_uprobe(struct uprobe *uprobe)
{
	struct rb_node **p = &uprobes_tree.rb_node;
	struct rb_node *parent = NULL;
	struct uprobe *u;
	unsigned long flags;

	spin_lock_irqsave(&treelock, flags);
	while (*p) {
		parent = *p;
		u = rb_entry(parent, struct uprobe, rb_node);
		if (u->inode > uprobe->inode)
			p = &(*p)->rb_left;
		else if (u->inode < uprobe->inode)
			p = &(*p)->rb_right;
		else {
			if (u->offset > uprobe->offset)
				p = &(*p)->rb_left;
			else if (u->offset < uprobe->offset)
				p = &(*p)->rb_right;
			else {
				/* get access ref */
				atomic_inc(&u->ref);
				goto unlock_return;
			}
		}
	}
	u = NULL;
	rb_link_node(&uprobe->rb_node, parent, p);
	rb_insert_color(&uprobe->rb_node, &uprobes_tree);
	/* get access + drop ref */
	atomic_set(&uprobe->ref, 2);

unlock_return:
	spin_unlock_irqrestore(&treelock, flags);
	return u;
}

static void put_uprobe(struct uprobe *uprobe)
{
	if (atomic_dec_and_test(&uprobe->ref))
		kfree(uprobe);
}

static struct uprobe *uprobes_add(struct inode *inode, loff_t offset)
{
	struct uprobe *uprobe, *cur_uprobe;

	uprobe = kzalloc(sizeof(struct uprobe), GFP_KERNEL);
	if (!uprobe)
		return NULL;

	__iget(inode);
	uprobe->inode = inode;
	uprobe->offset = offset;
	init_rwsem(&uprobe->consumer_rwsem);
	INIT_LIST_HEAD(&uprobe->pending_list);

	/* add to uprobes_tree, sorted on inode:offset */
	cur_uprobe = insert_uprobe(uprobe);

	/* a uprobe exists for this inode:offset combination*/
	if (cur_uprobe) {
		kfree(uprobe);
		uprobe = cur_uprobe;
		iput(inode);
	}
	return uprobe;
}

static void handler_chain(struct uprobe *uprobe, struct pt_regs *regs)
{
	struct uprobe_consumer *consumer;

	down_read(&uprobe->consumer_rwsem);
	consumer = uprobe->consumers;
	while (consumer) {
		if (!consumer->filter || consumer->filter(consumer, current))
			consumer->handler(consumer, regs);

		consumer = consumer->next;
	}
	up_read(&uprobe->consumer_rwsem);
}

static void add_consumer(struct uprobe *uprobe,
				struct uprobe_consumer *consumer)
{
	down_write(&uprobe->consumer_rwsem);
	consumer->next = uprobe->consumers;
	uprobe->consumers = consumer;
	up_write(&uprobe->consumer_rwsem);
}

/*
 * For uprobe @uprobe, delete the consumer @consumer.
 * Return true if the @consumer is deleted successfully
 * or return false.
 */
static bool del_consumer(struct uprobe *uprobe,
				struct uprobe_consumer *consumer)
{
	struct uprobe_consumer *con;
	bool ret = false;

	down_write(&uprobe->consumer_rwsem);
	con = uprobe->consumers;
	if (consumer == con) {
		uprobe->consumers = con->next;
		if (!con->next)
			put_uprobe(uprobe); /* drop creation ref */
		ret = true;
	} else {
		for (; con; con = con->next) {
			if (con->next == consumer) {
				con->next = consumer->next;
				ret = true;
				break;
			}
		}
	}
	up_write(&uprobe->consumer_rwsem);
	return ret;
}

static int __copy_insn(struct address_space *mapping,
		struct vm_area_struct *vma, char *insn,
		unsigned long nbytes, unsigned long offset)
{
	struct page *page;
	void *vaddr;
	unsigned long off1;
	unsigned long idx;

	idx = (unsigned long) (offset >> PAGE_CACHE_SHIFT);
	off1 = offset &= ~PAGE_MASK;
	if (vma) {
		/*
		 * We get here from uprobe_mmap() -- the case where we
		 * are trying to copy an instruction from a page that's
		 * not yet in page cache.
		 *
		 * Read page in before copy.
		 */
		struct file *filp = vma->vm_file;

		if (!filp)
			return -EINVAL;
		page_cache_sync_readahead(mapping, &filp->f_ra, filp, idx, 1);
	}
	page = grab_cache_page(mapping, idx);
	if (!page)
		return -ENOMEM;

	vaddr = kmap_atomic(page, KM_USER0);
	memcpy(insn, vaddr + off1, nbytes);
	kunmap_atomic(vaddr, KM_USER0);
	unlock_page(page);
	page_cache_release(page);
	return 0;
}

static int copy_insn(struct uprobe *uprobe, struct vm_area_struct *vma,
					unsigned long addr)
{
	struct address_space *mapping;
	int bytes;
	unsigned long nbytes;

	addr &= ~PAGE_MASK;
	nbytes = PAGE_SIZE - addr;
	mapping = uprobe->inode->i_mapping;

	/* Instruction at end of binary; copy only available bytes */
	if (uprobe->offset + MAX_UINSN_BYTES > uprobe->inode->i_size)
		bytes = uprobe->inode->i_size - uprobe->offset;
	else
		bytes = MAX_UINSN_BYTES;

	/* Instruction at the page-boundary; copy bytes in second page */
	if (nbytes < bytes) {
		if (__copy_insn(mapping, vma, uprobe->insn + nbytes,
				bytes - nbytes, uprobe->offset + nbytes))
			return -ENOMEM;
		bytes = nbytes;
	}
	return __copy_insn(mapping, vma, uprobe->insn, bytes, uprobe->offset);
}

static struct task_struct *uprobes_get_mm_owner(struct mm_struct *mm)
{
	struct task_struct *tsk;

	rcu_read_lock();
	tsk = rcu_dereference(mm->owner);
	if (tsk)
		get_task_struct(tsk);
	rcu_read_unlock();
	return tsk;
}

static int install_uprobe(struct mm_struct *mm, struct uprobe *uprobe,
		struct vm_area_struct *vma)
{
	struct task_struct *tsk = uprobes_get_mm_owner(mm);
	int ret;

	if (!tsk)	/* task is probably exiting; bail-out */
		return -ESRCH;

	if (!uprobe->copy) {
		ret = copy_insn(uprobe, vma, mm->uprobes_vaddr);
		if (ret)
			goto put_return;
		if (is_bkpt_insn(uprobe->insn)) {
			print_insert_fail(tsk, mm->uprobes_vaddr,
				"breakpoint instruction already exists");
			ret = -EEXIST;
			goto put_return;
		}
		ret = analyze_insn(tsk, uprobe);
		if (ret) {
			print_insert_fail(tsk, mm->uprobes_vaddr,
					"instruction type cannot be probed");
			goto put_return;
		}
		uprobe->copy = 1;
	}

	ret = set_bkpt(tsk, uprobe, mm->uprobes_vaddr);
	if (ret < 0)
		print_insert_fail(tsk, mm->uprobes_vaddr,
					"failed to insert bkpt instruction");
	else
		atomic_inc(&mm->uprobes_count);

put_return:
	put_task_struct(tsk);
	return ret;
}

static int remove_uprobe(struct mm_struct *mm, struct uprobe *uprobe)
{
	struct task_struct *tsk = uprobes_get_mm_owner(mm);
	int ret;

	if (!tsk)	/* task is probably exiting; bail-out */
		return -ESRCH;

	ret = set_orig_insn(tsk, uprobe, mm->uprobes_vaddr, true);
	if (!ret)
		atomic_dec(&mm->uprobes_count);
	put_task_struct(tsk);
	return ret;
}

static void delete_uprobe(struct mm_struct *mm, struct uprobe *uprobe)
{
	down_read(&mm->mmap_sem);
	remove_uprobe(mm, uprobe);
	list_del(&mm->uprobes_list);
	up_read(&mm->mmap_sem);
	mmput(mm);
}

/*
 * There could be threads that have hit the breakpoint and are entering
 * the notifier code and trying to acquire the treelock. The thread
 * calling erase_uprobe() that is removing the uprobe from the rb_tree
 * can race with these threads and might acquire the treelock compared
 * to some of the breakpoint hit threads. In such a case, the breakpoint
 * hit threads will not find the uprobe. Finding if a "trap" instruction
 * was present at the interrupting address is racy. Hence provide some
 * extra time (by way of synchronize_sched() for breakpoint hit threads
 * to acquire the treelock before the uprobe is removed from the rbtree.
 */
static void erase_uprobe(struct uprobe *uprobe)
{
	unsigned long flags;

	synchronize_sched();
	spin_lock_irqsave(&treelock, flags);
	rb_erase(&uprobe->rb_node, &uprobes_tree);
	spin_unlock_irqrestore(&treelock, flags);
	iput(uprobe->inode);
}

static DEFINE_MUTEX(uprobes_mutex);

/*
 * register_uprobe - register a probe
 * @inode: the file in which the probe has to be placed.
 * @offset: offset from the start of the file.
 * @consumer: information on howto handle the probe..
 *
 * Apart from the access refcount, register_uprobe() takes a creation
 * refcount (thro uprobes_add) if and only if this @uprobe is getting
 * inserted into the rbtree (i.e first consumer for a @inode:@offset
 * tuple).  Creation refcount stops unregister_uprobe from freeing the
 * @uprobe even before the register operation is complete. Creation
 * refcount is released when the last @consumer for the @uprobe
 * unregisters.
 *
 * Return errno if it cannot successully install probes
 * else return 0 (success)
 */
int register_uprobe(struct inode *inode, loff_t offset,
				struct uprobe_consumer *consumer)
{
	struct prio_tree_iter iter;
	struct list_head try_list, success_list;
	struct address_space *mapping;
	struct mm_struct *mm, *tmpmm;
	struct vm_area_struct *vma;
	struct uprobe *uprobe;
	int ret = -1;

	if (!inode || !consumer || consumer->next)
		return -EINVAL;

	uprobe = uprobes_add(inode, offset);
	if (!uprobe)
		return -ENOMEM;

	INIT_LIST_HEAD(&try_list);
	INIT_LIST_HEAD(&success_list);
	mapping = inode->i_mapping;

	mutex_lock(&uprobes_mutex);
	if (uprobe->consumers) {
		ret = 0;
		goto consumers_add;
	}

	spin_lock(&mapping->i_mmap_lock);
	vma_prio_tree_foreach(vma, &iter, &mapping->i_mmap, 0, 0) {
		loff_t vaddr;

		if (!atomic_inc_not_zero(&vma->vm_mm->mm_users))
			continue;

		mm = vma->vm_mm;
		if (!valid_vma(vma)) {
			mmput(mm);
			continue;
		}

		vaddr = vma->vm_start + offset;
		vaddr -= vma->vm_pgoff << PAGE_SHIFT;
		if (vaddr > ULONG_MAX) {
			/*
			 * We cannot have a virtual address that is
			 * greater than ULONG_MAX
			 */
			mmput(mm);
			continue;
		}
		mm->uprobes_vaddr = (unsigned long) vaddr;
		list_add(&mm->uprobes_list, &try_list);
	}
	spin_unlock(&mapping->i_mmap_lock);

	if (list_empty(&try_list)) {
		ret = 0;
		goto consumers_add;
	}
	list_for_each_entry_safe(mm, tmpmm, &try_list, uprobes_list) {
		down_read(&mm->mmap_sem);
		ret = install_uprobe(mm, uprobe, NULL);

		if (ret && (ret != -ESRCH || ret != -EEXIST)) {
			up_read(&mm->mmap_sem);
			break;
		}
		if (!ret)
			list_move(&mm->uprobes_list, &success_list);
		else {
			/*
			 * install_uprobe failed as there are no active
			 * threads for the mm; ignore the error.
			 */
			list_del(&mm->uprobes_list);
			mmput(mm);
		}
		up_read(&mm->mmap_sem);
	}

	if (list_empty(&try_list)) {
		/*
		 * All install_uprobes were successful;
		 * cleanup successful entries.
		 */
		ret = 0;
		list_for_each_entry_safe(mm, tmpmm, &success_list,
						uprobes_list) {
			list_del(&mm->uprobes_list);
			mmput(mm);
		}
		goto consumers_add;
	}

	/*
	 * Atleast one unsuccessful install_uprobe;
	 * remove successful probes and cleanup untried entries.
	 */
	list_for_each_entry_safe(mm, tmpmm, &success_list, uprobes_list)
		delete_uprobe(mm, uprobe);
	list_for_each_entry_safe(mm, tmpmm, &try_list, uprobes_list) {
		list_del(&mm->uprobes_list);
		mmput(mm);
	}
	erase_uprobe(uprobe);
	goto put_unlock;

consumers_add:
	add_consumer(uprobe, consumer);

put_unlock:
	mutex_unlock(&uprobes_mutex);
	put_uprobe(uprobe); /* drop access ref */
	return ret;
}

/*
 * unregister_uprobe - unregister a already registered probe.
 * @inode: the file in which the probe has to be removed.
 * @offset: offset from the start of the file.
 * @consumer: identify which probe if multiple probes are colocated.
 */
void unregister_uprobe(struct inode *inode, loff_t offset,
				struct uprobe_consumer *consumer)
{
	struct prio_tree_iter iter;
	struct list_head tmp_list;
	struct address_space *mapping;
	struct mm_struct *mm, *tmpmm;
	struct vm_area_struct *vma;
	struct uprobe *uprobe;

	if (!inode || !consumer)
		return;

	uprobe = find_uprobe(inode, offset);
	if (!uprobe) {
		printk(KERN_ERR "No uprobe found with inode:offset %p %lld\n",
				inode, offset);
		return;
	}

	if (!del_consumer(uprobe, consumer)) {
		printk(KERN_ERR "No uprobe found with consumer %p\n",
				consumer);
		return;
	}

	INIT_LIST_HEAD(&tmp_list);

	mapping = inode->i_mapping;

	mutex_lock(&uprobes_mutex);
	if (uprobe->consumers)
		goto put_unlock;

	spin_lock(&mapping->i_mmap_lock);
	vma_prio_tree_foreach(vma, &iter, &mapping->i_mmap, 0, 0) {
		if (!atomic_inc_not_zero(&vma->vm_mm->mm_users))
			continue;

		mm = vma->vm_mm;

		if (!atomic_read(&mm->uprobes_count)) {
			mmput(mm);
			continue;
		}

		if (valid_vma(vma)) {
			loff_t vaddr;

			vaddr = vma->vm_start + offset;
			vaddr -= vma->vm_pgoff << PAGE_SHIFT;
			if (vaddr > ULONG_MAX) {
				/*
				 * We cannot have a virtual address that is
				 * greater than ULONG_MAX
				 */
				mmput(mm);
				continue;
			}
			mm->uprobes_vaddr = (unsigned long) vaddr;
			list_add(&mm->uprobes_list, &tmp_list);
		} else
			mmput(mm);
	}
	spin_unlock(&mapping->i_mmap_lock);
	list_for_each_entry_safe(mm, tmpmm, &tmp_list, uprobes_list)
		delete_uprobe(mm, uprobe);

	erase_uprobe(uprobe);

put_unlock:
	mutex_unlock(&uprobes_mutex);
	put_uprobe(uprobe); /* drop access ref */
}

static void add_to_temp_list(struct vm_area_struct *vma, struct inode *inode,
		struct list_head *tmp_list)
{
	struct uprobe *uprobe;
	struct rb_node *n;
	unsigned long flags;

	n = uprobes_tree.rb_node;
	spin_lock_irqsave(&treelock, flags);
	uprobe = __find_uprobe(inode, 0, &n);
	for (; n; n = rb_next(n)) {
		uprobe = rb_entry(n, struct uprobe, rb_node);
		if (match_inode(uprobe, inode, &n)) {
			list_add(&uprobe->pending_list, tmp_list);
			continue;
		}
		break;
	}
	spin_unlock_irqrestore(&treelock, flags);
}

/*
 * Called from dup_mmap.
 * called with mm->mmap_sem and old_mm->mmap_sem acquired.
 */
void uprobe_dup_mmap(struct mm_struct *old_mm, struct mm_struct *mm)
{
	atomic_set(&old_mm->uprobes_count,
			atomic_read(&mm->uprobes_count));
}

/*
 * Called from mmap_region.
 * called with mm->mmap_sem acquired.
 *
 * Return -ve no if we fail to insert probes and we cannot
 * bail-out.
 * Return 0 otherwise. i.e :
 *	- successful insertion of probes
 *	- no possible probes to be inserted.
 *	- insertion of probes failed but we can bail-out.
 */
int uprobe_mmap(struct vm_area_struct *vma)
{
	struct list_head tmp_list;
	struct uprobe *uprobe, *u;
	struct mm_struct *mm;
	struct inode *inode;
	unsigned long start;
	unsigned long pgoff;
	int ret = 0;

	if (!valid_vma(vma))
		return ret;	/* Bail-out */

	INIT_LIST_HEAD(&tmp_list);

	mm = vma->vm_mm;
	inode = vma->vm_file->f_mapping->host;
	start = vma->vm_start;
	pgoff = vma->vm_pgoff;
	__iget(inode);

	up_write(&mm->mmap_sem);
	mutex_lock(&uprobes_mutex);
	down_read(&mm->mmap_sem);

	vma = find_vma(mm, start);
	/* Not the same vma */
	if (!vma || vma->vm_start != start ||
			vma->vm_pgoff != pgoff || !valid_vma(vma) ||
			inode->i_mapping != vma->vm_file->f_mapping)
		goto mmap_out;

	add_to_temp_list(vma, inode, &tmp_list);
	list_for_each_entry_safe(uprobe, u, &tmp_list, pending_list) {
		loff_t vaddr;

		list_del(&uprobe->pending_list);
		if (ret)
			continue;

		vaddr = vma->vm_start + uprobe->offset;
		vaddr -= vma->vm_pgoff << PAGE_SHIFT;
		if (vaddr > ULONG_MAX)
			/*
			 * We cannot have a virtual address that is
			 * greater than ULONG_MAX
			 */
			continue;
		mm->uprobes_vaddr = (unsigned long)vaddr;
		ret = install_uprobe(mm, uprobe, vma);
		if (ret && (ret == -ESRCH || ret == -EEXIST))
			ret = 0;
	}

mmap_out:
	mutex_unlock(&uprobes_mutex);
	iput(inode);
	up_read(&mm->mmap_sem);
	down_write(&mm->mmap_sem);
	return ret;
}

/* Slot allocation for XOL */

static int xol_add_vma(struct uprobes_xol_area *area)
{
	struct vm_area_struct *vma;
	struct mm_struct *mm;
	struct file *file;
	unsigned long addr;
	int ret = -ENOMEM;

	mm = get_task_mm(current);
	if (!mm)
		return -ESRCH;

	down_write(&mm->mmap_sem);
	if (mm->uprobes_xol_area) {
		ret = -EALREADY;
		goto fail;
	}

	/*
	 * Find the end of the top mapping and skip a page.
	 * If there is no space for PAGE_SIZE above
	 * that, mmap will ignore our address hint.
	 *
	 * We allocate a "fake" unlinked shmem file because
	 * anonymous memory might not be granted execute
	 * permission when the selinux security hooks have
	 * their way.
	 */
	vma = rb_entry(rb_last(&mm->mm_rb), struct vm_area_struct, vm_rb);
	addr = vma->vm_end + PAGE_SIZE;
	file = shmem_file_setup("uprobes/xol", PAGE_SIZE, VM_NORESERVE);
	if (!file) {
		printk(KERN_ERR "uprobes_xol failed to setup shmem_file "
			"while allocating vma for pid/tgid %d/%d for "
			"single-stepping out of line.\n",
			current->pid, current->tgid);
		goto fail;
	}
	addr = do_mmap_pgoff(file, addr, PAGE_SIZE, PROT_EXEC, MAP_PRIVATE, 0);
	fput(file);

	if (addr & ~PAGE_MASK) {
		printk(KERN_ERR "uprobes_xol failed to allocate a vma for "
				"pid/tgid %d/%d for single-stepping out of "
				"line.\n", current->pid, current->tgid);
		goto fail;
	}
	vma = find_vma(mm, addr);

	/* Don't expand vma on mremap(). */
	vma->vm_flags |= VM_DONTEXPAND | VM_DONTCOPY;
	area->vaddr = vma->vm_start;
	if (get_user_pages(current, mm, area->vaddr, 1, 1, 1, &area->page,
				&vma) > 0)
		ret = 0;

fail:
	up_write(&mm->mmap_sem);
	mmput(mm);
	return ret;
}

/*
 * xol_alloc_area - Allocate process's uprobes_xol_area.
 * This area will be used for storing instructions for execution out of
 * line.
 *
 * Returns the allocated area or NULL.
 */
static struct uprobes_xol_area *xol_alloc_area(void)
{
	struct uprobes_xol_area *area = NULL;

	area = kzalloc(sizeof(*area), GFP_KERNEL);
	if (unlikely(!area))
		return NULL;

	area->bitmap = kzalloc(BITS_TO_LONGS(UINSNS_PER_PAGE) * sizeof(long),
								GFP_KERNEL);

	if (!area->bitmap)
		goto fail;

	spin_lock_init(&area->slot_lock);
	if (!xol_add_vma(area) && !current->mm->uprobes_xol_area) {
		task_lock(current);
		if (!current->mm->uprobes_xol_area) {
			current->mm->uprobes_xol_area = area;
			task_unlock(current);
			return area;
		}
		task_unlock(current);
	}

fail:
	kfree(area->bitmap);
	kfree(area);
	return current->mm->uprobes_xol_area;
}

/*
 * uprobes_free_xol_area - Free the area allocated for slots.
 */
void uprobes_free_xol_area(struct mm_struct *mm)
{
	struct uprobes_xol_area *area = mm->uprobes_xol_area;

	if (!area)
		return;

	put_page(area->page);
	kfree(area->bitmap);
	kfree(area);
}

/*
 * Find a slot
 *  - searching in existing vmas for a free slot.
 *  - If no free slot in existing vmas, return 0;
 *
 * Called when holding uprobes_xol_area->slot_lock
 */
static unsigned long xol_take_insn_slot(struct uprobes_xol_area *area)
{
	unsigned long slot_addr;
	int slot_nr;

	slot_nr = find_first_zero_bit(area->bitmap, UINSNS_PER_PAGE);
	if (slot_nr < UINSNS_PER_PAGE) {
		__set_bit(slot_nr, area->bitmap);
		slot_addr = area->vaddr +
				(slot_nr * UPROBES_XOL_SLOT_BYTES);
		return slot_addr;
	}

	return 0;
}

/*
 * xol_get_insn_slot - If was not allocated a slot, then
 * allocate a slot.
 * Returns the allocated slot address or 0.
 */
static unsigned long xol_get_insn_slot(struct uprobe *uprobe,
					unsigned long slot_addr)
{
	struct uprobes_xol_area *area = current->mm->uprobes_xol_area;
	unsigned long flags, xol_vaddr = current->utask->xol_vaddr;
	void *vaddr;

	if (!current->utask->xol_vaddr || !area) {
		if (!area)
			area = xol_alloc_area();

		if (!area)
			return 0;

		spin_lock_irqsave(&area->slot_lock, flags);
		xol_vaddr = xol_take_insn_slot(area);
		spin_unlock_irqrestore(&area->slot_lock, flags);
		current->utask->xol_vaddr = xol_vaddr;
	}

	/*
	 * Initialize the slot if xol_vaddr points to valid
	 * instruction slot.
	 */
	if (unlikely(!xol_vaddr))
		return 0;

	current->utask->vaddr = slot_addr;
	vaddr = kmap_atomic(area->page, KM_USER0);
	xol_vaddr &= ~PAGE_MASK;
	memcpy(vaddr + xol_vaddr, uprobe->insn, MAX_UINSN_BYTES);
	kunmap_atomic(vaddr, KM_USER0);
	return current->utask->xol_vaddr;
}

/*
 * xol_free_insn_slot - If slot was earlier allocated by
 * @xol_get_insn_slot(), make the slot available for
 * subsequent requests.
 */
static void xol_free_insn_slot(struct task_struct *tsk, unsigned long slot_addr)
{
	struct uprobes_xol_area *area;
	unsigned long vma_end;

	if (!tsk->mm || !tsk->mm->uprobes_xol_area)
		return;

	area = tsk->mm->uprobes_xol_area;

	if (unlikely(!slot_addr || IS_ERR_VALUE(slot_addr)))
		return;

	vma_end = area->vaddr + PAGE_SIZE;
	if (area->vaddr <= slot_addr && slot_addr < vma_end) {
		int slot_nr;
		unsigned long offset = slot_addr - area->vaddr;
		unsigned long flags;

		BUG_ON(offset % UPROBES_XOL_SLOT_BYTES);

		slot_nr = offset / UPROBES_XOL_SLOT_BYTES;
		BUG_ON(slot_nr >= UINSNS_PER_PAGE);

		spin_lock_irqsave(&area->slot_lock, flags);
		__clear_bit(slot_nr, area->bitmap);
		spin_unlock_irqrestore(&area->slot_lock, flags);
		return;
	}
	printk(KERN_ERR "%s: no XOL vma for slot address %#lx\n",
						__func__, slot_addr);
}

/**
 * uprobes_get_bkpt_addr - compute address of bkpt given post-bkpt regs
 * @regs: Reflects the saved state of the task after it has hit a breakpoint
 * instruction.
 * Return the address of the breakpoint instruction.
 */
unsigned long uprobes_get_bkpt_addr(struct pt_regs *regs)
{
	return instruction_pointer(regs) - UPROBES_BKPT_INSN_SIZE;
}

/*
 * Called with no locks held.
 * Called in context of a exiting or a exec-ing thread.
 */
void uprobe_free_utask(struct task_struct *tsk)
{
	struct uprobe_task *utask = tsk->utask;
	unsigned long xol_vaddr;

	if (!utask)
		return;

	xol_vaddr = utask->xol_vaddr;
	if (utask->active_uprobe)
		put_uprobe(utask->active_uprobe);

	kfree(utask);
	tsk->utask = NULL;
	xol_free_insn_slot(tsk, xol_vaddr);
}

/*
 * Allocate a uprobe_task object for the task.
 * Called when the thread hits a breakpoint for the first time.
 *
 * Returns:
 * - pointer to new uprobe_task on success
 * - negative errno otherwise
 */
static struct uprobe_task *add_utask(void)
{
	struct uprobe_task *utask;

	utask = kzalloc(sizeof *utask, GFP_KERNEL);
	if (unlikely(utask == NULL))
		return ERR_PTR(-ENOMEM);

	utask->active_uprobe = NULL;
	current->utask = utask;
	return utask;
}

/* Prepare to single-step probed instruction out of line. */
static int pre_ssout(struct uprobe *uprobe, struct pt_regs *regs,
				unsigned long vaddr)
{
	xol_get_insn_slot(uprobe, vaddr);
	BUG_ON(!current->utask->xol_vaddr);
	if (!pre_xol(uprobe, regs)) {
		set_ip(regs, current->utask->xol_vaddr);
		return 0;
	}
	return -EFAULT;
}

/*
 * Verify from Instruction Pointer if singlestep has indeed occurred.
 * If Singlestep has occurred, then do post singlestep fix-ups.
 */
static bool sstep_complete(struct uprobe *uprobe, struct pt_regs *regs)
{
	unsigned long vaddr = instruction_pointer(regs);

	/*
	 * If we have executed out of line, Instruction pointer
	 * cannot be same as virtual address of XOL slot.
	 */
	if (vaddr == current->utask->xol_vaddr)
		return false;
	post_xol(uprobe, regs);
	return true;
}

/*
 * uprobe_notify_resume gets called in task context just before returning
 * to userspace.
 *
 *  If its the first time the probepoint is hit, slot gets allocated here.
 *  If its the first time the thread hit a breakpoint, utask gets
 *  allocated here.
 */
void uprobe_notify_resume(struct pt_regs *regs)
{
	struct vm_area_struct *vma;
	struct uprobe_task *utask;
	struct mm_struct *mm;
	struct uprobe *u = NULL;
	unsigned long probept;

	utask = current->utask;
	mm = current->mm;
	if (unlikely(!utask)) {
		utask = add_utask();

		/* Failed to allocate utask for the current task. */
		BUG_ON(!utask);
		utask->state = UTASK_BP_HIT;
	}
	if (utask->state == UTASK_BP_HIT) {
		probept = uprobes_get_bkpt_addr(regs);
		down_read(&mm->mmap_sem);
		for (vma = mm->mmap; vma; vma = vma->vm_next) {
			if (!valid_vma(vma))
				continue;
			if (probept < vma->vm_start || probept > vma->vm_end)
				continue;
			u = find_uprobe(vma->vm_file->f_mapping->host,
					probept - vma->vm_start);
			break;
		}
		up_read(&mm->mmap_sem);
		/*TODO Return SIGTRAP signal */
		if (!u) {
			set_ip(regs, probept);
			utask->state = UTASK_RUNNING;
			return;
		}
		/* TODO Start queueing signals. */
		utask->active_uprobe = u;
		handler_chain(u, regs);
		utask->state = UTASK_SSTEP;
		if (!pre_ssout(u, regs, probept))
			arch_uprobe_enable_sstep(regs);
	} else if (utask->state == UTASK_SSTEP) {
		u = utask->active_uprobe;
		if (sstep_complete(u, regs)) {
			put_uprobe(u);
			utask->active_uprobe = NULL;
			utask->state = UTASK_RUNNING;
		/* TODO Stop queueing signals. */
			arch_uprobe_disable_sstep(regs);
		}
	}
}

/*
 * uprobe_bkpt_notifier gets called from interrupt context
 * it gets a reference to the ppt and sets TIF_UPROBE flag,
 */
int uprobe_bkpt_notifier(struct pt_regs *regs)
{
	struct uprobe_task *utask;

	if (!current->mm || !atomic_read(&current->mm->uprobes_count))
		/* task is currently not uprobed */
		return 0;

	utask = current->utask;
	if (utask)
		utask->state = UTASK_BP_HIT;
	set_thread_flag(TIF_UPROBE);
	return 1;
}

/*
 * uprobe_post_notifier gets called in interrupt context.
 * It completes the single step operation.
 */
int uprobe_post_notifier(struct pt_regs *regs)
{
	struct uprobe *uprobe;
	struct uprobe_task *utask;

	if (!current->mm || !current->utask || !current->utask->active_uprobe)
		/* task is currently not uprobed */
		return 0;

	utask = current->utask;
	uprobe = utask->active_uprobe;
	if (!uprobe)
		return 0;

	if (uprobes_resume_can_sleep(uprobe)) {
		set_thread_flag(TIF_UPROBE);
		return 1;
	}
	if (sstep_complete(uprobe, regs)) {
		put_uprobe(uprobe);
		utask->active_uprobe = NULL;
		utask->state = UTASK_RUNNING;
		/* TODO Stop queueing signals. */
		arch_uprobe_disable_sstep(regs);
		return 1;
	}
	return 0;
}

struct notifier_block uprobes_exception_nb = {
	.notifier_call = uprobes_exception_notify,
	.priority = 0x7ffffff0,
};

static int __init init_uprobes(void)
{
	return register_die_notifier(&uprobes_exception_nb);
}

static void __exit exit_uprobes(void)
{
}

module_init(init_uprobes);
module_exit(exit_uprobes);
