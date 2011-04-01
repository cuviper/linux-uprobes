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

static bool valid_vma(struct vm_area_struct *vma)
{
	if (!vma->vm_file)
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

/*
 * Called with no locks held.
 * Called in context of a exiting or a exec-ing thread.
 */
void uprobe_free_utask(struct task_struct *tsk)
{
	struct uprobe_task *utask = tsk->utask;

	if (!utask)
		return;

	if (utask->active_uprobe)
		put_uprobe(utask->active_uprobe);
	kfree(utask);
	tsk->utask = NULL;
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
