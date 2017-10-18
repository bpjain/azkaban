/**
 * ept.c - Support for Intel's Extended Page Tables
 *
 * Authors:
 *   Bhushan Jain <bhushan@cs.unc.edu>
 *   Tao Zhang <zhtao@cs.unc.edu>
 *
 * This is an extenstion of dune's implementation for Intel's Extended Page Tables
 * Original Authors:
 *   Adam Belay <abelay@stanford.edu>
 *
 * Some of the low-level EPT functions are based on KVM.
 * Original Authors:
 *   Avi Kivity   <avi@qumranet.com>
 *   Yaniv Kamay  <yaniv@qumranet.com>
 */

#include <linux/version.h>
#include <linux/mm.h>
#include <linux/hugetlb.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/rmap.h>
#include <linux/azkaban.h>
#include <asm/pgtable.h>

#include "dune.h"
#include "vmx.h"

#define DEBUG 1 
#define EPT_LEVELS	4	/* 0 through 3 */
#define HUGE_PAGE_SIZE	2097152

//#define __pte(x) ((pte_t) { (x) } )
struct mm_struct *azk_init_mm = (struct mm_struct *) INIT_MM;
//struct mm_struct* azk_init_mm = &init_mm;


int ept_set_epte(struct vmx_vcpu *vcpu, int make_write, int make_read, int make_exec,
                unsigned long gpa, unsigned long gva);

static inline bool cpu_has_vmx_ept_execute_only(void)
{
	return vmx_capability.ept & VMX_EPT_EXECUTE_ONLY_BIT;
}

static inline bool cpu_has_vmx_eptp_uncacheable(void)
{
	return vmx_capability.ept & VMX_EPTP_UC_BIT;
}

static inline bool cpu_has_vmx_eptp_writeback(void)
{
	return vmx_capability.ept & VMX_EPTP_WB_BIT;
}

static inline bool cpu_has_vmx_ept_2m_page(void)
{
	return vmx_capability.ept & VMX_EPT_2MB_PAGE_BIT;
}

static inline bool cpu_has_vmx_ept_1g_page(void)
{
	return vmx_capability.ept & VMX_EPT_1GB_PAGE_BIT;
}

static inline bool cpu_has_vmx_ept_4levels(void)
{
	return vmx_capability.ept & VMX_EPT_PAGE_WALK_4_BIT;
}

#define VMX_EPT_FAULT_READ	0x01
#define VMX_EPT_FAULT_WRITE	0x02
#define VMX_EPT_FAULT_INS	0x04

typedef unsigned long epte_t;
static int count = 0;
#define __EPTE_READ	0x01
#define __EPTE_WRITE	0x02
#define __EPTE_EXEC	0x04
#define __EPTE_IPAT	0x40
#define __EPTE_SZ	0x80
#define __EPTE_A	0x100
#define __EPTE_D	0x200
#define __EPTE_TYPE(n)	(((n) & 0x7) << 3)

enum {
	EPTE_TYPE_UC = 0, /* uncachable */
	EPTE_TYPE_WC = 1, /* write combining */
	EPTE_TYPE_WT = 4, /* write through */
	EPTE_TYPE_WP = 5, /* write protected */
	EPTE_TYPE_WB = 6, /* write back */
};

#define __EPTE_NONE	0
#define __EPTE_FULL	(__EPTE_READ | __EPTE_WRITE | __EPTE_EXEC)

#define EPTE_ADDR	(~(PAGE_SIZE - 1))
#define EPTE_FLAGS	(PAGE_SIZE - 1)

static inline uintptr_t epte_addr(epte_t epte)
{
	return (epte & EPTE_ADDR);
}

static inline uintptr_t epte_page_vaddr(epte_t epte)
{
	return (uintptr_t) __va(epte_addr(epte));
}

static inline epte_t epte_flags(epte_t epte)
{
	return (epte & EPTE_FLAGS);
}

static inline int epte_present(epte_t epte)
{
	return (epte & __EPTE_FULL) > 0;
}

static inline int epte_big(epte_t epte)
{
	return (epte & __EPTE_SZ) > 0;
}

static pte_t hva_to_gpa(struct vmx_vcpu *vcpu,
		struct mm_struct *mm,
		unsigned long addr)
{
	// Bhushan: We need to walk the page table to translate the hva to hpa. We have identity mapping from hpa to gpa.
	// This implementation is wrong.
	
	/* Trying */
	pgd_t *pgd;
        pud_t *pud;
        pmd_t *pmd;
        pte_t *ptep, pte;	
	struct page *page;
	unsigned long address;

	page = NULL;
     	
	pgd = pgd_offset(mm, addr);
	// pgd_none() returns 1 if the entry does not exist, helps to check if a valid page table is being looked on
     	if (pgd_none(*pgd) || pgd_bad(*pgd))
                 goto out;

        pud = pud_offset(pgd, addr);
        if (pud_none(*pud) || pud_bad(*pud))
        	goto out;

        pmd = pmd_offset(pud, addr);
        if (pmd_none(*pmd) || pmd_bad(*pmd))
        	goto out;

        ptep = pte_offset_map(pmd, addr);
	if (!ptep)
		goto out;

        pte = *ptep;
        page = pte_page(pte);
	address = (page_to_pfn(page)) << PAGE_SHIFT;
	return pte;
/*
	if (pte_present(pte)) {
        	
		page = vm_normal_page(vma, address, pte);
	        if (unlikely(!page)) {
        	        if ((flags & FOLL_DUMP) ||
                	    !is_zero_pfn(pte_pfn(pte)))
                        	goto bad_page;
                page = pte_page(pte);
        }
*/

out:	return __pte(0);

#if 0
	page = NULL;
        pgd = pgd_offset(mm, address);
        if (pgd_none(*pgd) || unlikely(pgd_bad(*pgd)))
                goto no_page_table;

        pud = pud_offset(pgd, address);
        if (pud_none(*pud))
                goto no_page_table;
       
	/*
	 if (pud_huge(*pud) && vma->vm_flags & VM_HUGETLB) {
                if (flags & FOLL_GET)
                        goto out;
                page = follow_huge_pud(mm, address, pud, flags & FOLL_WRITE);
                goto out;
        }
        if (unlikely(pud_bad(*pud)))
                goto no_page_table;
	*/
        pmd = pmd_offset(pud, address);
        if (pmd_none(*pmd))
                goto no_page_table;
        
	if (pmd_huge(*pmd) && vma->vm_flags & VM_HUGETLB) {
                page = follow_huge_pmd(mm, address, pmd, flags & FOLL_WRITE);
                if (flags & FOLL_GET) {
                        /*
                         * Refcount on tail pages are not well-defined and
                         * shouldn't be taken. The caller should handle a NULL
                         * return when trying to follow tail pages.
                         */
                        if (PageHead(page))
                                get_page(page);
                        else {
                                page = NULL;
                                goto out;
                        }
                }
                goto out;
        }
        if ((flags & FOLL_NUMA) && pmd_numa(*pmd))
                goto no_page_table;
        if (pmd_trans_huge(*pmd)) {
                if (flags & FOLL_SPLIT) {
                        split_huge_page_pmd(vma, address, pmd);
                        goto split_fallthrough;
                }
                ptl = pmd_lock(mm, pmd);
                if (likely(pmd_trans_huge(*pmd))) {
                        if (unlikely(pmd_trans_splitting(*pmd))) {
                                spin_unlock(ptl);
                                wait_split_huge_page(vma->anon_vma, pmd);
                        } else {
                                page = follow_trans_huge_pmd(vma, address,
                                                             pmd, flags);
                                spin_unlock(ptl);
                                *page_mask = HPAGE_PMD_NR - 1;
                                goto out;
                      }
                }
                goto out;
        }
        if ((flags & FOLL_NUMA) && pmd_numa(*pmd))
                goto no_page_table;

split_fallthrough:
        if (unlikely(pmd_bad(*pmd)))
                goto no_page_table;
#endif

#if 0
	uintptr_t mmap_start;

	if (!mm) {
		printk(KERN_ERR "ept: proc has no MM %d\n", current->pid);
		return GPA_ADDR_INVAL;
	}

	BUG_ON(!mm);

	mmap_start = LG_ALIGN(mm->mmap_base) - GPA_SIZE;

	if ((addr & ~GPA_MASK) == 0)
		return (addr & GPA_MASK) | GPA_ADDR_PROC;
	else if (addr < LG_ALIGN(mm->mmap_base) && addr >= mmap_start)
		return (addr - mmap_start) | GPA_ADDR_MAP;
	else if ((addr & ~GPA_MASK) == (mm->start_stack & ~GPA_MASK))
		return (addr & GPA_MASK) | GPA_ADDR_STACK;
	else
		return GPA_ADDR_INVAL;
	return addr;
#endif


}


#define ADDR_TO_IDX(la, n) \
	((((unsigned long) (la)) >> (12 + 9 * (n))) & ((1 << 9) - 1))

int
ept_lookup_gpa(struct vmx_vcpu *vcpu, void *gpa, int level,
		int create, epte_t **epte_out)
{
	int i;
	epte_t paddr;
	epte_t *dir = (epte_t *) __va(vcpu->ept_root);
	*epte_out = 0;

	for (i = EPT_LEVELS - 1; i > level; i--) {
		int idx = ADDR_TO_IDX(gpa, i);

		if (!epte_present(dir[idx])) {
			void *page;

			if (!create)
				return -ENOENT;

			page = (void *) __get_free_page(GFP_AZK);
			if (!page)
				return -ENOMEM;

			memset(page, 0, PAGE_SIZE);

			paddr = epte_addr(virt_to_phys(page));
			if(paddr & 0xffff800000000000)
				dir[idx] = epte_addr(virt_to_phys(page)) |
					__EPTE_READ | __EPTE_EXEC | __EPTE_TYPE(EPTE_TYPE_WB) | __EPTE_IPAT;
			else
				dir[idx] = epte_addr(virt_to_phys(page)) |
					__EPTE_FULL | __EPTE_TYPE(EPTE_TYPE_WB) | __EPTE_IPAT;
		}

		if (epte_big(dir[idx])) {
			if (i != 1)
				return -EINVAL;
			level = i;
			break;
		}

		dir = (epte_t *) epte_page_vaddr(dir[idx]);
	}

	*epte_out = &dir[ADDR_TO_IDX(gpa, level)];
	return 0;
}

	static int
ept_lookup(struct vmx_vcpu *vcpu, struct mm_struct *mm,
		void *hva, int level, int create, epte_t **epte_out)
{
	void *gpa = (void *) pte_val(hva_to_gpa(vcpu, mm, (unsigned long) hva));

	if (gpa == (void *) GPA_ADDR_INVAL) {
		printk(KERN_ERR "ept: hva %p is out of range\n", hva);
		printk(KERN_ERR "ept: mem_base %lx, stack_start %lx\n",
				mm->mmap_base, mm->start_stack);
		return -EINVAL;
	}

	return ept_lookup_gpa(vcpu, gpa, level, create, epte_out);
}

static void free_ept_page(epte_t epte)
{
	struct page *page = pfn_to_page(epte_addr(epte) >> PAGE_SHIFT);

	if (epte & __EPTE_WRITE)
		set_page_dirty_lock(page);
	put_page(page);
}

static void vmx_free_ept(unsigned long ept_root)
{
	epte_t *pgd = (epte_t *) __va(ept_root);
	int i, j, k, l;

	for (i = 0; i < PTRS_PER_PGD; i++) {
		epte_t *pud = (epte_t *) epte_page_vaddr(pgd[i]);
		if (!epte_present(pgd[i]))
			continue;

		for (j = 0; j < PTRS_PER_PUD; j++) {
			epte_t *pmd = (epte_t *) epte_page_vaddr(pud[j]);
			if (!epte_present(pud[j]))
				continue;
			if (epte_flags(pud[j]) & __EPTE_SZ)
				continue;

			for (k = 0; k < PTRS_PER_PMD; k++) {
				epte_t *pte = (epte_t *) epte_page_vaddr(pmd[k]);
				if (!epte_present(pmd[k]))
					continue;
				if (epte_flags(pmd[k]) & __EPTE_SZ) {
					free_ept_page(pmd[k]);
					continue;
				}

				for (l = 0; l < PTRS_PER_PTE; l++) {
					if (!epte_present(pte[l]))
						continue;

					//free_ept_page(pte[l]);
				}

				free_page((unsigned long) pte);
			}

			free_page((unsigned long) pmd);
		}

		free_page((unsigned long) pud);
	}

	free_page((unsigned long) pgd);
}

static int ept_clear_epte(epte_t *epte)
{
	if (*epte == __EPTE_NONE)
		return 0;

	free_ept_page(*epte);
	*epte = __EPTE_NONE;

	return 1;
}

/*
   static int ept_clear_l1_epte(epte_t *epte)
   {
   int i;
   epte_t *pte = (epte_t *) epte_page_vaddr(*epte);

   if (*epte == __EPTE_NONE)
   return 0;

   for (i = 0; i < PTRS_PER_PTE; i++) {
   if (!epte_present(pte[i]))
   continue;

   free_ept_page(pte[i]);
   }

   free_page((uintptr_t) pte);
 *epte = __EPTE_NONE;

 return 1;
 }
 */

int vmx_do_ept_fault(struct vmx_vcpu *vcpu, unsigned long gpa,
		unsigned long gva, int fault_flags)
{
	epte_t *epte;
	int ret;
	int make_write = (fault_flags & VMX_EPT_FAULT_WRITE) ? 1 : 0;
	int make_read = (fault_flags & VMX_EPT_FAULT_READ) ? 1 : 0;
	int make_exec = (fault_flags & VMX_EPT_FAULT_INS) ? 1 : 0;

	printk(KERN_ERR "ept: GPA: 0x%lx, GVA: 0x%lx, flags: %x %pS\n",
			gpa, gva, fault_flags, gva);


/*	if(make_write && -ENOENT != ept_lookup_gpa(vcpu, (void *) gpa, 0, 0, &epte))
	{
		printk(KERN_ERR "EPT: vmx_do_ept_fault: The fault is write protection. gpa is %lx. gva is %lx. flags is %x. Expected virtual is %lx. Fount EPT entry: %lx\n", gpa, gva, fault_flags, phys_to_virt(gpa), *epte);
		printk(KERN_ERR "EPT:vmx_do_ept_fault: Wrong permissions for <%p> %pS \n", phys_to_virt(gpa), phys_to_virt(gpa));
		printk(KERN_ERR "EPT:vmx_do_ept_fault: The reverse physical addess is %p", pte_val(hva_to_gpa(vcpu, current->active_mm, phys_to_virt(gpa))));
	}
*/
	ret = ept_set_epte(vcpu, make_write, make_read, make_exec, gpa, gva);

	return ret;
}

/**
 * ept_invalidate_page - removes a page from the EPT
 * @vcpu: the vcpu
 * @mm: the process's mm_struct
 * @addr: the address of the page
 * 
 * Returns 1 if the page was removed, 0 otherwise
 */
static int ept_invalidate_page(struct vmx_vcpu *vcpu,
		struct mm_struct *mm,
		unsigned long addr)
{
	int ret;
	epte_t *epte;
	void *gpa = (void *) pte_val(hva_to_gpa(vcpu, mm, (unsigned long) addr));

	if (gpa == (void *) GPA_ADDR_INVAL) {
		printk(KERN_ERR "ept: hva %lx is out of range\n", addr);
		return 0;
	}

	spin_lock(&vcpu->ept_lock);
	ret = ept_lookup_gpa(vcpu, (void *) gpa, 0, 0, &epte);
	if (ret) {
		spin_unlock(&vcpu->ept_lock);
		return 0;
	}

	ret = ept_clear_epte(epte);
	spin_unlock(&vcpu->ept_lock);

	if (ret)
		vmx_ept_sync_individual_addr(vcpu, (gpa_t) gpa);

	return ret;
}

/**
 * ept_check_page_mapped - determines if a page is mapped in the ept
 * @vcpu: the vcpu
 * @mm: the process's mm_struct
 * @addr: the address of the page
 * 
 * Returns 1 if the page is mapped, 0 otherwise
 */
static int ept_check_page_mapped(struct vmx_vcpu *vcpu,
		struct mm_struct *mm,
		unsigned long addr)
{
	int ret;
	epte_t *epte;
	void *gpa = (void *) pte_val(hva_to_gpa(vcpu, mm, (unsigned long) addr));

	if (gpa == (void *) GPA_ADDR_INVAL) {
		printk(KERN_ERR "ept: hva %lx is out of range\n", addr);
		return 0;
	}

	spin_lock(&vcpu->ept_lock);
	ret = ept_lookup_gpa(vcpu, (void *) gpa, 0, 0, &epte);
	spin_unlock(&vcpu->ept_lock);

	return !ret;
}

/**
 * ept_check_page_accessed - determines if a page was accessed using AD bits
 * @vcpu: the vcpu
 * @mm: the process's mm_struct
 * @addr: the address of the page
 * @flush: if true, clear the A bit
 * 
 * Returns 1 if the page was accessed, 0 otherwise
 */
static int ept_check_page_accessed(struct vmx_vcpu *vcpu,
		struct mm_struct *mm,
		unsigned long addr,
		bool flush)
{
	int ret, accessed;
	epte_t *epte;
	void *gpa = (void *) pte_val(hva_to_gpa(vcpu, mm, (unsigned long) addr));

	if (gpa == (void *) GPA_ADDR_INVAL) {
		printk(KERN_ERR "ept: hva %lx is out of range\n", addr);
		return 0;
	}

	spin_lock(&vcpu->ept_lock);
	ret = ept_lookup_gpa(vcpu, (void *) gpa, 0, 0, &epte);
	if (ret) {
		spin_unlock(&vcpu->ept_lock);
		return 0;
	}

	accessed = (*epte & __EPTE_A);
	if (flush & accessed)
		*epte = (*epte & ~__EPTE_A);
	spin_unlock(&vcpu->ept_lock);

	if (flush & accessed)
		vmx_ept_sync_individual_addr(vcpu, (gpa_t) gpa);

	return accessed;
}

static inline struct vmx_vcpu *mmu_notifier_to_vmx(struct mmu_notifier *mn)
{
	return container_of(mn, struct vmx_vcpu, mmu_notifier);
}

static void ept_mmu_notifier_invalidate_page(struct mmu_notifier *mn,
		struct mm_struct *mm,
		unsigned long address)
{
	struct vmx_vcpu *vcpu = mmu_notifier_to_vmx(mn);

	pr_debug("ept: invalidate_page addr %lx\n", address);

	ept_invalidate_page(vcpu, mm, address);
}

static void ept_mmu_notifier_invalidate_range_start(struct mmu_notifier *mn,
		struct mm_struct *mm,
		unsigned long start,
		unsigned long end)
{
	/* FIXME: disable ept invalidate for now, need to implement correctly in the future */
	if (in_azkaban())
		return;
	struct vmx_vcpu *vcpu = mmu_notifier_to_vmx(mn);
	int ret;
	epte_t *epte;
	unsigned long pos = start;
	bool sync_needed = false;

	pr_debug("ept: invalidate_range_start start %lx end %lx\n", start, end);

	spin_lock(&vcpu->ept_lock);
	while (pos < end) {
		ret = ept_lookup(vcpu, mm, (void *) pos, 0, 0, &epte);
		if (!ret) {
			pos += epte_big(*epte) ? HUGE_PAGE_SIZE : PAGE_SIZE;
			ept_clear_epte(epte);
			sync_needed = true;
		} else
			pos += PAGE_SIZE;
	}
	spin_unlock(&vcpu->ept_lock);

	if (sync_needed)
		vmx_ept_sync_vcpu(vcpu);
}

static void ept_mmu_notifier_invalidate_range_end(struct mmu_notifier *mn,
		struct mm_struct *mm,
		unsigned long start,
		unsigned long end)
{
}

static void ept_mmu_notifier_change_pte(struct mmu_notifier *mn,
		struct mm_struct *mm,
		unsigned long address,
		pte_t pte)
{
	struct vmx_vcpu *vcpu = mmu_notifier_to_vmx(mn);

	pr_debug("ept: change_pte addr %lx flags %lx\n", address, pte_flags(pte));

	/*
	 * NOTE: Recent linux kernels (seen on 3.7 at least) hold a lock
	 * while calling this notifier, making it impossible to call
	 * get_user_pages_fast(). As a result, we just invalidate the
	 * page so that the mapping can be recreated later during a fault.
	 */
	ept_invalidate_page(vcpu, mm, address);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 18, 0)
static int ept_mmu_notifier_clear_flush_young(struct mmu_notifier *mn,
		struct mm_struct *mm,
		unsigned long start, unsigned long end)
{
	struct vmx_vcpu *vcpu = mmu_notifier_to_vmx(mn);
	unsigned long address;
	int err;

	for (address = start ; address < end ; address += PAGE_SIZE) {
		pr_debug("ept: clear_flush_young addr %lx\n", address);

		if (!vcpu->ept_ad_enabled)
			err = ept_invalidate_page(vcpu, mm, address);
		else
			err = ept_check_page_accessed(vcpu, mm, address, true);

		if (err < 0)
			return err;
	}

	return 0;
}
#else
static int ept_mmu_notifier_clear_flush_young(struct mmu_notifier *mn,
		struct mm_struct *mm,
		unsigned long address)
{
	struct vmx_vcpu *vcpu = mmu_notifier_to_vmx(mn);

	pr_debug("ept: clear_flush_young addr %lx\n", address);

	if (!vcpu->ept_ad_enabled)
		return ept_invalidate_page(vcpu, mm, address);
	else
		return ept_check_page_accessed(vcpu, mm, address, true);
}
#endif

static int ept_mmu_notifier_test_young(struct mmu_notifier *mn,
		struct mm_struct *mm,
		unsigned long address)
{
	struct vmx_vcpu *vcpu = mmu_notifier_to_vmx(mn);

	pr_debug("ept: test_young addr %lx\n", address);

	if (!vcpu->ept_ad_enabled)
		return ept_check_page_mapped(vcpu, mm, address);
	else
		return ept_check_page_accessed(vcpu, mm, address, false);
}

static void ept_mmu_notifier_release(struct mmu_notifier *mn,
		struct mm_struct *mm)
{
}

static const struct mmu_notifier_ops ept_mmu_notifier_ops = {
	.invalidate_page	= ept_mmu_notifier_invalidate_page,
	.invalidate_range_start	= ept_mmu_notifier_invalidate_range_start,
	.invalidate_range_end	= ept_mmu_notifier_invalidate_range_end,
	.clear_flush_young	= ept_mmu_notifier_clear_flush_young,
	.test_young		= ept_mmu_notifier_test_young,
	.change_pte		= ept_mmu_notifier_change_pte,
	.release		= ept_mmu_notifier_release,
};

int pte_kernel(unsigned long flags)
{
	int r = 0;
	if(__PAGE_KERNEL_EXEC == flags & __PAGE_KERNEL_EXEC) 
		r = 1;
	else if (__PAGE_KERNEL == flags & __PAGE_KERNEL) 
		r = 1;

	return r; 
}


struct page_flags_arg {
        int mapcount;
        int is_kernel;
	int is_write;
	int is_execute;
};

/*
 * arg: page_referenced_arg will be passed
 */
static int page_referenced_one(struct page *page, struct vm_area_struct *vma,
                        unsigned long address, void *arg)
{
        struct mm_struct *mm = vma->vm_mm;
        spinlock_t *ptl;
        struct page_flags_arg *pfa = arg;

        if (unlikely(PageTransHuge(page))) {
                pmd_t *pmd;

                /*
                 * rmap might return false positives; we must filter
                 * these out using page_check_address_pmd().
                 */
                pmd = page_check_address_pmd(page, mm, address,
                                             PAGE_CHECK_ADDRESS_PMD_FLAG, &ptl);
                if (!pmd)
                        return SWAP_AGAIN;

		pfa->is_kernel &= pte_kernel(pmd_flags(*pmd));
		pfa->is_write &= pmd_flags(*pmd) & _PAGE_RW;
		pfa->is_execute &= !(pmd_flags(*pmd) & _PAGE_NX);

                spin_unlock(ptl);
        } else {
                pte_t *pte;

                /*
                 * rmap might return false positives; we must filter
                 * these out using page_check_address().
                 */
                pte = page_check_address(page, mm, address, &ptl, 0);
                if (!pte)
                        return SWAP_AGAIN;

		pfa->is_kernel &= pte_kernel(pte_flags(*pte));
		pfa->is_write &= pte_write(*pte);
		pfa->is_execute &= pte_exec(*pte);

                spin_unlock(ptl);
        }


        pfa->mapcount--;
        if (!pfa->mapcount)
                return SWAP_SUCCESS; /* To break the loop */

        return SWAP_AGAIN;
}

/**
 * combine_flags - test the page permisions
 * @page: the page to test
 */
int combine_flags(struct page *page, struct page_flags_arg *pfa)
{
        int ret;
//        int we_locked = 0;
         struct page_flags_arg null_pfa = {
                .mapcount = 0,
		.is_kernel = 0,
		.is_write = 0,
		.is_execute = 0,
        };

        pfa->mapcount = page_mapcount(page);
	pfa->is_kernel = 1;
	pfa->is_write = 1;
	pfa->is_execute = 1;

        struct rmap_walk_control rwc = {
                .rmap_one = page_referenced_one,
                .arg = (void *)pfa,
//                .anon_lock = page_lock_anon_vma_read,
        };

        if (!page_mapped(page)){
                memcpy(pfa, &null_pfa, sizeof(struct page_flags_arg));
		return 0;
	}

        if (!page_rmapping(page)){
                memcpy(pfa, &null_pfa, sizeof(struct page_flags_arg));
		return 0;
	}


  /*      if (!is_locked && (!PageAnon(page) || PageKsm(page))) {
                we_locked = trylock_page(page);
                if (!we_locked)
                        return 1;
        }
*/
        /*
         * If we are reclaiming on behalf of a cgroup, skip
         * counting on behalf of references from different
         * cgroups
         */

        ret = rmap_walk(page, &rwc);

/*        if (we_locked)
                unlock_page(page);
*/
        return 0;
}

pte_t va_to_pte(unsigned long pgd_root,
		unsigned long addr)
{
	
	/* Trying */
	pgd_t *pgd;
        pud_t *pud;
        pmd_t *pmd;
        pte_t *ptep, pte;	

     	if(addr >= PAGE_OFFSET)
		pgd = pgd_offset_k(addr);
	else
		pgd = (pgd_t *)pgd_root + (((addr) >> PGDIR_SHIFT) & (PTRS_PER_PGD - 1));
     	
	if (pgd_none(*pgd) || pgd_bad(*pgd))
                 goto out;

        pud = pud_offset(pgd, addr);
        if (pud_none(*pud) || pud_bad(*pud))
        	goto out;

        pmd = pmd_offset(pud, addr);
        if (pmd_none(*pmd) || pmd_bad(*pmd))
        	goto out;

        ptep = pte_offset_map(pmd, addr);
	if (!ptep)
		goto out;

        pte = *ptep;
	return pte;

out:	return __pte(0);
}

/*
 * Walk a vmemmap address to the struct page it maps.
 */
unsigned long vmemmap_to_phys(const void *page_addr)
{
	unsigned long addr = (unsigned long) page_addr;
	unsigned long pa = 0;
	pgd_t *pgd = pgd_offset_k(addr);
	printk(KERN_ERR "%s %d: pgd %p %p %lx\n",
			__FILE__, __LINE__, pgd, __pa(pgd), *pgd);

	if (!pgd_none(*pgd)) {
		pud_t *pud = pud_offset(pgd, addr);
		printk(KERN_ERR "%s %d: pud %p %p %lx\n",
				__FILE__, __LINE__, pud, __pa(pud), *pud);
		if (!pud_none(*pud)) {
			pmd_t *pmd = pmd_offset(pud, addr);
			printk(KERN_ERR "%s %d: pmd %p %p %lx\n",
					__FILE__, __LINE__, pmd, __pa(pmd), *pmd);
			/* Assmue vmemmap area always uses huge page */
			BUG_ON(!pmd_large(*pmd));
			pa = (pmd_pfn(*pmd) << PAGE_SHIFT) | (addr & (HPAGE_SIZE-1));
		}
	}
	return pa;
}

int ept_set_epte(struct vmx_vcpu *vcpu, int make_write, int make_read, int make_exec,
		unsigned long gpa, unsigned long gva)
{
	int ret;
	void *va;
	epte_t *epte;
	pte_t gpa_pte;
	unsigned long hpa;
	struct page *pages;
	struct pgprot prot;
	struct page *pg;
	struct page_flags_arg pfa = {
		.mapcount = 0,
		.is_kernel = 0,
		.is_write = 0,
		.is_execute = 0,
        };
	int is_overwrite = 0;

//	pte_t pa = va_to_pte(vmcs_readl(GUEST_CR3), phys_to_virt(gpa));
//	pte_t pa = __va(gpa);
	/*Attention: change the flags to EPT flags.*/
//	printk(KERN_ERR "EPT: ept_set_epte:  gpa is %lx\n", gpa);
//	pte_t pa_pte;
//	pa_pte.pte = gpa;
//	pg = pfn_to_page(pte_pfn(pa_pte));
//	if(ret = combine_flags(pg, &pfa))
//		return -ENOMEM;

	/* Treat user space / kernel space address differently
	 * See Documentation/x86/x86_64/mm.txt for details
	 */
	if (gva < __PAGE_OFFSET) {
		/* User land */
		ret = get_user_pages_fast(gva, 1, 0, &pages);
		BUG_ON(ret < 1);
		hpa = page_to_phys(pages) | (gva & (PAGE_SIZE-1));
		put_page(pages);
	} else if (gva >= _AC(0xffff800000000000, UL)
			&& gva < _AC(0xffff880000000000, UL)) {
		/* guard hole */
		printk(KERN_ERR "%s %d: invalid GVA %p\n",
				__FILE__, __LINE__, gva);
		BUG();
	} else if (gva >= PAGE_OFFSET
			&& gva < (PAGE_OFFSET+MAXMEM)) {
		/* direct mapping area */
		hpa = gva - PAGE_OFFSET;
	} else if (gva >= _AC(0xffffc80000000000, UL)
			&& gva < _AC(0xffffc90000000000,UL)) {
		/* hole */
		printk(KERN_ERR "%s %d: invalid GVA %p\n",
				__FILE__, __LINE__, gva);
		BUG();
	} else if (gva >= VMALLOC_START && gva <= VMALLOC_END) {
		/* vmalloc area */
		hpa = (page_to_phys(vmalloc_to_page(gva)) | (gva & (PAGE_SIZE-1)));
	} else if (gva >= _AC(0xffffe90000000000,UL)
			&& gva < _AC(0xffffea0000000000, UL)) {
		/* hole */
		printk(KERN_ERR "%s %d: invalid GVA %p\n",
				__FILE__, __LINE__, gva);
		BUG();
	} else if (gva >= VMEMMAP_START
			&& gva <= _AC(0xffffeaffffffffff, UL)) {
		/* virtual memory map, vmemmap area (struct page) */
		// FIXME: now we temporarily share page structure with host,
		// so we don't use make_write to allocate new page for them
		if (make_write) {
			printk(KERN_DEBUG "%s %d\n",
					__FILE__, __LINE__);
			make_write = 0;
			pfa.is_write = 1;
			is_overwrite = 1;
		}
		hpa = vmemmap_to_phys(gva);
		printk(KERN_ERR "%s %d: setting vmemmap area gva %pS, gpa %p, hpa %p\n",
				__FILE__, __LINE__, gva, gpa, hpa);
	} else if (gva > _AC(0xffffeaffffffffff, UL)
			&& gva < __START_KERNEL_map) {
		/* holes, kasan shadow memory, %esp fixup stacks */
		printk(KERN_ERR "%s %d: invalid GVA %p\n",
				__FILE__, __LINE__, gva);
		BUG();
	} else if (gva >= __START_KERNEL_map && gva < MODULES_VADDR) {
		/* kernel text mappings */
		hpa = __pa(gva);
	} else if (gva >= MODULES_VADDR && gva < MODULES_END) {
		/* module mapping area */
		// FIXME: is it okay to use vmalloc_to_page on module area?
		hpa = (page_to_phys(vmalloc_to_page(gva)) | (gva & (PAGE_SIZE-1)));
	} else {
		/* vsyscalls, holes */
		printk(KERN_ERR "%s %d: invalid GVA %p\n",
				__FILE__, __LINE__, gva);
		BUG();
	}

	if(gva == 0){
		pfa.is_kernel = 1;
		pfa.is_write = 0;
		pfa.is_execute = 1;
	}
	else if(hpa == gpa){
		pfa.is_kernel = 1;
		gpa_pte = va_to_pte((unsigned long)azk_init_mm->pgd, gva);
		if (is_overwrite) {
			/* if is_overwrite is set, flags
			 * are already set in previous steps
			 */
		} else if(pte_val(gpa_pte) == 0){
			pfa.is_write = 0;
			pfa.is_execute = 1;
		} else {
			pfa.is_write = pte_write(gpa_pte);
			pfa.is_execute = pte_exec(gpa_pte);
		}
	} else {
		printk(KERN_ERR "%s %d: different hpa %p vs. gpa %p\n",
				__FILE__, __LINE__, hpa, gpa);
		pfa.is_kernel = 0;
		gpa_pte = va_to_pte(__va(vmcs_readl(GUEST_CR3)), gva);
		if (pte_val(gpa_pte) == 0) {
                        pfa.is_write = 0;
                        pfa.is_execute = 1;
                }
                else{
                        pfa.is_write = pte_write(gpa_pte);
                        pfa.is_execute = pte_exec(gpa_pte);
                }
	}
//	ret = add_to_ept(__va(vcpu->ept_root), pte_val(pa_pte) & PTE_PFN_MASK, pfa.is_kernel, pfa.is_write, pfa.is_execute, make_write, 0);
	spin_lock(&vcpu->ept_lock);
	ret = add_to_ept(__va(vcpu->ept_root), gpa & PTE_PFN_MASK,
			pfa.is_kernel, pfa.is_write, pfa.is_execute,
			make_write, make_read, make_exec, is_overwrite);
	spin_unlock(&vcpu->ept_lock);
#if 0 /* Debug code for examining actually ept mapping address, re-enable when need to debug */
	{
		epte_t *epte;
		int rval;
		rval = ept_lookup_gpa(vcpu, gpa, 0, 0, &epte);
		printk(KERN_DEBUG "%s %d: set epte for %p %p %p\n",
				__FILE__, __LINE__, gpa, hpa, *epte);
		WARN_ON((hpa & PTE_PFN_MASK) != (*epte & PTE_PFN_MASK));
	}
#endif
	return ret;
}

/* Add a specific hpa to ept, and map it at gpa */
int add_to_ept_hpa(pte_t *epgd, unsigned long gpa, unsigned long hpa, int is_kernel, int is_write, int is_execute, int make_write, int make_read, int make_exec, int is_overwrite)
{

	pte_t *epud;	// epud table
	pte_t *epmd;	// epmd table
	pte_t *epte;	// epte table
	int i;		// index
	void *page;
#if DEBUG
//	printk(KERN_INFO "add_to_ept: gpa = %lx, epgd = %lx, is_kernel = %d, is_w = %d, is_x = %d, make_write = %d\n", gpa, epgd, is_kernel, is_write, is_execute, make_write);
#endif
	i = ((gpa >> PGDIR_SHIFT) & (PTRS_PER_PGD - 1));

#if DEBUG
//        printk(KERN_INFO "add_to_ept: i = %d\n", i);
#endif

	if (!pte_present(epgd[i])) {
		page = (void *) __get_free_page(GFP_AZK);
		if (!page) {
#if DEBUG
        printk(KERN_INFO "add_to_ept: error 1\n");
#endif

		goto ERROR;
		}

		memset(page, 0, PAGE_SIZE);
		epgd[i] = __pte(virt_to_phys(page) | __EPTE_FULL);
	}

	epud = (pte_t *)phys_to_virt(pte_val(epgd[i]) & PTE_PFN_MASK);
	i = ((gpa >> PUD_SHIFT) & (PTRS_PER_PUD - 1));

	if (!pte_present(epud[i])) {
		page = (void *) __get_free_page(GFP_AZK);
		if (!page) {
#if DEBUG
        printk(KERN_INFO "add_to_ept: error 2\n");
#endif
			goto ERROR;
		}

		memset(page, 0, PAGE_SIZE);
		epud[i] = __pte(virt_to_phys(page) | __EPTE_FULL);
	}

	epmd = (pte_t *)phys_to_virt(pte_val(epud[i]) & PTE_PFN_MASK);
	i = ((gpa >> PMD_SHIFT) & (PTRS_PER_PMD - 1));

	if (!pte_present(epmd[i])) {
		page = (void *) __get_free_page(GFP_AZK);
		if (!page) {
#if DEBUG
        printk(KERN_INFO "add_to_ept: error 3\n");
#endif
			goto ERROR;
		}

		memset(page, 0, PAGE_SIZE);
		epmd[i] = __pte(virt_to_phys(page) | __EPTE_FULL);
	}

	epte = (pte_t *)phys_to_virt(pte_val(epmd[i]) & PTE_PFN_MASK);
	i = pte_index(gpa);

	if (!pte_present(epte[i]) || is_overwrite) {
		if(is_execute)
			epte[i] = __pte(hpa | __EPTE_READ | __EPTE_EXEC | __EPTE_TYPE(EPTE_TYPE_WB) | __EPTE_IPAT);
		else if(is_write)
			epte[i] = __pte(hpa | __EPTE_READ | __EPTE_WRITE | __EPTE_TYPE(EPTE_TYPE_WB) | __EPTE_IPAT);
		else
			epte[i] = __pte(hpa | __EPTE_READ | __EPTE_TYPE(EPTE_TYPE_WB) | __EPTE_IPAT);
	}
	else if(make_write){
#if DEBUG
//        printk(KERN_INFO "add_to_ept: count is %d\n", count++);
#endif

//	if(count++ != 0){
#if DEBUG
//        printk(KERN_INFO "add_to_ept: error 4\n");
#endif
//		goto ERROR;
//}
		page = (void *) __get_free_page(GFP_AZK);
		if(!page){
		goto ERROR;
		}
		memcpy(page, __va(hpa), PAGE_SIZE);
		epte[i] = __pte(__pa(page) | __EPTE_READ | __EPTE_WRITE | __EPTE_TYPE(EPTE_TYPE_WB) | __EPTE_IPAT);
	}
	else if(make_exec){
		epte[i] = __pte(pte_val(epte[i]) | __EPTE_EXEC);
	}
	else if(make_read){
		epte[i] = __pte(pte_val(epte[i]) | __EPTE_READ);
	}
	return 0;

ERROR:
	printk(KERN_ERR "add_to_ept: error in ept\n");
	// TODO: free_ept_
	return -ENOMEM;

}

int add_to_ept(pte_t *epgd, unsigned long address, int is_kernel, int is_write, int is_execute, int make_write, int make_read, int make_exec, int is_overwrite){

	pte_t *epud;	// epud table
	pte_t *epmd;	// epmd table
	pte_t *epte;	// epte table
	int i;		// index
	void *page;
#if DEBUG
//	printk(KERN_INFO "add_to_ept: address = %lx, epgd = %lx, is_kernel = %d, is_w = %d, is_x = %d, make_write = %d\n", address, epgd, is_kernel, is_write, is_execute, make_write);
#endif
	i = ((address >> PGDIR_SHIFT) & (PTRS_PER_PGD - 1));

#if DEBUG
//        printk(KERN_INFO "add_to_ept: i = %d\n", i);
#endif

	if (!pte_present(epgd[i])) {
		page = (void *) __get_free_page(GFP_AZK);
		if (!page) {
#if DEBUG
        printk(KERN_INFO "add_to_ept: error 1\n");
#endif

		goto ERROR;
		}

		memset(page, 0, PAGE_SIZE);
		epgd[i] = __pte(virt_to_phys(page) | __EPTE_FULL);
	}

	epud = (pte_t *)phys_to_virt(pte_val(epgd[i]) & PTE_PFN_MASK);
	i = ((address >> PUD_SHIFT) & (PTRS_PER_PUD - 1));

	if (!pte_present(epud[i])) {
		page = (void *) __get_free_page(GFP_AZK);
		if (!page) {
#if DEBUG
        printk(KERN_INFO "add_to_ept: error 2\n");
#endif
			goto ERROR;
		}

		memset(page, 0, PAGE_SIZE);
		epud[i] = __pte(virt_to_phys(page) | __EPTE_FULL);
	}

	epmd = (pte_t *)phys_to_virt(pte_val(epud[i]) & PTE_PFN_MASK);
	i = ((address >> PMD_SHIFT) & (PTRS_PER_PMD - 1));

	if (!pte_present(epmd[i])) {
		page = (void *) __get_free_page(GFP_AZK);
		if (!page) {
#if DEBUG
        printk(KERN_INFO "add_to_ept: error 3\n");
#endif
			goto ERROR;
		}

		memset(page, 0, PAGE_SIZE);
		epmd[i] = __pte(virt_to_phys(page) | __EPTE_FULL);
	}

	epte = (pte_t *)phys_to_virt(pte_val(epmd[i]) & PTE_PFN_MASK);
	i = pte_index(address);

	if (!pte_present(epte[i]) || is_overwrite) {
		if(is_execute)
			epte[i] = __pte(address | __EPTE_READ | __EPTE_EXEC | __EPTE_TYPE(EPTE_TYPE_WB) | __EPTE_IPAT);
		else if(is_write)
			epte[i] = __pte(address | __EPTE_READ | __EPTE_WRITE | __EPTE_TYPE(EPTE_TYPE_WB) | __EPTE_IPAT);
		else
			epte[i] = __pte(address | __EPTE_READ | __EPTE_TYPE(EPTE_TYPE_WB) | __EPTE_IPAT);
	}
	else if(make_write){
#if DEBUG
//        printk(KERN_INFO "add_to_ept: count is %d\n", count++);
#endif
		
//	if(count++ != 0){
#if DEBUG
//        printk(KERN_INFO "add_to_ept: error 4\n");
#endif
//		goto ERROR;
//}
		page = (void *) __get_free_page(GFP_AZK);
		if(!page){
		goto ERROR;
		}
		memcpy(page, __va(address), PAGE_SIZE);
		epte[i] = __pte(__pa(page) | __EPTE_READ | __EPTE_WRITE | __EPTE_TYPE(EPTE_TYPE_WB) | __EPTE_IPAT);	
	}
	else if(make_exec){
		epte[i] = __pte(pte_val(epte[i]) | __EPTE_EXEC);
	}
	else if(make_read){
		epte[i] = __pte(pte_val(epte[i]) | __EPTE_READ);
	}
	return 0;

ERROR:
	printk(KERN_ERR "add_to_ept: error in ept\n");
	// TODO: free_ept_
	return -ENOMEM;

}

int add_mm(struct mm_struct *mm, struct vmx_vcpu *vcpu, pte_t *epgd, int is_overwrite)
{
        pte_t *pgd;
        pte_t *pud;
        pte_t *pmd;
        pte_t *pte;
        int i, j, k, l;

        //asm("\t movq %%cr3,%0" : "=r"(cr3));

        //printk(KERN_ERR "vmx_init_ept: asm pass \n");
        //pgd = phys_to_virt(cr3 & PTE_PFN_MASK);
        pgd = (pte_t *)mm->pgd;


        for (i = 0; i < PTRS_PER_PGD; i++) {
                // If pgd entry not present, continue to next
                if (!pte_present(pgd[i]))
                        continue;
                // Get original pud vaddress
                pud = (pte_t *)phys_to_virt(pte_val(pgd[i]) & PTE_PFN_MASK);
#if DEBUG
//                printk("Adding pud root at %lx\n", pte_val(pgd[i]) & PTE_PFN_MASK);
#endif
                if(add_to_ept(epgd, (pte_val(pgd[i]) & PTE_PFN_MASK), pte_kernel(pte_flags(pgd[i])), pte_write(pgd[i]), pte_exec(pgd[i]), 0, 0, 0, is_overwrite) < 0){
                        goto ERROR;
                }

                // Traverse thro all pud entries
                for (j = 0; j < PTRS_PER_PUD; j++) {
                        if (!pte_present(pud[j]))
                                continue;
                        pmd = (pte_t *) phys_to_virt(pte_val(pud[j]) & PTE_PFN_MASK);
#if DEBUG
//                        printk("Adding pmd root at %lx\n", pte_val(pud[j]) & PTE_PFN_MASK);
#endif
                        if(add_to_ept(epgd, pte_val(pud[j]) & PTE_PFN_MASK, pte_kernel(pte_flags(pud[j])), pte_write(pud[j]), pte_exec(pud[j]), 0, 0, 0, is_overwrite) < 0){
                                goto ERROR;
                        }

                        // Traverse thro all pmd entries
                        for (k = 0; k < PTRS_PER_PMD; k++) {
                                if (!pte_present(pmd[k]))
                                        continue;

                                pte = (pte_t *) phys_to_virt(pte_val(pmd[k]) & PTE_PFN_MASK);
#if DEBUG
//                                printk("Adding pte root at %lx\n", pte_val(pmd[k]) & PTE_PFN_MASK);
#endif
                                if(add_to_ept(epgd, pte_val(pmd[k]) & PTE_PFN_MASK, pte_kernel(pte_flags(pmd[k])), pte_write(pmd[k]), pte_exec(pmd[k]), 0, 0, 0, is_overwrite) < 0){
                                        goto ERROR;
                                }

                                for (l = 0; l < PTRS_PER_PTE; l++) {
                                        if (!pte_present(pte[l]))
                                                continue;
#if DEBUG
//                                        printk("Adding pte entry at %lx\n", pte_val(pte[l]) & PTE_PFN_MASK);
#endif
                                        if(add_to_ept(epgd, pte_val(pte[l]) & PTE_PFN_MASK, pte_kernel(pte_flags(pte[l])), pte_write(pte[l]), pte_exec(pte[l]), 0, 0, 0, is_overwrite) < 0){
                                                goto ERROR;
                                        }
                                }
                        }
                }
        }

        return 0;
ERROR:
        printk(KERN_ERR "vmx_init_ept error");
        return -ENOMEM;
}

int ept_set_stack_perm(struct vmx_vcpu *vcpu, pte_t *epgd, unsigned long rsp)
{
	int r = 0;
	unsigned long curr_rsp, pa_rsp, pa_curr_rsp;
	struct page *pages;
	asm volatile("mov %%rsp,%0\n\t" : "=r" (curr_rsp), "=m" (__force_order));
//	pa_rsp = pte_val(va2pa(vcpu, rsp));
//	pa_curr_rsp = pte_val(va2pa(vcpu, curr_rsp));
//	for(i = rsp; i < 0xffffff7fffffffff && r == 0; i+= PAGE_SIZE)
	printk(KERN_ERR "Setting stack pointers %p\n", rsp);
	r = add_to_ept(epgd, (long unsigned int)__pa(rsp) & PTE_PFN_MASK, 1, 1, 0, 0, 0, 0, 1);
#if 0
	r = get_user_pages_fast(rsp, 1, 0, &pages);
	BUG_ON(r < 1);
	pa_rsp = page_to_phys(pages);
	printk(KERN_ERR "Setting stack pointers %p at phys %lx\n", rsp, pa_rsp);
	r = add_to_ept(epgd, pa_rsp & PTE_PFN_MASK, 0, 1, 0, 0, 1);
	put_page(pages);
#endif
	return r;
}

int ept_set_user_stack_perm(struct vmx_vcpu *vcpu, pte_t *epgd, unsigned long rsp)
{
	int r = 0;
	struct page *pages;
	unsigned long pa_rsp;
	r = get_user_pages_fast(rsp, 1, 0, &pages);
	BUG_ON(r < 1);
	pa_rsp = page_to_phys(pages);
	printk(KERN_ERR "Setting user stack pointers %p at phys %lx\n", rsp, pa_rsp);
	r = add_to_ept(epgd, pa_rsp & PTE_PFN_MASK, 0, 1, 0, 0, 0, 0, 1);
	put_page(pages);
	return r;
}

int ept_set_rip_perm(struct vmx_vcpu *vcpu, pte_t *epgd, unsigned long rip)
{
	int r = 0;
	unsigned long curr_rsp, pa_rsp, pa_curr_rsp;
	struct page *pages;
//	asm volatile("mov %%rsp,%0\n\t" : "=r" (curr_rsp), "=m" (__force_order));
//	pa_rsp = pte_val(va2pa(vcpu, rsp));
//	pa_curr_rsp = pte_val(va2pa(vcpu, curr_rsp));
//	for(i = rsp; i < 0xffffff7fffffffff && r == 0; i+= PAGE_SIZE)
	printk(KERN_ERR "Setting IP pointers %p\n", rip);
	r = add_to_ept(epgd, (long unsigned int)__pa(rip) & PTE_PFN_MASK, 1, 0, 1, 0, 0, 0, 1);
#if 0
	r = get_user_pages_fast(rsp, 1, 0, &pages);
	BUG_ON(r < 1);
	pa_rsp = page_to_phys(pages);
	printk(KERN_ERR "Setting stack pointers %p at phys %lx\n", rsp, pa_rsp);
	r = add_to_ept(epgd, pa_rsp & PTE_PFN_MASK, 0, 1, 0, 0, 1);
	put_page(pages);
#endif
	return r;
}

int ept_set_user_rip_perm(struct vmx_vcpu *vcpu, pte_t *epgd, unsigned long rip)
{
	int r = 0;
	struct page *pages;
	unsigned long pa_rip;
	r = get_user_pages_fast(rip, 1, 0, &pages);
	if (r < 1)
		printk(KERN_ERR "%s %d Failed to retrieve user RIP page at %p (error %d)\n",
				__FILE__, __LINE__, rip, r);
	BUG_ON(r < 1);
	pa_rip = page_to_phys(pages);
	printk(KERN_ERR "Setting user IP pointer %p at phys %lx\n", rip, pa_rip);
	r = add_to_ept(epgd, pa_rip & PTE_PFN_MASK, 0, 0, 1, 0, 0, 0, 1);
	put_page(pages);
	return r;
}


int ept_set_cr3_perm(struct vmx_vcpu *vcpu, pte_t *epgd, unsigned long pa_cr3)
{
	int r = 0;
	printk(KERN_ERR "Setting CR3 perms %p\n", pa_cr3);
	r = add_to_ept(epgd, pa_cr3 & PTE_PFN_MASK, 1, 0, 0, 0, 0, 0, 1);
	return r;
}


int vmx_init_ept(struct vmx_vcpu *vcpu, struct azk_config *conf)
{	
	struct mm_struct *mm = current->active_mm;
	int ret, i;
	pte_t *epgd;
        void *page = (void *) __get_free_page(GFP_AZK);

        /*Change : changing PTE_PFN_MASK to EPT_PAGE_MASK */

        printk(KERN_ERR "vmx_init_ept: Entering \n");
        if (!page) {
                printk(KERN_ERR "vmx_init_ept: Alloc 1 fail \n");
                return -ENOMEM;
        }

        memset(page, 0, PAGE_SIZE);
        epgd = (pte_t *)page;
        vcpu->ept_root =  __pa(page);
/*	for(i = vmcs_readl(GUEST_RSP); i < 0xffffff7fffffffff; i+= PAGE_SIZE)
		add_to_ept(epgd, i & PTE_PFN_MASK, 1, 0, 0, 0);
	return 0;
*/
	return 0;
}

int vmx_populate_ept(struct vmx_vcpu *vcpu, struct azk_config *conf)
{
	struct mm_struct *mm = current->active_mm;
	int ret, i;
	pte_t *epgd = __va(vcpu->ept_root);

	if((ret = add_mm(mm, vcpu, epgd, 1)))
		return ret;
	if(ret = add_mm(azk_init_mm, vcpu, epgd, 1))
		return ret;
	if(ept_set_stack_perm(vcpu, epgd, conf->krsp))
                return -ENOMEM;
	if(ept_set_user_stack_perm(vcpu, epgd, conf->rsp))
		return -ENOMEM;
	if(ept_set_cr3_perm(vcpu, epgd, conf->cr3))
		return -ENOMEM;
	if(ept_set_rip_perm(vcpu, epgd, conf->krip))
                return -ENOMEM;
	if(ept_set_user_rip_perm(vcpu, epgd, conf->rip))
		return -ENOMEM;
	
	return 0;
	
}

int vmx_create_ept(struct vmx_vcpu *vcpu)
{
	int ret;

	vcpu->mmu_notifier.ops = &ept_mmu_notifier_ops;
	ret = mmu_notifier_register(&vcpu->mmu_notifier, current->mm);
	if (ret)
		goto fail;

	return 0;

fail:
	vmx_free_ept(vcpu->ept_root);

	return ret;
}

void vmx_destroy_ept(struct vmx_vcpu *vcpu)
{
	mmu_notifier_unregister(&vcpu->mmu_notifier, current->mm);
	vmx_free_ept(vcpu->ept_root);
}
