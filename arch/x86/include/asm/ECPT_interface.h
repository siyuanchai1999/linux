#ifndef _ASM_X86_ECPT_INTERFACE_H
#define _ASM_X86_ECPT_INTERFACE_H

#include <asm/ECPT.h>

/**
 * @brief index on compacted pte
 * 
 * @param addr 
 * @return unsigned long 
 */

static inline unsigned long ecpt_pte_index(unsigned long addr) 
{
	return (addr >> PAGE_SIZE_4KB) & (ECPT_CLUSTER_FACTOR - 1);
}

static inline unsigned long ecpt_pmd_index(unsigned long addr) 
{
	return (addr >> PAGE_SIZE_2MB) & (ECPT_CLUSTER_FACTOR - 1);
}

static inline unsigned long ecpt_pud_index(unsigned long addr)
{
	return (addr >> PAGE_SIZE_1GB) & (ECPT_CLUSTER_FACTOR - 1);
}


static inline pte_t * pte_offset_from_ecpt_entry(struct ecpt_entry *entry, unsigned long addr) 
{
	return (pte_t *) &entry->pte[ecpt_pte_index(addr)];
}

static inline pmd_t * pmd_offset_from_ecpt_entry(struct ecpt_entry *entry, unsigned long addr) 
{
	return (pmd_t *) &entry->pte[ecpt_pmd_index(addr)];
}

static inline pud_t * pud_offset_from_ecpt_entry(struct ecpt_entry *entry, unsigned long addr)
{
	return (pud_t *) &entry->pte[ecpt_pud_index(addr)];
}


/*  */
static inline spinlock_t *pte_lockptr(struct mm_struct *mm, pmd_t *pmd)
{
	return &mm->page_table_lock;
}
#define pte_lockptr pte_lockptr



static inline pte_t * pte_offset_ecpt(struct mm_struct *mm, unsigned long addr) {
	Granularity g = page_4KB;
	// uint32_t way = 0;
	// ecpt_entry_t * e = get_hpt_entry(mm->map_desc, addr, &g, &way);
	ecpt_entry_t * e = ecpt_search_fit(mm->map_desc, addr, g);
	if (e) 
		return (pte_t *) &e->pte;
	else 
		return (pte_t *) &pte_default.pte;
}

/* override definition in linux/pgtable.h */
static inline pte_t *pte_offset_kernel(void *mm, unsigned long address)
{
	return pte_offset_ecpt((struct mm_struct *)mm, address);
}

#define pte_offset_kernel pte_offset_kernel


/* return address of default entry if it doesn't exit */
#define pte_offset_map_lock(mm, pmd, address, ptlp)	\
({							\
	spinlock_t *__ptl = pte_lockptr(mm, pmd);	\
	pte_t *__pte = pte_offset_ecpt(mm, address);	\
	*(ptlp) = __ptl;				\
	spin_lock(__ptl);				\
	__pte;						\
})

// #define pte_unmap_unlock(pte, ptl)	do {} while (0)

#define pte_alloc(mm, pmd) (NULL)
#define __ARCH_HAS_PTE_ALLOC

int ecpt_set_pte_at(struct mm_struct *mm, unsigned long addr,
			      pte_t *ptep, pte_t pte);


static inline void ecpt_set_pmd_at(struct mm_struct *mm, unsigned long addr,
			      pmd_t *pmdp, pmd_t pmd)
{
	int res = ecpt_mm_insert(
		mm,
		addr,
		ENTRY_TO_ADDR(pmd.pmd),
		__ecpt_pgprot(ENTRY_TO_PROT(pmd.pmd)),
		page_2MB
	);

	WARN(res, "Error when insert %lx as 2MB page\n", addr);
}

static inline void ecpt_set_pud_at(struct mm_struct *mm, unsigned long addr,
			      pud_t *pudp, pud_t pud)
{
	int res = ecpt_mm_insert(
		mm,
		addr,
		ENTRY_TO_ADDR(pud.pud),
		__ecpt_pgprot(ENTRY_TO_PROT(pud.pud)),
		page_1GB
	);

	WARN(res, "Error when insert %lx as 1GB page\n", addr);
}

pte_t ecpt_native_ptep_get_and_clear(struct mm_struct *mm,
					unsigned long addr, pte_t *ptep);


static inline pmd_t ecpt_native_pmdp_get_and_clear(struct mm_struct *mm,
					unsigned long addr, pmd_t *pmdp)
{
	pmd_t ret = *pmdp;
	int res = ecpt_mm_invalidate(mm, addr, page_2MB);
	
	WARN(res, "Fail to invalid 2MB page %lx \n", addr);
	return ret;
}

static inline pud_t ecpt_native_pudp_get_and_clear(struct mm_struct *mm,
					unsigned long addr, pud_t *pudp)
{
	pud_t ret = *pudp;
	int res = ecpt_mm_invalidate(mm, addr, page_1GB);

	WARN(res, "Fail to invalid 1GB page %lx \n", addr);
	return ret;
}

#endif /* _ASM_X86_ECPT_INTERFACE_H */