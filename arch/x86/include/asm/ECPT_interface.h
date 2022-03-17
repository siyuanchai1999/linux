#ifndef _ASM_X86_ECPT_INTERFACE_H
#define _ASM_X86_ECPT_INTERFACE_H

#include <asm/ECPT.h>

static inline void ecpt_set_pte_at(struct mm_struct *mm, unsigned long addr,
			      pte_t *ptep, pte_t pte)
{
	int res;
	pr_info("set_pte_at Insert 4KB addr=%lx pte=%lx\n", addr, pte.pte);
	res = ecpt_mm_insert(
		mm,
		addr,
		ENTRY_TO_ADDR(pte.pte),
		__ecpt_pgprot(ENTRY_TO_PROT(pte.pte)),
		page_4KB
	);

	WARN(res, "Error when insert %lx as 4KB page\n", addr);
}
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

static inline pte_t ecpt_native_ptep_get_and_clear(struct mm_struct *mm,
					unsigned long addr, pte_t *ptep)
{
	pte_t ret = *ptep;
	int res = ecpt_mm_invalidate(mm, addr, page_4KB);

	WARN(res, "Fail to invalid 4KB page %lx \n", addr);
	return ret;
}


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