#include <asm/ECPT.h>
#include <asm/ECPT_defs.h>
#include <asm/ECPT_interface.h>

#include <asm/page.h>
#include <asm/pgalloc.h>
#include <linux/spinlock.h>
#include <linux/panic.h>

inline int pgd_next_level_not_accessible(pgd_t *pgd) 
{	
	if ((pgd == (pgd_t *) &pmd_default) || pgd_none(*pgd))
		return 0;
	if (unlikely(pgd_bad(*pgd))) {
		pgd_clear_bad(pgd);
		return 1;
	}
	return 0;
}

inline int p4d_next_level_not_accessible(p4d_t *p4d) 
{
	if (p4d == (p4d_t *) &pmd_default || p4d_none(*p4d))
		return 0;
	if (unlikely(p4d_bad(*p4d))) {
		p4d_clear_bad(p4d);
		return 1;
	}
	return 0;
}

inline int pud_next_level_not_accessible(pud_t *pud) 
{
	pud_t pudval = READ_ONCE(*pud);

	if (pud == ((pud_t *) &pmd_default) || pud_none(pudval))  {
		/* pmd actually not in ECPT */
		return 0;
	}

	/**
	 * copied from pud_none_or_trans_huge_or_dev_or_clear_bad 
	 * but allow pud to be none since default case is none
	 * */
	if (pud_trans_huge(pudval) || pud_devmap(pudval))
		return 1;
	if (unlikely(pud_bad(pudval))) {
		pud_clear_bad(pud);
		return 1;
	}
	return 0;
}

inline int pmd_next_level_not_accessible(pmd_t *pmd) 
{
	pmd_t pmdval = pmd_read_atomic(pmd);
#ifdef CONFIG_TRANSPARENT_HUGEPAGE	
	barrier();
#endif
	// if (pmd == ((pmd_t *) &pmd_default) || pmd_none(pmdval))  {
	if (no_pmd_huge_page((pmdval))) {
		/* pmd actually not in ECPT */
		return 0;
	}

	/* For ECPT case, it's unstable if it's trans_huge or bad */
	if (pmd_trans_huge(*pmd)) {
		return 1;
	}

	if (unlikely(pmd_bad(pmdval))) {
		pmd_clear_bad(pmd);
		return 1;
	}

	return 0;
}
/* TODO: fix pmd_trans_unstable and pud_trans_unstable */
inline int pmd_trans_unstable(pmd_t *pmd)
{
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
	return pmd_next_level_not_accessible(pmd);
	// pmd_t pmdval = pmd_read_atomic(pmd);
	// barrier();
	
	// if (pmd == ((pmd_t *) &pmd_default) || pmd_none(pmdval))  {
	// 	/* pmd actually not in ECPT */
	// 	return 0;
	// }

	// /* For ECPT case, it's unstable if it's trans_huge or bad */
	// if (pmd_trans_huge(*pmd)) {
	// 	return 1;
	// }

	// if (unlikely(pmd_bad(pmdval))) {
	// 	pmd_clear_bad(pmd);
	// 	return 1;
	// }

	// return 0;
#else
	return 0;
#endif
}

inline int pud_trans_unstable(pud_t *pud)
{
#if defined(CONFIG_TRANSPARENT_HUGEPAGE) &&			\
	defined(CONFIG_HAVE_ARCH_TRANSPARENT_HUGEPAGE_PUD)
	pud_t pudval = READ_ONCE(*pud);

	if (pud == ((pud_t *) &pmd_default) || pud_none(pudval))  {
		/* pmd actually not in ECPT */
		return 0;
	}

	/**
	 * copied from pud_none_or_trans_huge_or_dev_or_clear_bad 
	 * but allow pud to be none since default case is none
	 * */
	if (pud_trans_huge(pudval) || pud_devmap(pudval))
		return 1;
	if (unlikely(pud_bad(pudval))) {
		pud_clear_bad(pud);
		return 1;
	}
	return 0;
#else
	return 0;
#endif
}

void pgtable_trans_huge_deposit(struct mm_struct *mm, pmd_t *pmdp,
				pgtable_t pgtable)
{
	assert_spin_locked(pmd_lockptr(mm, pmdp));

	pr_info_verbose("deposit pmdp at %llx pgtable at %llx pte_page_default at %llx\n",
	 	(uint64_t) pmdp, (uint64_t) pgtable, (uint64_t) pte_page_default);

	WARN(pgtable != pte_page_default, "Expect pgtable=%llx but at %llx\n",
		(uint64_t) pte_page_default, (uint64_t) pgtable);

	/* no need to deposit for ECPT */
	// if (!pmd_huge_pte(mm, pmdp))
	// 	INIT_LIST_HEAD(&pgtable->lru);
	// else
	// 	list_add(&pgtable->lru, &pmd_huge_pte(mm, pmdp)->lru);
	// pmd_huge_pte(mm, pmdp) = pgtable;
}

pgtable_t pgtable_trans_huge_withdraw(struct mm_struct *mm, pmd_t *pmdp)
{
	return pte_page_default;
}

inline void pud_mk_pmd_accessible(struct mm_struct *mm, pud_t *pud, 
	unsigned long addr, pmd_t *pmd)
{
	pr_info_verbose("make accessible pud at %llx addr= %lx\n",
	 	(uint64_t) pud, addr);
	
#if ECPT_1G_WAY > 0 || ECPT_1G_USER_WAY > 0
	if (!no_pud_huge_page(*pud)) {
		WARN(1, "Clean pud at %llx addr=%lx\n", (uint64_t) pud, addr);
		ecpt_native_pudp_get_and_clear(mm, addr, pud);
	}
#else
	/* do nothing */
#endif
}

inline void pmd_mk_pte_accessible(struct mm_struct *mm, pmd_t *pmd, 
	unsigned long addr, struct page *pte)
{
	pr_info_verbose("make accessible pmdp at %llx addr= %lx\n",
	 	(uint64_t) pmd, addr);
#if ECPT_2M_WAY > 0 || ECPT_2M_USER_WAY > 0
	if (!no_pmd_huge_page(*pmd)) {
		// WARN(1, "Clean pmd at %llx = %lx addr=%lx\n", 
		// 	(uint64_t) pmd, pmd->pmd, addr);
		if (ptep_is_in_ecpt((ECPT_desc_t *) mm->map_desc, (pte_t *) pmd,
			 		addr, page_2MB)) 
		{
			ecpt_native_pmdp_get_and_clear(mm, addr, pmd);
		}
	}
#else
	/* do nothing */
#endif
}

inline void pmd_mk_pte_accessible_kernel(struct mm_struct *mm, pmd_t *pmd, 
	unsigned long addr, pte_t *pte) 
{
	pmd_mk_pte_accessible(mm, pmd, addr, virt_to_page((void *) pte));
}
