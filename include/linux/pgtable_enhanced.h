#ifndef _LINUX_PGTABLE_ENHANCED_H
#define _LINUX_PGTABLE_ENHANCED_H

#include <linux/pgtable.h>
#include <linux/pgtable_enhanced.h>

#ifndef	 __ARCH_HAS_PTE_OFFSET_MAP_WITH_MM
#define pte_offset_map_with_mm(mm, pmd, addr) pte_offset_kernel((pmd), (addr))
#endif

#ifndef	 __ARCH_HAS_PMD_OFFSET_MAP_WITH_MM
#define pmd_offset_map_with_mm(mm, pud, addr) pmd_offset((pud), (addr))
#endif

#ifndef	 __ARCH_HAS_PUD_OFFSET_MAP_WITH_MM
#define pud_offset_map_with_mm(mm, p4d, addr) pud_offset((p4d), (addr))
#endif

#ifndef	 __ARCH_HAS_P4D_OFFSET_MAP_WITH_MM
#define p4d_offset_map_with_mm(mm, pgd, addr) p4d_offset((pgd), (addr))
#endif

#ifndef	 __ARCH_HAS_PGD_OFFSET_MAP_WITH_MM
#define pgd_offset_map_with_mm(mm, addr) pgd_offset((mm), (addr))
#endif

#ifndef	 __ARCH_HAS_PTEP_GET_NEXT
static inline pte_t * ptep_get_next(struct mm_struct *mm, pte_t * ptep, unsigned long addr) 
{
	return ptep + 1;
}
#endif

#ifndef	 __ARCH_HAS_PTEP_GET_N_NEXT
static inline pte_t * ptep_get_n_next(struct mm_struct *mm, pte_t * ptep, unsigned long addr, unsigned int n) 
{
	return ptep + n;
}
#endif


#ifndef	 __ARCH_HAS_PMDP_GET_NEXT
static inline pmd_t * pmdp_get_next(struct mm_struct *mm, pmd_t *pmdp, unsigned long addr) 
{
	return pmdp + 1;
}
#endif

#ifndef	 __ARCH_HAS_PUDP_GET_NEXT
static inline pud_t * pudp_get_next(struct mm_struct *mm, pud_t *pudp, unsigned long addr) 
{
	return pudp + 1;
}
#endif

#ifndef	 __ARCH_HAS_P4DP_GET_NEXT
static inline p4d_t * p4dp_get_next(struct mm_struct *mm, p4d_t *p4dp, unsigned long addr) 
{
	return p4dp + 1;
}
#endif

#ifndef	 __ARCH_HAS_PGDP_GET_NEXT
static inline pgd_t * pgdp_get_next(struct mm_struct *mm, pgd_t *pgdp, unsigned long addr)
{
	return pgdp + 1;
}
#endif


#ifndef __HAVE_ARCH_NO_P4D_PGTABLE
static inline int no_p4d_and_lower_pgtable(pgd_t pgd) 
{
	return pgd_none(pgd);
}
#endif

#ifndef __HAVE_ARCH_NO_PUD_PGTABLE
static inline int no_pud_and_lower_pgtable(p4d_t p4d) 
{
	return p4d_none(p4d);
}
#endif

#ifndef __HAVE_ARCH_NO_PMD_PGTABLE
static inline int no_pmd_and_lower_pgtable(pud_t pud) 
{
	return pud_none(pud);
}
#endif

#ifndef __HAVE_ARCH_NO_PTE_PGTABLE
static inline int no_pte_pgtable(pmd_t pmd) 
{
	return pmd_none(pmd);
}
#endif

#ifndef __HAVE_ARCH_NO_PGD_HUGE_PAGE
static inline int no_pgd_huge_page(pgd_t pgd) 
{
	return 1; 	/* most arch don't have pgd page support */
}
#endif

#ifndef __HAVE_ARCH_NO_P4D_HUGE_PAGE
static inline int no_p4d_huge_page(p4d_t p4d) 
{
	return 1;	/* most arch don't have p4d page support */
}
#endif

#ifndef __HAVE_ARCH_NO_PUD_HUGE_PAGE
static inline int no_pud_huge_page(pud_t pud) 
{
	return pud_none(pud);
}
#endif

#ifndef __HAVE_ARCH_NO_PMD_HUGE_PAGE
static inline int no_pmd_huge_page(pmd_t pmd) 
{
	return pmd_none(pmd);
}
#endif

#ifndef __HAVE_ARCH_NO_PGD_HUGE_AND_P4D_PGTABLE
static inline int no_pgd_huge_and_p4d_pgtable(pgd_t pgd) 
{
	return no_pgd_huge_page(pgd) && no_p4d_and_lower_pgtable(pgd);
}
#endif

#ifndef __HAVE_ARCH_NO_P4D_HUGE_AND_PUD_PGTABLE
static inline int no_p4d_huge_and_pud_pgtable(p4d_t p4d) 
{
	return no_p4d_huge_page(p4d) && no_pud_and_lower_pgtable(p4d);
}
#endif

#ifndef __HAVE_ARCH_NO_PUD_HUGE_AND_PMD_PGTABLE
static inline int no_pud_huge_and_pmd_pgtable(pud_t pud) 
{
	return no_pud_huge_page(pud) && no_pmd_and_lower_pgtable(pud);
}
#endif

#ifndef __HAVE_ARCH_NO_PMD_HUGE_AND_PTE_PGTABLE
static inline int no_pmd_huge_and_pte_pgtable(pmd_t pmd) 
{
	return no_pmd_huge_page(pmd) && no_pte_pgtable(pmd);
}
#endif

#ifndef __ARCH_HAS_PGD_NEXT_LEVEL_NOT_ACCESSIBLE
static inline int pgd_next_level_not_accessible(pgd_t *pgd) 
{
	return pgd_none_or_clear_bad(pgd);
}
#endif

#ifndef __ARCH_HAS_P4D_NEXT_LEVEL_NOT_ACCESSIBLE
static inline int p4d_next_level_not_accessible(p4d_t *p4d) 
{
	return p4d_none_or_clear_bad(p4d);
}
#endif

#ifndef __ARCH_HAS_PUD_NEXT_LEVEL_NOT_ACCESSIBLE
static inline int pud_next_level_not_accessible(pud_t *pud) 
{
	return pud_none_or_clear_bad(pud);
}
#endif

#ifndef __ARCH_HAS_PMD_NEXT_LEVEL_NOT_ACCESSIBLE
static inline int pmd_next_level_not_accessible(pmd_t *pmd) 
{
	return pmd_none_or_trans_huge_or_clear_bad(pmd);
}
#endif

#ifndef __HAVE_ARCH_MK_P4D_ACCESSSIBLE
inline void pgd_mk_p4d_accessible(struct mm_struct *mm, pgd_t *pgd, unsigned long addr, p4d_t *p4d);
#endif /* __HAVE_ARCH_MK_PTE_ACCESSSIBLE  */

#ifndef __HAVE_ARCH_MK_PUD_ACCESSSIBLE
inline void p4d_mk_pud_accessible(struct mm_struct *mm, p4d_t *p4d, unsigned long addr, pud_t *pud);
#endif /* __HAVE_ARCH_MK_PUD_ACCESSSIBLE  */

#ifndef __HAVE_ARCH_MK_PMD_ACCESSSIBLE
inline void pud_mk_pmd_accessible(struct mm_struct *mm, pud_t *pud, unsigned long addr, pmd_t *pmd);
#endif /* __HAVE_ARCH_MK_PMD_ACCESSSIBLE  */

#ifndef __HAVE_ARCH_MK_PTE_ACCESSSIBLE
inline void pmd_mk_pte_accessible(struct mm_struct *mm, pmd_t *pmd, unsigned long addr, struct page *pte);
#endif /* __HAVE_ARCH_MK_PTE_ACCESSSIBLE  */

#ifndef __HAVE_ARCH_MK_PTE_ACCESSSIBLE_KERNEL
inline void pmd_mk_pte_accessible_kernel(struct mm_struct *mm, pmd_t *pmd, unsigned long addr, pte_t *pte);
#endif /* __HAVE_ARCH_MK_PTE_ACCESSSIBLE_KERNEL  */


int __pte_alloc(struct mm_struct *mm, pmd_t *pmd, unsigned long addr);
int __pte_alloc_kernel(pmd_t *pmd, unsigned long addr);

#endif /* _LINUX_PGTABLE_ENHANCED_H */
