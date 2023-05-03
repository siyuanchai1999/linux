#ifndef _LINUX_PGTABLE_ENHANCED_H
#define _LINUX_PGTABLE_ENHANCED_H

#ifndef __ASSEMBLY__

#include <linux/pgtable.h>

#ifndef	 __ARCH_HAS_PTEP_GET_NEXT
inline pte_t * ptep_get_next(struct mm_struct *mm, pte_t * ptep, unsigned long addr);
#endif

#ifndef	 __ARCH_HAS_PTEP_GET_N_NEXT
inline pte_t * ptep_get_n_next(struct mm_struct *mm, pte_t * ptep, unsigned long addr, unsigned int n);
#endif

#ifndef	 __ARCH_HAS_PMDP_GET_NEXT
inline pmd_t * pmdp_get_next(struct mm_struct *mm, pmd_t *pmdp, unsigned long addr);
#endif

#ifndef	 __ARCH_HAS_PUDP_GET_NEXT
inline pud_t * pudp_get_next(struct mm_struct *mm, pud_t *pudp, unsigned long addr);
#endif

#ifndef	 __ARCH_HAS_P4DP_GET_NEXT
inline p4d_t * p4dp_get_next(struct mm_struct *mm, p4d_t *p4dp, unsigned long addr);
#endif

#ifndef	 __ARCH_HAS_PGDP_GET_NEXT
inline pgd_t * pgdp_get_next(struct mm_struct *mm, pgd_t *pgdp, unsigned long addr);
#endif

#ifndef __HAVE_ARCH_NO_P4D_PGTABLE
inline int no_p4d_and_lower_pgtable(pgd_t pgd);
#endif

#ifndef __HAVE_ARCH_NO_PUD_PGTABLE
inline int no_pud_and_lower_pgtable(p4d_t p4d);
#endif

#ifndef __HAVE_ARCH_NO_PMD_PGTABLE
inline int no_pmd_and_lower_pgtable(pud_t pud);
#endif

#ifndef __HAVE_ARCH_NO_PTE_PGTABLE
inline int no_pte_pgtable(pmd_t pmd);
#endif

#ifndef __HAVE_ARCH_NO_PGD_HUGE_PAGE
inline int no_pgd_huge_page(pgd_t pgd);
#endif

#ifndef __HAVE_ARCH_NO_P4D_HUGE_PAGE
inline int no_p4d_huge_page(p4d_t p4d);
#endif

#ifndef __HAVE_ARCH_NO_PUD_HUGE_PAGE
inline int no_pud_huge_page(pud_t pud);
#endif

#ifndef __HAVE_ARCH_NO_PMD_HUGE_PAGE
inline int no_pmd_huge_page(pmd_t pmd);
#endif

#ifndef __HAVE_ARCH_NO_PGD_HUGE_AND_P4D_PGTABLE
inline int no_pgd_huge_and_p4d_pgtable(pgd_t pgd);
#endif

#ifndef __HAVE_ARCH_NO_P4D_HUGE_AND_PUD_PGTABLE
inline int no_p4d_huge_and_pud_pgtable(p4d_t p4d);
#endif

#ifndef __HAVE_ARCH_NO_PUD_HUGE_AND_PMD_PGTABLE
inline int no_pud_huge_and_pmd_pgtable(pud_t pud);
#endif

#ifndef __HAVE_ARCH_NO_PMD_HUGE_AND_PTE_PGTABLE
inline int no_pmd_huge_and_pte_pgtable(pmd_t pmd);
#endif

#ifndef __ARCH_HAS_PGD_NEXT_LEVEL_NOT_ACCESSIBLE
inline int pgd_next_level_not_accessible(pgd_t *pgd);
#endif

#ifndef __ARCH_HAS_P4D_NEXT_LEVEL_NOT_ACCESSIBLE
inline int p4d_next_level_not_accessible(p4d_t *p4d);
#endif

#ifndef __ARCH_HAS_PUD_NEXT_LEVEL_NOT_ACCESSIBLE
inline int pud_next_level_not_accessible(pud_t *pud);
#endif

#ifndef __ARCH_HAS_PMD_NEXT_LEVEL_NOT_ACCESSIBLE
inline int pmd_next_level_not_accessible(pmd_t *pmd);
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

#ifndef	 __ARCH_HAS_PTE_OFFSET_MAP_WITH_MM
inline pte_t *pte_offset_map_with_mm(struct mm_struct *mm, pmd_t *pmd, unsigned long addr);
#endif

#ifndef	 __ARCH_HAS_PMD_OFFSET_MAP_WITH_MM
inline pmd_t *pmd_offset_map_with_mm(struct mm_struct *mm, pud_t *pud, unsigned long addr);
#endif

#ifndef	 __ARCH_HAS_PUD_OFFSET_MAP_WITH_MM
inline pud_t *pud_offset_map_with_mm(struct mm_struct *mm, p4d_t *p4d, unsigned long addr);
#endif

#ifndef	 __ARCH_HAS_P4D_OFFSET_MAP_WITH_MM
inline p4d_t *p4d_offset_map_with_mm(struct mm_struct *mm, pgd_t *pgd, unsigned long addr);
#endif

#ifndef	 __ARCH_HAS_PGD_OFFSET_MAP_WITH_MM
inline pgd_t *pgd_offset_map_with_mm(struct mm_struct *mm, unsigned long addr);
#endif


int __pte_alloc(struct mm_struct *mm, pmd_t *pmd, unsigned long addr);
int __pte_alloc_kernel(pmd_t *pmd, unsigned long addr);

#endif /* !__ASSEMBLY__ */

spinlock_t *pte_lockptr_with_addr(struct mm_struct *mm, pmd_t *pmd, unsigned long addr);

#endif /* _LINUX_PGTABLE_ENHANCED_H */
