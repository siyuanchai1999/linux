#ifndef _LINUX_PGTABLE_ENHANCED_H
#define _LINUX_PGTABLE_ENHANCED_H

#include <linux/pgtable.h>

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
static inline pdg_t * pgdp_get_next(struct mm_struct *mm, pdg_t *pgdp, unsigned long addr) 
{
	return pgdp + 1;
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
	return pmd_none_or_trans_huge_or_clear_bad(pmd)
}
#endif

#ifndef __HAVE_ARCH_MK_P4D_ACCESSSIBLE
static inline void pgd_mk_p4d_accessible(struct mm_struct *mm, pgd_t *pgd, unsigned long addr, p4d_t *p4d)
{
	pgd_populate(mm, pgd, p4d);
}
#endif /* __HAVE_ARCH_MK_PTE_ACCESSSIBLE  */

#ifndef __HAVE_ARCH_MK_PUD_ACCESSSIBLE
static inline void p4d_mk_pud_accessible(struct mm_struct *mm, p4d_t *p4d, unsigned long addr, pud_t *pud)
{
	p4d_populate(mm, p4d, pud);
}
#endif /* __HAVE_ARCH_MK_PUD_ACCESSSIBLE  */

#ifndef __HAVE_ARCH_MK_PMD_ACCESSSIBLE
static inline void pud_mk_pmd_accessible(struct mm_struct *mm, pud_t *pud, 
	unsigned long addr, pmd_t *pmd)
{
	pud_populate(mm, pud, pmd);
}
#endif /* __HAVE_ARCH_MK_PMD_ACCESSSIBLE  */

#ifndef __HAVE_ARCH_MK_PTE_ACCESSSIBLE
static inline void pmd_mk_pte_accessible(struct mm_struct *mm, pmd_t *pmd, 
	unsigned long addr, struct page *pte)
{
	pmd_populate(mm, pmd, pte);
}
#endif /* __HAVE_ARCH_MK_PTE_ACCESSSIBLE  */

#ifndef __HAVE_ARCH_MK_PTE_ACCESSSIBLE_KERNEL
static inline void pmd_mk_pte_accessible_kernel(struct mm_struct *mm, pmd_t *pmd, 
	unsigned long addr, pte_t *pte)
{
	pmd_populate_kernel(mm, pmd, pte);
}
#endif /* __HAVE_ARCH_MK_PTE_ACCESSSIBLE  */


int __pte_alloc(struct mm_struct *mm, pmd_t *pmd, unsigned long addr);
int __pte_alloc_kernel(pmd_t *pmd, unsigned long addr);

#endif /* _LINUX_PGTABLE_ENHANCED_H */
