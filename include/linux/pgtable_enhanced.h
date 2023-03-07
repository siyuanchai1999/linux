#ifndef _LINUX_PGTABLE_ENHANCED_H
#define _LINUX_PGTABLE_ENHANCED_H

#include <linux/pgtable.h>

#ifndef	 __ARCH_HAS_PTE_OFFSET_MAP_WITH_MM
#define pte_offset_map_with_mm(mm, dir, addr) pte_offset_kernel((dir), (addr))
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

#endif /* _LINUX_PGTABLE_ENHANCED_H */
