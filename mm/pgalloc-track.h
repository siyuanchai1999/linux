/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_PGALLOC_TRACK_H
#define _LINUX_PGALLOC_TRACK_H

#if defined(CONFIG_MMU)

#ifdef CONFIG_PGTABLE_OP_GENERALIZABLE
#include <linux/pgtable_enhanced.h>
static inline p4d_t *p4d_alloc_track(struct mm_struct *mm, pgd_t *pgd,
				     unsigned long address,
				     pgtbl_mod_mask *mod_mask)
{
	if (unlikely(no_pgd_huge_and_p4d_pgtable(pgd))) {
		if (__p4d_alloc(mm, pgd, address))
			return NULL;
		*mod_mask |= PGTBL_PGD_MODIFIED;
	}

	return p4d_offset_map_with_mm(mm, pgd, address);
}

static inline pud_t *pud_alloc_track(struct mm_struct *mm, p4d_t *p4d,
				     unsigned long address,
				     pgtbl_mod_mask *mod_mask)
{
	if (unlikely(no_p4d_huge_and_pud_pgtable(p4d))) {
		if (__pud_alloc(mm, p4d, address))
			return NULL;
		*mod_mask |= PGTBL_P4D_MODIFIED;
	}

	return pud_offset_map_with_mm(mm, p4d, address);
}

static inline pmd_t *pmd_alloc_track(struct mm_struct *mm, pud_t *pud,
				     unsigned long address,
				     pgtbl_mod_mask *mod_mask)
{
	if (unlikely(no_pud_huge_and_pmd_pgtable(pud))) {
		if (__pmd_alloc(mm, pud, address))
			return NULL;
		*mod_mask |= PGTBL_PUD_MODIFIED;
	}

	return pmd_offset_map_with_mm(mm, pud, address);
}
#else
static inline p4d_t *p4d_alloc_track(struct mm_struct *mm, pgd_t *pgd,
				     unsigned long address,
				     pgtbl_mod_mask *mod_mask)
{
	if (unlikely(pgd_none(*pgd))) {
		if (__p4d_alloc(mm, pgd, address))
			return NULL;
		*mod_mask |= PGTBL_PGD_MODIFIED;
	}

	return p4d_offset(pgd, address);
}

static inline pud_t *pud_alloc_track(struct mm_struct *mm, p4d_t *p4d,
				     unsigned long address,
				     pgtbl_mod_mask *mod_mask)
{
	if (unlikely(p4d_none(*p4d))) {
		if (__pud_alloc(mm, p4d, address))
			return NULL;
		*mod_mask |= PGTBL_P4D_MODIFIED;
	}

	return pud_offset(p4d, address);
}

static inline pmd_t *pmd_alloc_track(struct mm_struct *mm, pud_t *pud,
				     unsigned long address,
				     pgtbl_mod_mask *mod_mask)
{
	if (unlikely(pud_none(*pud))) {
		if (__pmd_alloc(mm, pud, address))
			return NULL;
		*mod_mask |= PGTBL_PUD_MODIFIED;
	}

	return pmd_offset(pud, address);
}
#endif
#endif /* CONFIG_MMU */

#ifdef CONFIG_PGTABLE_OP_GENERALIZABLE

static inline pte_t *pte_alloc_kernel_track(pmd_t *pmd,
				     unsigned long address,
				     pgtbl_mod_mask *mod_mask)
{
	if (unlikely(no_pmd_huge_and_pte_pgtable(pmd))) {
		if (__pte_alloc_kernel(pmd, address))
			return NULL;
		*mod_mask |= PGTBL_PMD_MODIFIED;
	}

	return pte_offset_map_with_mm(&init_mm, pmd, address);
}

#else
#define pte_alloc_kernel_track(pmd, address, mask)			\
	((unlikely(pmd_none(*(pmd))) &&					\
	  (__pte_alloc_kernel(pmd) || ({*(mask)|=PGTBL_PMD_MODIFIED;0;})))?\
		NULL: pte_offset_kernel(pmd, address))
#endif

#endif /* _LINUX_PGALLOC_TRACK_H */
