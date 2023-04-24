#include <linux/mm.h>
#include <asm/pgalloc.h>
#include <linux/pgtable_enhanced.h>

#ifndef __HAVE_ARCH_MK_P4D_ACCESSSIBLE
inline void pgd_mk_p4d_accessible(struct mm_struct *mm, pgd_t *pgd, unsigned long addr, p4d_t *p4d)
{
	pgd_populate(mm, pgd, p4d);
}
#endif /* __HAVE_ARCH_MK_PTE_ACCESSSIBLE  */

#ifndef __HAVE_ARCH_MK_PUD_ACCESSSIBLE
inline void p4d_mk_pud_accessible(struct mm_struct *mm, p4d_t *p4d, unsigned long addr, pud_t *pud)
{
	p4d_populate(mm, p4d, pud);
}
#endif /* __HAVE_ARCH_MK_PUD_ACCESSSIBLE  */

#ifndef __HAVE_ARCH_MK_PMD_ACCESSSIBLE
inline void pud_mk_pmd_accessible(struct mm_struct *mm, pud_t *pud,
	unsigned long addr, pmd_t *pmd)
{
	pud_populate(mm, pud, pmd);
}
#endif /* __HAVE_ARCH_MK_PMD_ACCESSSIBLE  */

#ifndef __HAVE_ARCH_MK_PTE_ACCESSSIBLE
inline void pmd_mk_pte_accessible(struct mm_struct *mm, pmd_t *pmd,
	unsigned long addr, struct page *pte)
{
	pmd_populate(mm, pmd, pte);
}
#endif /* __HAVE_ARCH_MK_PTE_ACCESSSIBLE  */

#ifndef __HAVE_ARCH_MK_PTE_ACCESSSIBLE_KERNEL
inline void pmd_mk_pte_accessible_kernel(struct mm_struct *mm, pmd_t *pmd,
	unsigned long addr, pte_t *pte)
{
	pmd_populate_kernel(mm, pmd, pte);
}
#endif /* __HAVE_ARCH_MK_PTE_ACCESSSIBLE_KERNEL  */
