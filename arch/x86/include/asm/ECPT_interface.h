#ifndef _ASM_X86_ECPT_INTERFACE_H
#define _ASM_X86_ECPT_INTERFACE_H

#include <asm/ECPT.h>

/**
 * @brief index on compacted pte
 * 
 * @param addr 
 * @return unsigned long index on compacted pte
 */

static inline unsigned long ecpt_pte_index(unsigned long addr) 
{
	return (addr >> PAGE_SHIFT_4KB) & (ECPT_CLUSTER_FACTOR - 1);
}

static inline unsigned long ecpt_pmd_index(unsigned long addr) 
{
	return (addr >> PAGE_SHIFT_2MB) & (ECPT_CLUSTER_FACTOR - 1);
}

static inline unsigned long ecpt_pud_index(unsigned long addr)
{
	return (addr >> PAGE_SHIFT_1GB) & (ECPT_CLUSTER_FACTOR - 1);
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

static inline ecpt_entry_t* get_ecpt_entry_from_ptep(pte_t *ptep, unsigned long addr) 
{	
	/**
	 * start_ptep is a pointer to uint64[ECPT_CLUSTER_FACTOR]
	 * The pointer type tweaking is necessary to avoid compiler warning
	 * because container_of expects start_ptep to be the same type with &entry->pte
	 */
	uint64_t (*start_ptep)[ECPT_CLUSTER_FACTOR] = 
				((void *) ptep - ecpt_pte_index(addr) * sizeof(uint64_t));
	return container_of(start_ptep, struct ecpt_entry, pte);
}

static inline ecpt_entry_t* get_ecpt_entry_from_pmdp(pmd_t *pmdp, unsigned long addr) 
{
	uint64_t (*start_ptep)[ECPT_CLUSTER_FACTOR] = 
				((void *) pmdp - ecpt_pmd_index(addr) * sizeof(uint64_t));
	return container_of(start_ptep, struct ecpt_entry, pte);
}

static inline ecpt_entry_t* get_ecpt_entry_from_pudp(pud_t *pudp, unsigned long addr) 
{
	uint64_t (*start_ptep)[ECPT_CLUSTER_FACTOR] = 
				((void *) pudp - ecpt_pud_index(addr) * sizeof(uint64_t));
	return container_of(start_ptep, struct ecpt_entry, pte);
}

/* Keep all fields of newpte except the vpn
	Keep only vpn field from the oldpte
 */
static inline void ecpt_entry_set_pte_helper(uint64_t *oldptep, uint64_t newpte) {
	WRITE_ONCE(*oldptep, 
		PTE_WITH_VPN_CLEARED(newpte) | CLEAR_PTE_BUT_NOT_VPN(*oldptep));
}

static inline void ecpt_entry_set_pte(ecpt_entry_t * e, pte_t pte, unsigned long addr) 
{
	ecpt_entry_set_pte_helper(&e->pte[ecpt_pte_index(addr)], pte.pte);
}

static inline void ecpt_entry_set_pmd(ecpt_entry_t * e, pte_t pte, unsigned long addr) 
{
	ecpt_entry_set_pte_helper(&e->pte[ecpt_pmd_index(addr)], pte.pte);
}

static inline void ecpt_entry_set_pud(ecpt_entry_t * e, pte_t pte, unsigned long addr) 
{
	ecpt_entry_set_pte_helper(&e->pte[ecpt_pud_index(addr)], pte.pte);
}

static inline void ecpt_entry_set_pte_with_pointer
	(ecpt_entry_t * e, pte_t pte, uint64_t * ptep, unsigned long addr) 
{
	ecpt_entry_set_pte_helper(ptep, pte.pte);
}

static inline int ecpt_pte_none(pte_t pte) {
#ifdef PTE_VPN_MASK
	return (pte.pte & ~(_PAGE_KNL_ERRATUM_MASK | PTE_VPN_MASK))  == 0;
#else
	return (pte.pte & ~(_PAGE_KNL_ERRATUM_MASK))  == 0;
#endif
}

static inline int ecpt_pmd_none(pmd_t pmd) {
#ifdef PTE_VPN_MASK
	return (pmd.pmd & ~(_PAGE_KNL_ERRATUM_MASK | PTE_VPN_MASK))  == 0;
#else
	return (pmd.pmd & ~(_PAGE_KNL_ERRATUM_MASK))  == 0;
#endif
}

static inline int ecpt_pud_none(pud_t pud) {
#ifdef PTE_VPN_MASK
	return (pud.pud & ~(_PAGE_KNL_ERRATUM_MASK | PTE_VPN_MASK))  == 0;
#else
	return (pud.pud & ~(_PAGE_KNL_ERRATUM_MASK))  == 0;
#endif
}

static inline uint64_t ecpt_entry_get_vpn(ecpt_entry_t * e) 
{
	uint64_t vpn = 0;
	uint16_t i = 0;
	for (; i < ECPT_CLUSTER_FACTOR && i < PTE_IDX_FOR_COUNT; i++) {
		vpn |= GET_PARTIAL_VPN_SHIFTED(e->pte[i], i);
	}
	return vpn;
}

uint64_t * get_ptep_with_gran(struct ecpt_entry *entry, unsigned long vaddr, Granularity g);
int ecpt_entry_present(ecpt_entry_t * entry, unsigned long addr, Granularity g);
inline bool empty_entry(ecpt_entry_t * e);

#define REP0(X)
#define REP1(X) X
#define REP2(X) REP1(X) X
#define REP3(X) REP2(X) X
#define REP4(X) REP3(X) X
#define REP5(X) REP4(X) X
#define REP6(X) REP5(X) X
#define REP7(X) REP6(X) X
#define REP8(X) REP7(X) X
#define REP9(X) REP8(X) X
#define REP10(X) REP9(X) X

#define PTE_0(e) (e)->pte[0]
#define PTE_1(e) PTE_0(e), (e)->pte[1]
#define PTE_2(e) PTE_1(e), (e)->pte[2]
#define PTE_3(e) PTE_2(e), (e)->pte[3]
#define PTE_4(e) PTE_3(e), (e)->pte[4]
#define PTE_5(e) PTE_4(e), (e)->pte[5]
#define PTE_6(e) PTE_5(e), (e)->pte[6]
#define PTE_7(e) PTE_6(e), (e)->pte[7]


#define PTE_ARRAY_FMT REP8("%016llx ")
#define PTE_ARRAY_PRINT(e) PTE_7(e)

#define PRINT_ECPT_ENTRY_BASE(e, func) \
	do { \
    	func("entry at %llx  {.vpn=%llx .pte={" PTE_ARRAY_FMT "}}\n",\
			(uint64_t) e, ecpt_entry_get_vpn(e), PTE_ARRAY_PRINT(e) \
		); \
  	} while (0)

#define PRINT_ECPT_ENTRY_VERBOSE(e) PRINT_ECPT_ENTRY_BASE(e, pr_info_verbose)

/*  */
static inline spinlock_t *pte_lockptr(struct mm_struct *mm, pmd_t *pmd)
{
	return &mm->page_table_lock;
}
#define pte_lockptr pte_lockptr

static inline spinlock_t *ecpt_pmd_lockptr(struct mm_struct *mm, pmd_t *pmd)
{
	return &mm->page_table_lock;
}
#define pmd_lockptr ecpt_pmd_lockptr

static inline pte_t * pte_offset_ecpt(struct mm_struct *mm, unsigned long addr) {
	Granularity g = page_4KB;
	// uint32_t way = 0;
	// ecpt_entry_t * e = get_hpt_entry(mm->map_desc, addr, &g, &way);
	ecpt_entry_t * e = ecpt_search_fit(mm->map_desc, addr, g);
	if (e) 
		return pte_offset_from_ecpt_entry(e, addr);
	else 
		return (pte_t *) &pte_default.pte;
}

static inline pmd_t * pmd_offset_ecpt(struct mm_struct *mm, unsigned long addr) {
	Granularity g = page_2MB;
	ecpt_entry_t * e = ecpt_search_fit(mm->map_desc, addr, g);
	if (e) 
		return pmd_offset_from_ecpt_entry(e, addr);
	else 
		return (pmd_t *) &pte_default.pte;
}

static inline pud_t * pud_offset_ecpt(struct mm_struct *mm, unsigned long addr) {
	Granularity g = page_1GB;
	ecpt_entry_t * e = ecpt_search_fit(mm->map_desc, addr, g);
	if (e) 
		return pud_offset_from_ecpt_entry(e, addr);
	else 
		return (pud_t *) &pte_default.pte;
}

/* ECPT has no support for P4D level page right now */
static inline p4d_t * p4d_offset_ecpt(struct mm_struct *mm, unsigned long addr) {
	return (p4d_t *) &pte_default.pte;
}

/* ECPT has no support for PGD level page right now */
static inline pgd_t * pgd_offset_ecpt(struct mm_struct *mm, unsigned long addr) {
	return (pgd_t *) &pte_default.pte;
}

/* TODO replace with pte_offset_map_with_mm */
/* override definition in linux/pgtable.h */
static inline pte_t *pte_offset_kernel(void *mm, unsigned long address)
{	
	WARN(1, "obslete interface!\n");
	return pte_offset_ecpt((struct mm_struct *)mm, address);
}

#define pte_offset_kernel pte_offset_kernel

#define __ARCH_HAS_PTE_OFFSET_MAP_WITH_MM
#define pte_offset_map_with_mm(mm, pmd, addr) pte_offset_ecpt((mm), (addr))

#define __ARCH_HAS_PMD_OFFSET_MAP_WITH_MM
#define pmd_offset_map_with_mm(mm, pud, addr) pmd_offset_ecpt((mm), (addr))

#define __ARCH_HAS_PUD_OFFSET_MAP_WITH_MM
#define pud_offset_map_with_mm(mm, p4d, addr) pud_offset_ecpt((mm), (addr))

#define __ARCH_HAS_P4D_OFFSET_MAP_WITH_MM
#define p4d_offset_map_with_mm(mm, pgd, addr) p4d_offset_ecpt((mm), (addr))

#define __ARCH_HAS_PGD_OFFSET_MAP_WITH_MM
#define pgd_offset_map_with_mm(mm, addr) pgd_offset_ecpt((mm), (addr))


#define __ARCH_HAS_PTEP_GET_NEXT
static inline pte_t * ptep_get_next(struct mm_struct *mm, pte_t * ptep, unsigned long addr) {
	if (ptep == &pte_default) {
		return &pte_default;
	}
	
	if (ecpt_pte_index(addr) < ECPT_CLUSTER_FACTOR - 1) {
		return ptep + 1;
	} else {
		return pte_offset_ecpt(mm, addr + PAGE_SIZE);
	}
}

#define __ARCH_HAS_PMDP_GET_NEXT
static inline pmd_t * pmdp_get_next(struct mm_struct *mm, pmd_t *pmdp, unsigned long addr) {
	if (pmdp == (pmd_t *) &pte_default) {
		return (pmd_t *) &pte_default;
	}

	if (ecpt_pmd_index(addr) < ECPT_CLUSTER_FACTOR - 1) {
		return pmdp + 1;
	} else {
		return pmd_offset_ecpt(mm, addr + PAGE_SIZE_2MB);
	}
}

#define __ARCH_HAS_PUDP_GET_NEXT
static inline pud_t * pudp_get_next(struct mm_struct *mm, pud_t *pudp, unsigned long addr) {
	if (pudp == (pud_t *) &pte_default) {
		return (pud_t *) &pte_default;
	}

	if (ecpt_pud_index(addr) < ECPT_CLUSTER_FACTOR - 1) {
		return pudp + 1;
	} else {
		return pud_offset_ecpt(mm, addr + PAGE_SIZE_1GB);
	}
}

#define __ARCH_HAS_P4DP_GET_NEXT
/* ECPT doesn't support p4dp */
static inline p4d_t * p4dp_get_next(struct mm_struct *mm, p4d_t *p4dp, unsigned long addr) 
{
	return (p4d_t *) &pte_default;
}

#define __ARCH_HAS_PGDP_GET_NEXT
/* ECPT doesn't support pgdp page */
static inline pgd_t * pgdp_get_next(struct mm_struct *mm, pgd_t *pgdp, unsigned long addr) 
{
	return (pgd_t *) &pte_default;
}

#define __ARCH_HAS_PGD_NEXT_LEVEL_NOT_ACCESSIBLE
inline int pgd_next_level_not_accessible(pgd_t *pgd);

#define __ARCH_HAS_P4D_NEXT_LEVEL_NOT_ACCESSIBLE
inline int p4d_next_level_not_accessible(p4d_t *p4d);

#define __ARCH_HAS_PUD_NEXT_LEVEL_NOT_ACCESSIBLE
inline int pud_next_level_not_accessible(pud_t *pud);

#define __ARCH_HAS_PMD_NEXT_LEVEL_NOT_ACCESSIBLE
/* see pmd_none_or_trans_huge_or_clear_bad for reference */
inline int pmd_next_level_not_accessible(pmd_t *pmd);

#define __HAVE_ARCH_MK_P4D_ACCESSSIBLE
static inline void pgd_mk_p4d_accessible(struct mm_struct *mm, pgd_t *pgd, 
	unsigned long addr, p4d_t *p4d) 
{
	/* nothing to do for ECPT */
}

#define __HAVE_ARCH_MK_PUD_ACCESSSIBLE
static inline void p4d_mk_pud_accessible(struct mm_struct *mm, p4d_t *p4d,
	unsigned long addr, pud_t *pud) 
{
	/* nothing to do for ECPT */
}

#define __HAVE_ARCH_MK_PMD_ACCESSSIBLE
inline void pud_mk_pmd_accessible(struct mm_struct *mm, pud_t *pud, 
	unsigned long addr, pmd_t *pmd);

#define __HAVE_ARCH_MK_PTE_ACCESSSIBLE
inline void pmd_mk_pte_accessible(struct mm_struct *mm, pmd_t *pmd, 
	unsigned long addr, struct page *pte);

#define __HAVE_ARCH_MK_PTE_ACCESSSIBLE_KERNEL
inline void pmd_mk_pte_accessible_kernel(struct mm_struct *mm, pmd_t *pmd, 
	unsigned long addr, pte_t *pte);

#define __HAVE_ARCH_NO_PTE_PGTABLE
inline int no_pte_pgtable(pmd_t *pmd);

// #define pte_unmap_unlock(pte, ptl)	do {} while (0)

#define pte_alloc(mm, pmd) (NULL)
#define __ARCH_HAS_PTE_ALLOC

#define __HAVE_ARCH_PTE_FREE
/**
 * pte_free - free PTE-level user page table page. 
 * ECPT should not be expected to execute this.
 * @mm: the mm_struct of the current context
 * @pte_page: the `struct page` representing the page table
 */
static inline void pte_free(struct mm_struct *mm, struct page *pte_page)
{
	if (pte_page != pte_page_default) {
		WARN(1, "free page at %llx\n", (uint64_t) pte_page);
	}
}

#define __ARCH_HAS_MM_INC_NR_PTES
static inline void mm_inc_nr_ptes(struct mm_struct *mm)
{
	/* ECPT doesn't track pagetable bytes through this */
}

#define __ARCH_HAS_MM_DEC_NR_PTES
static inline void mm_dec_nr_ptes(struct mm_struct *mm)
{
	/* ECPT doesn't track pagetable bytes through this */
}

#define __ARCH_HAS_MM_INC_NR_PMDS
static inline void mm_inc_nr_pmds(struct mm_struct *mm)
{
	/* ECPT do nothing */
}

#define __ARCH_HAS_MM_DEC_NR_PMDS
static inline void mm_dec_nr_pmds(struct mm_struct *mm)
{
	/* ECPT do nothing */
}

#define __ARCH_HAS_MM_INC_NR_PUDS
static inline void mm_inc_nr_puds(struct mm_struct *mm)
{
	/* ECPT do nothing */
}

#define __ARCH_HAS_MM_DEC_NR_PUDS
static inline void mm_dec_nr_puds(struct mm_struct *mm)
{
	/* ECPT do nothing */
}

int ecpt_set_pte_at(struct mm_struct *mm, unsigned long addr,
			      pte_t *ptep, pte_t pte);

void ecpt_set_pmd_at(struct mm_struct *mm, unsigned long addr,
			      pmd_t *pmdp, pmd_t pmd);

void ecpt_set_pud_at(struct mm_struct *mm, unsigned long addr,
			      pud_t *pudp, pud_t pud);

pte_t ecpt_native_ptep_get_and_clear(struct mm_struct *mm,
					unsigned long addr, pte_t *ptep);


pmd_t ecpt_native_pmdp_get_and_clear(struct mm_struct *mm, unsigned long addr,
				     pmd_t *pmdp);

pud_t ecpt_native_pudp_get_and_clear(struct mm_struct *mm, unsigned long addr,
				     pud_t *pudp);

#define __HAVE_ARCH_PMD_TRANS_UNSTABLE
inline int pmd_trans_unstable(pmd_t *pmd);

#define __HAVE_ARCH_PUD_TRANS_UNSTABLE
inline int pud_trans_unstable(pud_t *pud);

#define __HAVE_ARCH_PMD_OFF_SAFE
static inline pmd_t *pmd_off_safe(struct mm_struct *mm, unsigned long va)
{
	return pmd_offset_ecpt(mm, va);
}

#define __HAVE_ARCH_PGTABLE_DEPOSIT
void pgtable_trans_huge_deposit(struct mm_struct *mm, pmd_t *pmdp,
				pgtable_t pgtable);

#define __HAVE_ARCH_PGTABLE_WITHDRAW
pgtable_t pgtable_trans_huge_withdraw(struct mm_struct *mm, pmd_t *pmdp);

#endif /* _ASM_X86_ECPT_INTERFACE_H */