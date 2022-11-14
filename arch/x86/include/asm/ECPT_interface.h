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