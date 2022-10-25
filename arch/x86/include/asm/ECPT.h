#ifndef _ASM_X86_ECPT_H
#define _ASM_X86_ECPT_H

// #include <asm/page_types.h>
// #include <asm/page_64_types.h>
// #include <linux/mm_types.h>
// #include <linux/gfp.h>
// #include <linux/random.h>
// #include <asm/pgalloc.h>
// #include <linux/slab.h>


#include <asm/ecpt_types.h>
#include <linux/types.h>

#include <asm/ECPT_defs.h>

#define pgprot_encrypted(prot)	__pgprot(__sme_set(pgprot_val(prot)))
#define pgprot_decrypted(prot)	__pgprot(__sme_clr(pgprot_val(prot)))

#ifndef __ASSEMBLY__
// #include <asm/x86_init.h>
// #include <asm/pkru.h>
// #include <asm/fpu/api.h>
// #include <asm-generic/pgtable_uffd.h>
#include <asm/processor.h>
#include <linux/bitops.h>
#include <linux/threads.h>
#include <asm/fixmap.h>
#endif

static inline void native_set_ecpt_pud(ecpt_pud_t *pudp, ecpt_pud_t pud)
{
	WRITE_ONCE(*pudp, pud);
}

static inline int ecpt_pud_present(ecpt_pud_t pud)
{
	return ecpt_pud_flags(pud) & _PAGE_PRESENT;
}


static inline void native_set_ecpt_pmd(ecpt_pmd_t *pmdp, ecpt_pmd_t pmd)
{
	WRITE_ONCE(*pmdp, pmd);
}

static inline int ecpt_pmd_present(ecpt_pmd_t pmd)
{
	/*
	 * Checking for _PAGE_PSE is needed too because
	 * split_huge_page will temporarily clear the present bit (but
	 * the _PAGE_PSE flag will remain set at all times while the
	 * _PAGE_PRESENT bit is clear).
	 */
	return ecpt_pmd_flags(pmd) & (_PAGE_PRESENT | _PAGE_PROTNONE | _PAGE_PSE);
}


static inline void native_set_ecpt_pte(ecpt_pte_t *ptep, ecpt_pte_t pte)
{
	WRITE_ONCE(*ptep, pte);
}

static inline int ecpt_pte_present(ecpt_pte_t a)
{
	return ecpt_pte_flags(a) & (_PAGE_PRESENT | _PAGE_PROTNONE);
}

#define set_ecpt_pud(pudp, pud)		native_set_ecpt_pud(pudp, pud)
#define set_ecpt_pmd(pmdp, pmd)		native_set_ecpt_pmd(pmdp, pmd)
#define set_ecpt_pte(ptep, pte)		native_set_ecpt_pte(ptep, pte)

#define ecpt_pud_val(x)	native_ecpt_pud_val(x)
#define __ecpt_pud(x)	native_make_ecpt_pud(x)

#define ecpt_pmd_val(x)	native_ecpt_pmd_val(x)
#define __ecpt_pmd(x)	native_make_ecpt_pmd(x)

#define ecpt_pte_val(x)	native_ecpt_pte_val(x)
#define __ecpt_pte(x)	native_make_ecpt_pte(x)





#define ECPT_INSERT_MAX_TRIES 128

// typedef struct ecpt_meta_2M_ {
// 	uint64_t table_4K[ECPT_4K_WAY];
// 	uint64_t table[ECPT_2M_WAY];
// }	ecpt_meta_2M;

typedef struct ECPT_desc {
	uint64_t table[ECPT_TOTAL_WAY];
	struct mm_struct * mm;
	struct list_head lru; /* call it lru which is the same name as page->lru as it was used by radix */
	uint32_t occupied[ECPT_TOTAL_WAY];
} ECPT_desc_t;

typedef enum {
	unknown,
	page_4KB,
	page_2MB,
	page_1GB
} Granularity ; 
// enum Granularity {}; 

extern uint32_t way_to_crN[ECPT_MAX_WAY];

/* defined in head64.S */
extern ECPT_desc_t ecpt_desc;

extern pte_t pte_default;

void load_ECPT_desc(ECPT_desc_t * ecpt);
// void * map_desc_alloc_default(void);
 
// uint64_t gen_hash_32(uint32_t vpn, uint64_t size);
// int early_ecpt_insert(uint64_t cr3, uint64_t vaddr, uint64_t paddr, ecpt_pgprot_t prot, uint64_t kernel_start, uint64_t physaddr);
int early_ecpt_insert(ECPT_desc_t * ecpt, uint64_t vaddr, uint64_t paddr, ecpt_pgprot_t prot, uint64_t kernel_start, uint64_t physaddr);
int early_ecpt_invalidate(ECPT_desc_t * ecpt, uint64_t vaddr);

int ecpt_insert(ECPT_desc_t * ecpt, uint64_t vaddr, uint64_t paddr, ecpt_pgprot_t prot, Granularity gran);
int ecpt_mm_insert(struct mm_struct* mm, uint64_t vaddr, uint64_t paddr, ecpt_pgprot_t prot, Granularity gran);
int ecpt_mm_insert_range(
	struct mm_struct* mm, 
	uint64_t vaddr, 
	uint64_t vaddr_end,
	uint64_t paddr, 
	uint64_t paddr_end,
	ecpt_pgprot_t prot
);


int ecpt_invalidate(ECPT_desc_t * ecpt_desc, uint64_t vaddr, Granularity gran);
int ecpt_mm_invalidate(struct mm_struct* mm, uint64_t vaddr, Granularity gran);

/**
 * @brief 
 * 
 * @param ecpt 
 * @param vaddr 
 * @param gran if gran == unknown search for all entries, and update gran with real granularity
 * 				ow. only search in such granularity 
 * @return ecpt_entry_t 
 */
ecpt_entry_t ecpt_peek(ECPT_desc_t * ecpt, uint64_t vaddr, Granularity * gran);
ecpt_entry_t ecpt_mm_peek(struct mm_struct* mm, uint64_t vaddr, Granularity * gran);

int ecpt_update_prot(ECPT_desc_t * ecpt, uint64_t vaddr, ecpt_pgprot_t new_prot, Granularity gran);
int ecpt_mm_update_prot(struct mm_struct* mm, uint64_t vaddr, ecpt_pgprot_t new_prot, Granularity gran);

ecpt_entry_t * get_ecpt_entry_from_mm(struct mm_struct* mm, uint64_t vaddr, Granularity *g);
ecpt_entry_t * get_hpt_entry(ECPT_desc_t * ecpt, uint64_t vaddr, Granularity *g, uint32_t * way);
ecpt_entry_t * ecpt_search_fit(ECPT_desc_t * ecpt, uint64_t vaddr, Granularity gran);

void print_ecpt(ECPT_desc_t * ecpt, bool kernel_table_detail, bool user_table_detail);


#endif /* _ASM_X86_ECPT_HASH_H */
