#ifndef _ASM_X86_ECPT_H
#define _ASM_X86_ECPT_H

#include <asm/ECPT_defs.h>
#include <linux/types.h>

#define pgprot_encrypted(prot)	__pgprot(__sme_set(pgprot_val(prot)))
#define pgprot_decrypted(prot)	__pgprot(__sme_clr(pgprot_val(prot)))

#ifndef __ASSEMBLY__
#include <asm/processor.h>
#include <linux/bitops.h>
#include <linux/threads.h>
#include <asm/fixmap.h>
#endif

#define ECPT_INSERT_MAX_TRIES 128

typedef unsigned long	ecpt_pgprotval_t;
typedef struct ecpt_pgprot { ecpt_pgprotval_t pgprot; } ecpt_pgprot_t;

#define ecpt_pgprot_val(x)		((x).pgprot)
#define __ecpt_pgprot(x)		((ecpt_pgprot_t) { (x) } )
#define __ecpt_pg(x)					__ecpt_pgprot(x)

typedef struct ecpt_entry{
	uint64_t pte[ECPT_CLUSTER_FACTOR];
} ecpt_entry_t;

typedef struct ECPT_desc {
	uint64_t table[ECPT_MAX_WAY];
	struct mm_struct * mm;
	struct list_head lru; /* call it lru which is the same name as page->lru as it was used by radix */
	uint32_t occupied[ECPT_MAX_WAY];

	/* This should not be neccessary but let's save implementation pain right now */
	uint32_t rehash_ptr[ECPT_MAX_WAY];
} ECPT_desc_t;

typedef enum {
	unknown,
	page_4KB,
	page_2MB,
	page_1GB
} Granularity ; 

enum search_entry_status {
	ENTRY_NOT_FOUND,
	ENTRY_MATCHED,
	ENTRY_EMPTY,
	ENTRY_OCCUPIED
};

// enum Granularity {}; 

extern uint32_t way_to_crN[ECPT_MAX_WAY];

/* defined in head64.S */
extern ECPT_desc_t ecpt_desc;

extern pte_t pte_default;

void load_ECPT_desc(ECPT_desc_t * ecpt);

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
// ecpt_entry_t * ecpt_search_fit_entry(ECPT_desc_t * ecpt, uint64_t vaddr, bool is_write,
	// Granularity* gran, enum search_entry_status * status);

void print_ecpt(ECPT_desc_t * ecpt, bool kernel_table_detail,
 				bool user_table_detail, bool print_entry);
inline void check_ecpt_user_detail(ECPT_desc_t * ecpt, bool print_entry);
inline void check_ecpt_kernel_detail(ECPT_desc_t * ecpt, bool print_entry);


int ecpt_rehash_way(ECPT_desc_t *ecpt, uint32_t way);

#endif /* _ASM_X86_ECPT_HASH_H */
