#ifndef _ASM_X86_ECPT_H
#define _ASM_X86_ECPT_H

// #include <asm/page_types.h>
// #include <asm/page_64_types.h>
#include <asm/ecpt_types.h>
#include <linux/types.h>

#include <asm/ECPT_defs.h>

#define pgprot_encrypted(prot)	__pgprot(__sme_set(pgprot_val(prot)))
#define pgprot_decrypted(prot)	__pgprot(__sme_clr(pgprot_val(prot)))

#ifndef __ASSEMBLY__
#include <asm/x86_init.h>
#include <asm/pkru.h>
#include <asm/fpu/api.h>
#include <asm-generic/pgtable_uffd.h>
#endif

// #define HPT_SIZE_MASK (0xfff)      	/* 16 * cr3[0:11] for number of entries */
// #define HPT_SIZE_HIDDEN_BITS (4)    
// #define HPT_NUM_ENTRIES_TO_CR3(cr3) (((uint64_t) cr3 ) >> HPT_SIZE_HIDDEN_BITS)
// #define HPT_BASE_MASK (~(HPT_SIZE_MASK))
// #define GET_HPT_SIZE(cr3) ((((uint64_t) cr3) & HPT_SIZE_MASK ) << HPT_SIZE_HIDDEN_BITS)
// #define GET_HPT_BASE(cr3) (((uint64_t) cr3) & HPT_BASE_MASK )



// #define PAGE_HEADER_MASK (0xffff000000000000)
// #define PAGE_TAIL_MASK_4KB (0xfff)
// #define PAGE_TAIL_MASK_2MB (0x1fffff)
// #define PAGE_TAIL_MASK_1GB (0x3fffffff)
// #define PAGE_TAIL_MASK_512GB (0x7fffffffff)

// #define PAGE_SHIFT_4KB (12)
// #define PAGE_SHIFT_2MB (21)
// #define PAGE_SHIFT_1GB (30)
// #define PAGE_SHIFT_512GB (39)


// #define PAGE_SIZE_4KB (1UL << PAGE_SHIFT_4KB)
// #define PAGE_SIZE_2MB (1UL << PAGE_SHIFT_2MB)
// #define PAGE_SIZE_1GB (1UL << PAGE_SHIFT_1GB)
// #define PAGE_SIZE_512GB (1UL << PAGE_SHIFT_512GB)

// #define ADDR_REMOVE_OFFSET_4KB(x)   ((x) & ~PAGE_TAIL_MASK_4KB)
// #define ADDR_REMOVE_OFFSET_2MB(x)   ((x) & ~PAGE_TAIL_MASK_2MB)
// #define ADDR_REMOVE_OFFSET_1GB(x)   ((x) & ~PAGE_TAIL_MASK_1GB)

// #define ADDR_TO_OFFSET_4KB(x)   ((x) & PAGE_TAIL_MASK_4KB)
// #define ADDR_TO_OFFSET_2MB(x)   ((x) & PAGE_TAIL_MASK_2MB)
// #define ADDR_TO_OFFSET_1GB(x)   ((x) & PAGE_TAIL_MASK_1GB)

// #define ADDR_TO_PAGE_NUM_4KB(x)   ((ADDR_REMOVE_OFFSET_4KB(x)) >> PAGE_SHIFT_4KB)
// #define ADDR_TO_PAGE_NUM_2MB(x)   ((ADDR_REMOVE_OFFSET_2MB(x)) >> PAGE_SHIFT_2MB)
// #define ADDR_TO_PAGE_NUM_1GB(x)   ((ADDR_REMOVE_OFFSET_1GB(x)) >> PAGE_SHIFT_1GB)


// #define PAGE_NUM_TO_ADDR_4KB(x)   (((uint64_t) x) << PAGE_SHIFT_4KB)
// #define PAGE_NUM_TO_ADDR_2MB(x)   (((uint64_t) x) << PAGE_SHIFT_2MB)
// #define PAGE_NUM_TO_ADDR_1GB(x)   (((uint64_t) x) << PAGE_SHIFT_1GB)

// #define EARLY_HPT_ENTRIES (512 * 8)
// #define EARLY_HPT_ENTRY_SIZE (8)
// #define EARLY_HPT_SIZE (EARLY_HPT_ENTRIES * EARLY_HPT_ENTRY_SIZE)
// #define EARLY_HPT_OFFSET_MASK (EARLY_HPT_ENTRIES - 1)         /* the trailing 12 */

// #define HPT_SIZE_MASK (0xfff)      /* 16 * cr3[0:11] for number of entries */
// #define HPT_SIZE_HIDDEN_BITS (4)    
// #define BOOT_CR3_NUM_ENTRIES_VAL (EARLY_HPT_ENTRIES >> HPT_SIZE_HIDDEN_BITS)            /* 16 * cr3[0:11] for number of entries */
// #define BOOT_HPT_ENTRIES_MAX (HPT_SIZE_MASK << HPT_SIZE_HIDDEN_BITS)

extern ecpt_pmd_t early_hpt[EARLY_HPT_ENTRIES];

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

// uint64_t gen_hash_32(uint32_t vpn, uint64_t size);

int hpt_insert(uint64_t cr3, uint64_t vaddr, uint64_t paddr, ecpt_pgprot_t prot);

int early_hpt_insert(uint64_t cr3, uint64_t vaddr, uint64_t paddr, ecpt_pgprot_t prot, int64_t kernel_start, uint64_t physaddr);

#endif /* _ASM_X86_ECPT_HASH_H */
