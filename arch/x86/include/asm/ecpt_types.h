/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_ECPT_TYPES_H
#define _ASM_X86_ECPT_TYPES_H

/* adpated from <asm/pgtable_types.h> */
#include <linux/const.h>
#include <asm/ECPT_defs.h>
#include <linux/types.h>
// #include <linux/mem_encrypt.h>

// #include <asm/page_types.h>
typedef unsigned long	ecpt_pteval_t;
typedef unsigned long	ecpt_pmdval_t;
typedef unsigned long	ecpt_pudval_t;
// typedef unsigned long	p4dval_t;
// typedef unsigned long	pgdval_t;
typedef unsigned long	ecpt_pgprotval_t;



typedef struct ecpt_entry{
	uint64_t VPN_tag;  
	uint64_t pte[ECPT_CLUSTER_FACTOR];
} ecpt_entry_t;


#if ECPT_4K_USER_WAY > 0
	#define ECPT_4K_PER_WAY_ENTRIES (512 * 8)
#else
	#define ECPT_4K_PER_WAY_ENTRIES (0)
#endif

#if ECPT_2M_USER_WAY > 0
	#define ECPT_2M_PER_WAY_ENTRIES (512 * 8)
#else
	#define ECPT_2M_PER_WAY_ENTRIES (0)
#endif

#if ECPT_1G_USER_WAY > 0
	#define ECPT_1G_PER_WAY_ENTRIES (512 * 8)
#else
	#define ECPT_1G_PER_WAY_ENTRIES (0)
#endif


#define EPCT_NUM_ENTRY_TO_NR_PAGES(num) ((num * sizeof(ecpt_entry_t)) >> PAGE_SHIFT)

/* eager = 1, allocate such when map_desc_alloc is called, ow. wait until it is needed */
#define ECPT_4K_WAY_EAGER 1
#define ECPT_2M_WAY_EAGER 0
#define ECPT_1G_WAY_EAGER 0

// #define GET_PTEP_OFFSET(addr) ( sizeof(((ecpt_entry_t *)0)->VPN_tag) )
// #define GET_ECPT_P_FROM_PTEP(ptep, addr) ((ecpt_entry_t *) (((void *) ptep) - GET_PTEP_OFFSET(addr)) )

#define IS_KERNEL_MAP(vaddr) (vaddr >= __PAGE_OFFSET)

typedef struct { ecpt_pudval_t pud; } ecpt_pud_t;
typedef struct { ecpt_pmdval_t pmd; } ecpt_pmd_t;
typedef struct { ecpt_pteval_t pte; } ecpt_pte_t;
typedef struct ecpt_pgprot { ecpt_pgprotval_t pgprot; } ecpt_pgprot_t;

#define ecpt_pgprot_val(x)		((x).pgprot)
#define __ecpt_pgprot(x)		((ecpt_pgprot_t) { (x) } )
#define __ecpt_pg(x)					__ecpt_pgprot(x)


#define PAGE_SHIFT		12
#define PAGE_SIZE		(_AC(1,UL) << PAGE_SHIFT)
#define PAGE_MASK		(~(PAGE_SIZE-1))

#define PMD_SHITFT		21
#define PMD_PAGE_SIZE		(_AC(1, UL) << PMD_SHIFT)
#define PMD_PAGE_MASK		(~(PMD_PAGE_SIZE-1))

#define PUD_SHIFT		30
#define PUD_PAGE_SIZE		(_AC(1, UL) << PUD_SHIFT)
#define PUD_PAGE_MASK		(~(PUD_PAGE_SIZE-1))

#define __VIRTUAL_MASK		((1UL << __VIRTUAL_MASK_SHIFT) - 1)

/* bits for virtual address */
#define __PHYSICAL_MASK_SHIFT 	52

#ifndef __PHYSICAL_MASK
#define __PHYSICAL_MASK ((1ULL << __PHYSICAL_MASK_SHIFT) - 1)
#endif

/* Cast *PAGE_MASK to a signed type so that it is sign-extended if
   virtual addresses are 32-bits but physical addresses are larger
   (ie, 32-bit PAE). */
#define PHYSICAL_PAGE_MASK	(((signed long)PAGE_MASK) & __PHYSICAL_MASK)
#define PHYSICAL_PMD_PAGE_MASK	(((signed long)PMD_PAGE_MASK) & __PHYSICAL_MASK)
#define PHYSICAL_PUD_PAGE_MASK	(((signed long)PUD_PAGE_MASK) & __PHYSICAL_MASK)

#ifdef CONFIG_RANDOMIZE_BASE
#define KERNEL_IMAGE_SIZE	(1024 * 1024 * 1024)
#else
#define KERNEL_IMAGE_SIZE	(512 * 1024 * 1024)
#endif


#define _PAGE_BIT_PRESENT	0	/* is present */
#define _PAGE_BIT_RW		1	/* writeable */
#define _PAGE_BIT_USER		2	/* userspace addressable */
#define _PAGE_BIT_PWT		3	/* page write through */
#define _PAGE_BIT_PCD		4	/* page cache disabled */
#define _PAGE_BIT_ACCESSED	5	/* was accessed (raised by CPU) */
#define _PAGE_BIT_DIRTY		6	/* was written to (raised by CPU) */
#define _PAGE_BIT_PSE		7	/* 4 MB (or 2MB) page */
#define _PAGE_BIT_PAT		7	/* on 4KB pages */
#define _PAGE_BIT_GLOBAL	8	/* Global TLB entry PPro+ */
#define _PAGE_BIT_SOFTW1	9	/* available for programmer */
#define _PAGE_BIT_SOFTW2	10	/* " */
#define _PAGE_BIT_SOFTW3	11	/* " */
#define _PAGE_BIT_PAT_LARGE	12	/* On 2MB or 1GB pages */
#define _PAGE_BIT_SOFTW4	58	/* available for programmer */
#define _PAGE_BIT_PKEY_BIT0	59	/* Protection Keys, bit 1/4 */
#define _PAGE_BIT_PKEY_BIT1	60	/* Protection Keys, bit 2/4 */
#define _PAGE_BIT_PKEY_BIT2	61	/* Protection Keys, bit 3/4 */
#define _PAGE_BIT_PKEY_BIT3	62	/* Protection Keys, bit 4/4 */
#define _PAGE_BIT_NX		63	/* No execute: only valid after cpuid check */

#define _PAGE_BIT_SPECIAL	_PAGE_BIT_SOFTW1
#define _PAGE_BIT_CPA_TEST	_PAGE_BIT_SOFTW1
#define _PAGE_BIT_UFFD_WP	_PAGE_BIT_SOFTW2 /* userfaultfd wrprotected */
#define _PAGE_BIT_SOFT_DIRTY	_PAGE_BIT_SOFTW3 /* software dirty tracking */
#define _PAGE_BIT_DEVMAP	_PAGE_BIT_SOFTW4

/* If _PAGE_BIT_PRESENT is clear, we use these: */
/* - if the user mapped it with PROT_NONE; pte_present gives true */
#define _PAGE_BIT_PROTNONE	_PAGE_BIT_GLOBAL

#ifndef _ASM_X86_PGTABLE_DEFS_H			/* temporarily undefine to suppress compiler warning */

#define _PAGE_PRESENT	(_AT(ecpt_pteval_t, 1) << _PAGE_BIT_PRESENT)
#define _PAGE_RW	(_AT(ecpt_pteval_t, 1) << _PAGE_BIT_RW)
#define _PAGE_USER	(_AT(ecpt_pteval_t, 1) << _PAGE_BIT_USER)
#define _PAGE_PWT	(_AT(ecpt_pteval_t, 1) << _PAGE_BIT_PWT)
#define _PAGE_PCD	(_AT(ecpt_pteval_t, 1) << _PAGE_BIT_PCD)
#define _PAGE_ACCESSED	(_AT(ecpt_pteval_t, 1) << _PAGE_BIT_ACCESSED)
#define _PAGE_DIRTY	(_AT(ecpt_pteval_t, 1) << _PAGE_BIT_DIRTY)
#define _PAGE_PSE	(_AT(ecpt_pteval_t, 1) << _PAGE_BIT_PSE)
#define _PAGE_GLOBAL	(_AT(ecpt_pteval_t, 1) << _PAGE_BIT_GLOBAL)
#define _PAGE_SOFTW1	(_AT(ecpt_pteval_t, 1) << _PAGE_BIT_SOFTW1)
#define _PAGE_SOFTW2	(_AT(ecpt_pteval_t, 1) << _PAGE_BIT_SOFTW2)
#define _PAGE_SOFTW3	(_AT(ecpt_pteval_t, 1) << _PAGE_BIT_SOFTW3)
#define _PAGE_PAT	(_AT(ecpt_pteval_t, 1) << _PAGE_BIT_PAT)
#define _PAGE_PAT_LARGE (_AT(ecpt_pteval_t, 1) << _PAGE_BIT_PAT_LARGE)
#define _PAGE_SPECIAL	(_AT(ecpt_pteval_t, 1) << _PAGE_BIT_SPECIAL)
#define _PAGE_CPA_TEST	(_AT(ecpt_pteval_t, 1) << _PAGE_BIT_CPA_TEST)
#ifdef CONFIG_X86_INTEL_MEMORY_PROTECTION_KEYS
#define _PAGE_PKEY_BIT0	(_AT(ecpt_pteval_t, 1) << _PAGE_BIT_PKEY_BIT0)
#define _PAGE_PKEY_BIT1	(_AT(ecpt_pteval_t, 1) << _PAGE_BIT_PKEY_BIT1)
#define _PAGE_PKEY_BIT2	(_AT(ecpt_pteval_t, 1) << _PAGE_BIT_PKEY_BIT2)
#define _PAGE_PKEY_BIT3	(_AT(ecpt_pteval_t, 1) << _PAGE_BIT_PKEY_BIT3)
#else
#define _PAGE_PKEY_BIT0	(_AT(ecpt_pteval_t, 0))
#define _PAGE_PKEY_BIT1	(_AT(ecpt_pteval_t, 0))
#define _PAGE_PKEY_BIT2	(_AT(ecpt_pteval_t, 0))
#define _PAGE_PKEY_BIT3	(_AT(ecpt_pteval_t, 0))
#endif

#define _PAGE_PKEY_MASK (_PAGE_PKEY_BIT0 | \
			 _PAGE_PKEY_BIT1 | \
			 _PAGE_PKEY_BIT2 | \
			 _PAGE_PKEY_BIT3)

#if defined(CONFIG_X86_64) || defined(CONFIG_X86_PAE)
#define _PAGE_KNL_ERRATUM_MASK (_PAGE_DIRTY | _PAGE_ACCESSED)
#else
#define _PAGE_KNL_ERRATUM_MASK 0
#endif

#ifdef CONFIG_MEM_SOFT_DIRTY
#define _PAGE_SOFT_DIRTY	(_AT(ecpt_pteval_t, 1) << _PAGE_BIT_SOFT_DIRTY)
#else
#define _PAGE_SOFT_DIRTY	(_AT(ecpt_pteval_t, 0))
#endif

/*
 * Tracking soft dirty bit when a page goes to a swap is tricky.
 * We need a bit which can be stored in pte _and_ not conflict
 * with swap entry format. On x86 bits 1-4 are *not* involved
 * into swap entry computation, but bit 7 is used for thp migration,
 * so we borrow bit 1 for soft dirty tracking.
 *
 * Please note that this bit must be treated as swap dirty page
 * mark if and only if the PTE/PMD has present bit clear!
 */
#ifdef CONFIG_MEM_SOFT_DIRTY
#define _PAGE_SWP_SOFT_DIRTY	_PAGE_RW
#else
#define _PAGE_SWP_SOFT_DIRTY	(_AT(ecpt_pteval_t, 0))
#endif

#ifdef CONFIG_HAVE_ARCH_USERFAULTFD_WP
#define _PAGE_UFFD_WP		(_AT(ecpt_pteval_t, 1) << _PAGE_BIT_UFFD_WP)
#define _PAGE_SWP_UFFD_WP	_PAGE_USER
#else
#define _PAGE_UFFD_WP		(_AT(ecpt_pteval_t, 0))
#define _PAGE_SWP_UFFD_WP	(_AT(ecpt_pteval_t, 0))
#endif

#if defined(CONFIG_X86_64) || defined(CONFIG_X86_PAE)
#define _PAGE_NX	(_AT(ecpt_pteval_t, 1) << _PAGE_BIT_NX)
#define _PAGE_DEVMAP	(_AT(u64, 1) << _PAGE_BIT_DEVMAP)
#else
#define _PAGE_NX	(_AT(ecpt_pteval_t, 0))
#define _PAGE_DEVMAP	(_AT(ecpt_pteval_t, 0))
#endif

#define _PAGE_PROTNONE	(_AT(ecpt_pteval_t, 1) << _PAGE_BIT_PROTNONE)

/*
 * Set of bits not changed in pte_modify.  The pte's
 * protection key is treated like _PAGE_RW, for
 * instance, and is *not* included in this mask since
 * pte_modify() does modify it.
 */
#define _PAGE_CHG_MASK	(PTE_PFN_MASK | _PAGE_PCD | _PAGE_PWT |		\
			 _PAGE_SPECIAL | _PAGE_ACCESSED | _PAGE_DIRTY |	\
			 _PAGE_SOFT_DIRTY | _PAGE_DEVMAP | _PAGE_ENC |  \
			 _PAGE_UFFD_WP)
#define _HPAGE_CHG_MASK (_PAGE_CHG_MASK | _PAGE_PSE)

/*
 * The cache modes defined here are used to translate between pure SW usage
 * and the HW defined cache mode bits and/or PAT entries.
 *
 * The resulting bits for PWT, PCD and PAT should be chosen in a way
 * to have the WB mode at index 0 (all bits clear). This is the default
 * right now and likely would break too much if changed.
 */
#ifndef __ASSEMBLY__
enum page_cache_mode {
	_PAGE_CACHE_MODE_WB       = 0,
	_PAGE_CACHE_MODE_WC       = 1,
	_PAGE_CACHE_MODE_UC_MINUS = 2,
	_PAGE_CACHE_MODE_UC       = 3,
	_PAGE_CACHE_MODE_WT       = 4,
	_PAGE_CACHE_MODE_WP       = 5,

	_PAGE_CACHE_MODE_NUM      = 8
};
#endif

#define _PAGE_ENC		(_AT(ecpt_pteval_t, sme_me_mask))

#define _PAGE_CACHE_MASK	(_PAGE_PWT | _PAGE_PCD | _PAGE_PAT)
#define _PAGE_LARGE_CACHE_MASK	(_PAGE_PWT | _PAGE_PCD | _PAGE_PAT_LARGE)

#define _PAGE_NOCACHE		(cachemode2protval(_PAGE_CACHE_MODE_UC))
#define _PAGE_CACHE_WP		(cachemode2protval(_PAGE_CACHE_MODE_WP))

#define __PP _PAGE_PRESENT
#define __RW _PAGE_RW
#define _USR _PAGE_USER
#define ___A _PAGE_ACCESSED
#define ___D _PAGE_DIRTY
#define ___G _PAGE_GLOBAL
#define __NX _PAGE_NX

#define _ENC _PAGE_ENC
#define __WP _PAGE_CACHE_WP
#define __NC _PAGE_NOCACHE
#define _PSE _PAGE_PSE

#define pgprot_val(x)		((x).pgprot)
#define __pgprot(x)		((pgprot_t) { (x) } )
#define __pg(x)			__pgprot(x)

#define PAGE_NONE	     __pg(   0|   0|   0|___A|   0|   0|   0|___G)
#define PAGE_SHARED	     __pg(__PP|__RW|_USR|___A|__NX|   0|   0|   0)
#define PAGE_SHARED_EXEC     __pg(__PP|__RW|_USR|___A|   0|   0|   0|   0)
#define PAGE_COPY_NOEXEC     __pg(__PP|   0|_USR|___A|__NX|   0|   0|   0)
#define PAGE_COPY_EXEC	     __pg(__PP|   0|_USR|___A|   0|   0|   0|   0)
#define PAGE_COPY	     __pg(__PP|   0|_USR|___A|__NX|   0|   0|   0)
#define PAGE_READONLY	     __pg(__PP|   0|_USR|___A|__NX|   0|   0|   0)
#define PAGE_READONLY_EXEC   __pg(__PP|   0|_USR|___A|   0|   0|   0|   0)

#define __PAGE_KERNEL		 (__PP|__RW|   0|___A|__NX|___D|   0|___G)
#define __PAGE_KERNEL_EXEC	 (__PP|__RW|   0|___A|   0|___D|   0|___G)
#define _KERNPG_TABLE_NOENC	 (__PP|__RW|   0|___A|   0|___D|   0|   0)
#define _KERNPG_TABLE		 (__PP|__RW|   0|___A|   0|___D|   0|   0| _ENC)
#define _PAGE_TABLE_NOENC	 (__PP|__RW|_USR|___A|   0|___D|   0|   0)
#define _PAGE_TABLE		 (__PP|__RW|_USR|___A|   0|___D|   0|   0| _ENC)
#define __PAGE_KERNEL_RO	 (__PP|   0|   0|___A|__NX|___D|   0|___G)
#define __PAGE_KERNEL_ROX	 (__PP|   0|   0|___A|   0|___D|   0|___G)
#define __PAGE_KERNEL_NOCACHE	 (__PP|__RW|   0|___A|__NX|___D|   0|___G| __NC)
#define __PAGE_KERNEL_VVAR	 (__PP|   0|_USR|___A|__NX|___D|   0|___G)
#define __PAGE_KERNEL_LARGE	 (__PP|__RW|   0|___A|__NX|___D|_PSE|___G)
#define __PAGE_KERNEL_LARGE_EXEC (__PP|__RW|   0|___A|   0|___D|_PSE|___G)
#define __PAGE_KERNEL_WP	 (__PP|__RW|   0|___A|__NX|___D|   0|___G| __WP)


#define __PAGE_KERNEL_IO		__PAGE_KERNEL
#define __PAGE_KERNEL_IO_NOCACHE	__PAGE_KERNEL_NOCACHE


#ifndef __ASSEMBLY__

#define __PAGE_KERNEL_ENC	(__PAGE_KERNEL    | _ENC)
#define __PAGE_KERNEL_ENC_WP	(__PAGE_KERNEL_WP | _ENC)
#define __PAGE_KERNEL_NOENC	(__PAGE_KERNEL    |    0)
#define __PAGE_KERNEL_NOENC_WP	(__PAGE_KERNEL_WP |    0)

#define __pgprot_mask(x)	__pgprot((x) & __default_kernel_pte_mask)

#define PAGE_KERNEL		__pgprot_mask(__PAGE_KERNEL            | _ENC)
#define PAGE_KERNEL_NOENC	__pgprot_mask(__PAGE_KERNEL            |    0)
#define PAGE_KERNEL_RO		__pgprot_mask(__PAGE_KERNEL_RO         | _ENC)
#define PAGE_KERNEL_EXEC	__pgprot_mask(__PAGE_KERNEL_EXEC       | _ENC)
#define PAGE_KERNEL_EXEC_NOENC	__pgprot_mask(__PAGE_KERNEL_EXEC       |    0)
#define PAGE_KERNEL_ROX		__pgprot_mask(__PAGE_KERNEL_ROX        | _ENC)
#define PAGE_KERNEL_NOCACHE	__pgprot_mask(__PAGE_KERNEL_NOCACHE    | _ENC)
#define PAGE_KERNEL_LARGE	__pgprot_mask(__PAGE_KERNEL_LARGE      | _ENC)
#define PAGE_KERNEL_LARGE_EXEC	__pgprot_mask(__PAGE_KERNEL_LARGE_EXEC | _ENC)
#define PAGE_KERNEL_VVAR	__pgprot_mask(__PAGE_KERNEL_VVAR       | _ENC)

#define PAGE_KERNEL_IO		__pgprot_mask(__PAGE_KERNEL_IO)
#define PAGE_KERNEL_IO_NOCACHE	__pgprot_mask(__PAGE_KERNEL_IO_NOCACHE)

#endif	/* __ASSEMBLY__ */

/*         xwr */
#define __P000	PAGE_NONE
#define __P001	PAGE_READONLY
#define __P010	PAGE_COPY
#define __P011	PAGE_COPY
#define __P100	PAGE_READONLY_EXEC
#define __P101	PAGE_READONLY_EXEC
#define __P110	PAGE_COPY_EXEC
#define __P111	PAGE_COPY_EXEC

#define __S000	PAGE_NONE
#define __S001	PAGE_READONLY
#define __S010	PAGE_SHARED
#define __S011	PAGE_SHARED
#define __S100	PAGE_READONLY_EXEC
#define __S101	PAGE_READONLY_EXEC
#define __S110	PAGE_SHARED_EXEC
#define __S111	PAGE_SHARED_EXEC

/*
 * early identity mapping  pte attrib macros.
 */
#ifdef CONFIG_X86_64
#define __PAGE_KERNEL_IDENT_LARGE_EXEC	__PAGE_KERNEL_LARGE_EXEC
#else
#define PTE_IDENT_ATTR	 0x003		/* PRESENT+RW */
#define PDE_IDENT_ATTR	 0x063		/* PRESENT+RW+DIRTY+ACCESSED */
#define PGD_IDENT_ATTR	 0x001		/* PRESENT (no other attributes) */
#endif

#ifdef CONFIG_X86_32
# include <asm/pgtable_32_types.h>
#else
# include <asm/pgtable_64_types.h>
#endif

#endif /*  ifndef _ASM_X86_PGTABLE_DEFS_H*/



#ifndef __ASSEMBLY__

#include <linux/types.h>

/* Extracts the PFN from a (pte|pmd|pud|pgd)val_t of a 4KB page */

#ifndef PTE_PFN_MASK

#define PTE_PFN_MASK		((ecpt_pteval_t)PHYSICAL_PAGE_MASK)

/*
 *  Extracts the flags from a (pte|pmd|pud|pgd)val_t
 *  This includes the protection key value.
 */
#define PTE_FLAGS_MASK		(~PTE_PFN_MASK)

#endif /* ifndef PTE_PFN_MASK */





static inline ecpt_pgprot_t ecpt_pgprot_nx(ecpt_pgprot_t prot)
{
	return __ecpt_pgprot(ecpt_pgprot_val(prot) | _PAGE_NX);
}
// #define pgprot_nx pgprot_nx

// #ifdef CONFIG_X86_PAE

// /*
//  * PHYSICAL_PAGE_MASK might be non-constant when SME is compiled in, so we can't
//  * use it here.
//  */

// #define PGD_PAE_PAGE_MASK	((signed long)PAGE_MASK)
// #define PGD_PAE_PHYS_MASK	(((1ULL << __PHYSICAL_MASK_SHIFT)-1) & PGD_PAE_PAGE_MASK)

// /*
//  * PAE allows Base Address, P, PWT, PCD and AVL bits to be set in PGD entries.
//  * All other bits are Reserved MBZ
//  */

/*
 #define PGD_ALLOWED_BITS	(PGD_PAE_PHYS_MASK | _PAGE_PRESENT | \
 				 _PAGE_PWT | _PAGE_PCD | \
 				 _PAGE_SOFTW1 | _PAGE_SOFTW2 | _PAGE_SOFTW3)
*/
// #else
// /* No need to mask any bits for !PAE */
// #define PGD_ALLOWED_BITS	(~0ULL)
// #endif

#define PGD_ALLOWED_BITS	(~0ULL)




// static inline pgd_t native_make_pgd(pgdval_t val)
// {
// 	return (pgd_t) { val & PGD_ALLOWED_BITS };
// }

// static inline pgdval_t native_pgd_val(pgd_t pgd)
// {
// 	return pgd.pgd & PGD_ALLOWED_BITS;
// }

// static inline pgdval_t pgd_flags(pgd_t pgd)
// {
// 	return native_pgd_val(pgd) & PTE_FLAGS_MASK;
// }

/* ----- ECPT PUD helper functions --- */

static inline ecpt_pud_t native_make_ecpt_pud(ecpt_pudval_t val)
{
	return (ecpt_pud_t) { val };
}

static inline ecpt_pudval_t native_ecpt_pud_val(ecpt_pud_t pud)
{
	return pud.pud;
}

static inline ecpt_pudval_t ecpt_pud_pfn_mask(ecpt_pud_t pud)
{
	if (native_ecpt_pud_val(pud) & _PAGE_PSE)
		return PHYSICAL_PUD_PAGE_MASK;
	else
		return PTE_PFN_MASK;
}

static inline ecpt_pudval_t ecpt_pud_flags_mask(ecpt_pud_t pud)
{
	return ~ecpt_pud_pfn_mask(pud);
}

static inline ecpt_pudval_t ecpt_pud_flags(ecpt_pud_t pud)
{
	return native_ecpt_pud_val(pud) & ecpt_pud_flags_mask(pud);
}


/* ----- ECPT PMD helper functions --- */

static inline ecpt_pmd_t native_make_ecpt_pmd(ecpt_pmdval_t val)
{
	return (ecpt_pmd_t) { val };
}

static inline ecpt_pmdval_t native_ecpt_pmd_val(ecpt_pmd_t pmd)
{
	return pmd.pmd;
}

static inline ecpt_pmdval_t ecpt_pmd_pfn_mask(ecpt_pmd_t pmd)
{
	if (native_ecpt_pmd_val(pmd) & _PAGE_PSE)
		return PHYSICAL_PMD_PAGE_MASK;
	else
		return PTE_PFN_MASK;
}

static inline ecpt_pmdval_t ecpt_pmd_flags_mask(ecpt_pmd_t pmd)
{
	return ~ecpt_pmd_pfn_mask(pmd);
}

static inline ecpt_pmdval_t ecpt_pmd_flags(ecpt_pmd_t pmd)
{
	return native_ecpt_pmd_val(pmd) & ecpt_pmd_flags_mask(pmd);
}



/* ----- ECPT PTE helper functions --- */

static inline ecpt_pte_t native_make_ecpt_pte(ecpt_pteval_t val)
{
	return (ecpt_pte_t) { .pte = val };
}

static inline ecpt_pteval_t native_ecpt_pte_val(ecpt_pte_t pte)
{
	return pte.pte;
}

static inline ecpt_pteval_t ecpt_pte_flags(ecpt_pte_t pte)
{
	return native_ecpt_pte_val(pte) & PTE_FLAGS_MASK;
}



/* TODO: concern more about atomicity later */
// static inline void set_ecpt_entry(ecpt_entry_t *entry , ecpt_entry_t e)
// {
// 	*entry = e;
// 	// WRITE_ONCE(*entry, e);
// }


// static inline ecpt_pteval_t native_ecpt_entry_val(ecpt_entry_t entry)
// {
// 	return entry.pte;
// }


// static inline ecpt_pteval_t native_ecpt_entry_tag(ecpt_entry_t entry)
// {
// 	return entry.pte;
// }

// static inline ecpt_pteval_t ecpt_pte_flags(ecpt_pte_t pte)
// {
// 	return native_ecpt_pte_val(pte) & PTE_FLAGS_MASK;
// }




// #if CONFIG_PGTABLE_LEVELS > 4
// typedef struct { p4dval_t p4d; } p4d_t;

// static inline p4d_t native_make_p4d(pudval_t val)
// {
// 	return (p4d_t) { val };
// }

// static inline p4dval_t native_p4d_val(p4d_t p4d)
// {
// 	return p4d.p4d;
// }
// #else
// #include <asm-generic/pgtable-nop4d.h>

// static inline p4d_t native_make_p4d(pudval_t val)
// {
// 	return (p4d_t) { .pgd = native_make_pgd((pgdval_t)val) };
// }

// static inline p4dval_t native_p4d_val(p4d_t p4d)
// {
// 	return native_pgd_val(p4d.pgd);
// }
// #endif





// static inline p4dval_t p4d_pfn_mask(p4d_t p4d)
// {
// 	/* No 512 GiB huge pages yet */
// 	return PTE_PFN_MASK;
// }

// static inline p4dval_t p4d_flags_mask(p4d_t p4d)
// {
// 	return ~p4d_pfn_mask(p4d);
// }

// static inline p4dval_t p4d_flags(p4d_t p4d)
// {
// 	return native_p4d_val(p4d) & p4d_flags_mask(p4d);
// }

// static inline pudval_t pud_pfn_mask(pud_t pud)
// {
// 	if (native_pud_val(pud) & _PAGE_PSE)
// 		return PHYSICAL_PUD_PAGE_MASK;
// 	else
// 		return PTE_PFN_MASK;
// }

// static inline pudval_t pud_flags_mask(pud_t pud)
// {
// 	return ~pud_pfn_mask(pud);
// }

// static inline pudval_t pud_flags(pud_t pud)
// {
// 	return native_pud_val(pud) & pud_flags_mask(pud);
// }

// static inline pmdval_t pmd_pfn_mask(pmd_t pmd)
// {
// 	if (native_pmd_val(pmd) & _PAGE_PSE)
// 		return PHYSICAL_PMD_PAGE_MASK;
// 	else
// 		return PTE_PFN_MASK;
// }

// static inline pmdval_t pmd_flags_mask(pmd_t pmd)
// {
// 	return ~pmd_pfn_mask(pmd);
// }

// static inline pmdval_t pmd_flags(pmd_t pmd)
// {
// 	return native_pmd_val(pmd) & pmd_flags_mask(pmd);
// }

// static inline pte_t native_make_pte(pteval_t val)
// {
// 	return (pte_t) { .pte = val };
// }

// static inline pteval_t native_pte_val(pte_t pte)
// {
// 	return pte.pte;
// }

// static inline pteval_t pte_flags(pte_t pte)
// {
// 	return native_pte_val(pte) & PTE_FLAGS_MASK;
// }


/*
 #define __pte2cm_idx(cb)				\
 	((((cb) >> (_PAGE_BIT_PAT - 2)) & 4) |		\
 	 (((cb) >> (_PAGE_BIT_PCD - 1)) & 2) |		\
 	 (((cb) >> _PAGE_BIT_PWT) & 1))
 #define __cm_idx2pte(i)					\
 	((((i) & 4) << (_PAGE_BIT_PAT - 2)) |		\
 	 (((i) & 2) << (_PAGE_BIT_PCD - 1)) |		\
 	 (((i) & 1) << _PAGE_BIT_PWT))
*/
// unsigned long cachemode2protval(enum page_cache_mode pcm);

// static inline pgprotval_t protval_4k_2_large(pgprotval_t val)
// {
// 	return (val & ~(_PAGE_PAT | _PAGE_PAT_LARGE)) |
// 		((val & _PAGE_PAT) << (_PAGE_BIT_PAT_LARGE - _PAGE_BIT_PAT));
// }
// static inline pgprot_t pgprot_4k_2_large(pgprot_t pgprot)
// {
// 	return __pgprot(protval_4k_2_large(pgprot_val(pgprot)));
// }
// static inline pgprotval_t protval_large_2_4k(pgprotval_t val)
// {
// 	return (val & ~(_PAGE_PAT | _PAGE_PAT_LARGE)) |
// 		((val & _PAGE_PAT_LARGE) >>
// 		 (_PAGE_BIT_PAT_LARGE - _PAGE_BIT_PAT));
// }
// static inline pgprot_t pgprot_large_2_4k(pgprot_t pgprot)
// {
// 	return __pgprot(protval_large_2_4k(pgprot_val(pgprot)));
// }


// typedef struct page *pgtable_t;

// extern pteval_t __supported_pte_mask;
// extern pteval_t __default_kernel_pte_mask;
// extern void set_nx(void);
// extern int nx_enabled;

// #define pgprot_writecombine	pgprot_writecombine
// extern pgprot_t pgprot_writecombine(pgprot_t prot);

// #define pgprot_writethrough	pgprot_writethrough
// extern pgprot_t pgprot_writethrough(pgprot_t prot);

// /* Indicate that x86 has its own track and untrack pfn vma functions */
// #define __HAVE_PFNMAP_TRACKINGpgprot_t
// // 	PG_LEVEL_4K,
// // 	PG_LEVEL_2M,
// // 	PG_LEVEL_1G,
// // 	PG_LEVEL_512G,
// // 	PG_LEVEL_NUM
// // };

// #ifdef CONFIG_PROC_FS
// extern void update_page_count(int level, unsigned long pages);
// #else
// static inline void update_page_count(int level, unsigned long pages) { }
// #endif

// /*
//  * Helper function that returns the kernel pagetable entry controlling
//  * the virtual address 'address'. NULL means no pagetable entry present.
//  * NOTE: the return type is pte_t but if the pmd is PSE then we return it
//  * as a pte too.
//  */
// extern pte_t *lookup_address(unsigned long address, unsigned int *level);
// extern pte_t *lookup_address_in_pgd(pgd_t *pgd, unsigned long address,
// 				    unsigned int *level);

// struct mm_struct;
// extern pte_t *lookup_address_in_mm(struct mm_struct *mm, unsigned long address,
// 				   unsigned int *level);
// extern pmd_t *lookup_pmd_address(unsigned long address);
// extern phys_addr_t slow_virt_to_phys(void *__address);
// extern int __init kernel_map_pages_in_pgd(pgd_t *pgd, u64 pfn,
// 					  unsigned long address,
// 					  unsigned numpages,
// 					  unsigned long page_flags);
// extern int __init kernel_unmap_pages_in_pgd(pgd_t *pgd, unsigned long address,
// 					    unsigned long numpages);
#endif	/* !__ASSEMBLY__ */

#endif /* _ASM_X86_ECPT_TYPES_H */
