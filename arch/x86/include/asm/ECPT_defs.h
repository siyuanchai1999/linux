#ifndef _ASM_X86_ECPT_DEFS_H
#define _ASM_X86_ECPT_DEFS_H


#define HPT_SIZE_MASK (0xfff)      	/* 16 * cr3[0:11] for number of entries */
#define HPT_SIZE_HIDDEN_BITS (4)    
#define HPT_NUM_ENTRIES_TO_CR3(size) (((uint64_t) size ) >> HPT_SIZE_HIDDEN_BITS)
#define HPT_BASE_MASK (0x000ffffffffff000UL)
#define GET_HPT_SIZE(cr3) ((((uint64_t) cr3) & HPT_SIZE_MASK ) << HPT_SIZE_HIDDEN_BITS)
#define GET_HPT_BASE(cr3) (((uint64_t) cr3) & HPT_BASE_MASK )


/* we should use GET_HPT_BASE_VIRT after kernel transitions to virtual address space */
#define HPT_BASE_MASK_VIRT (0xfffffffffffff000UL)
#define GET_HPT_BASE_VIRT(cr3) (((uint64_t) cr3) & HPT_BASE_MASK_VIRT )
/**
 * @brief cr in virtual
 * 		virtual address + hpt_size
 * 	cr in physical
 * 		physical address + hpt_size + ecpt_enabled_bit (for cr3)
 * 		 
 * 
 */

#define PAGE_HEADER_MASK (0xffff000000000000)

#define PG_ADDRESS_MASK  (0x000ffffffffff000LL)
#define PAGE_TAIL_MASK_4KB (0xfff)
#define PAGE_TAIL_MASK_2MB (0x1fffff)
#define PAGE_TAIL_MASK_1GB (0x3fffffff)
#define PAGE_TAIL_MASK_512GB (0x7fffffffff)


#define PAGE_SHIFT_4KB (12)
#define PAGE_SHIFT_2MB (21)
#define PAGE_SHIFT_1GB (30)
#define PAGE_SHIFT_512GB (39)


#define PAGE_SIZE_4KB (1UL << PAGE_SHIFT_4KB)
#define PAGE_SIZE_2MB (1UL << PAGE_SHIFT_2MB)
#define PAGE_SIZE_1GB (1UL << PAGE_SHIFT_1GB)
#define PAGE_SIZE_512GB (1UL << PAGE_SHIFT_512GB)

#define ADDR_REMOVE_OFFSET_4KB(x)   (((x) & ~PAGE_TAIL_MASK_4KB) & PG_ADDRESS_MASK)
#define ADDR_REMOVE_OFFSET_2MB(x)   (((x) & ~PAGE_TAIL_MASK_2MB) & PG_ADDRESS_MASK)
#define ADDR_REMOVE_OFFSET_1GB(x)   (((x) & ~PAGE_TAIL_MASK_1GB) & PG_ADDRESS_MASK)

#define ADDR_TO_OFFSET_4KB(x)   ((x) & PAGE_TAIL_MASK_4KB)
#define ADDR_TO_OFFSET_2MB(x)   ((x) & PAGE_TAIL_MASK_2MB)
#define ADDR_TO_OFFSET_1GB(x)   ((x) & PAGE_TAIL_MASK_1GB)

#define ADDR_TO_PAGE_NUM_4KB(x)   ((ADDR_REMOVE_OFFSET_4KB(x)) >> PAGE_SHIFT_4KB)
#define ADDR_TO_PAGE_NUM_2MB(x)   ((ADDR_REMOVE_OFFSET_2MB(x)) >> PAGE_SHIFT_2MB)
#define ADDR_TO_PAGE_NUM_1GB(x)   ((ADDR_REMOVE_OFFSET_1GB(x)) >> PAGE_SHIFT_1GB)


#define PAGE_NUM_TO_ADDR_4KB(x)   (((uint64_t) x) << PAGE_SHIFT_4KB)
#define PAGE_NUM_TO_ADDR_2MB(x)   (((uint64_t) x) << PAGE_SHIFT_2MB)
#define PAGE_NUM_TO_ADDR_1GB(x)   (((uint64_t) x) << PAGE_SHIFT_1GB)

#define PTE_CLUSTER_NBITS 0
#define PMD_CLUSTER_NBITS 0
#define PUD_CLUSTER_NBITS 0

#define PTE_4KB_CLUSTER_FACTOR (1 << PTE_CLUSTER_NBITS)
#define PMD_2MB_CLUSTER_FACTOR (1 << PMD_CLUSTER_NBITS)
#define PUD_1GB_CLUSTER_FACTOR (1 << PUD_CLUSTER_NBITS)

#define PTE_CLUSTERED_SIZE (PTE_4KB_CLUSTER_FACTOR * PAGE_SIZE_4KB)
#define PMD_CLUSTERED_SIZE (PMD_2MB_CLUSTER_FACTOR * PAGE_SIZE_2MB)
#define PUD_CLUSTERED_SIZE (PUD_1GB_CLUSTER_FACTOR * PAGE_SIZE_1GB)

#define cluster_pte_addr_end(addr, end)						\
({	unsigned long __boundary = ((addr) + PTE_CLUSTERED_SIZE) & (~(PTE_CLUSTERED_SIZE - 1));	\
	(__boundary - 1 < (end) - 1)? __boundary: (end);		\
})

#define cluster_pmd_addr_end(addr, end)						\
({	unsigned long __boundary = ((addr) + PMD_CLUSTERED_SIZE) & (~(PMD_CLUSTERED_SIZE - 1));	\
	(__boundary - 1 < (end) - 1)? __boundary: (end);		\
})

#define cluster_pud_addr_end(addr, end)						\
({	unsigned long __boundary = ((addr) + PUD_CLUSTERED_SIZE) & (~(PUD_CLUSTERED_SIZE - 1));	\
	(__boundary - 1 < (end) - 1)? __boundary: (end);		\
})

#define ENTRY_TO_PROT(x) ((x) & ~PG_ADDRESS_MASK)
#define ENTRY_TO_ADDR(x) ((x) & PG_ADDRESS_MASK)

#define EARLY_HPT_ENTRIES (512 * 8 * 4)
#define EARLY_HPT_ENTRY_SIZE (16)
#define EARLY_HPT_ENTRY_QUAD_CNT (EARLY_HPT_ENTRY_SIZE / 8)
#define EARLY_HPT_SIZE (EARLY_HPT_ENTRIES * EARLY_HPT_ENTRY_SIZE)
#define EARLY_HPT_OFFSET_MASK (EARLY_HPT_ENTRIES - 1)         /* the trailing 12 */

// #define HPT_SIZE_MASK (0xfff)      /* 16 * cr3[0:11] for number of entries */
// #define HPT_SIZE_HIDDEN_BITS (4)   
#define EARLY_HPT_CR3_SIZE_VAL (EARLY_HPT_ENTRIES >> HPT_SIZE_HIDDEN_BITS)

#define CR3_TRANSITION_SHIFT (52)
#define CR3_TRANSITION_BIT (0x0010000000000000ULL)

// #define EARLY_HPT_ENTRY_SIZE (16)
// #define EARLY_HPT_ENTRY_QUAD_CNT (EARLY_HPT_ENTRY_SIZE / 8)
// #define EARLY_HPT_SIZE (EARLY_HPT_ENTRIES * EARLY_HPT_ENTRY_SIZE)
// #define EARLY_HPT_OFFSET_MASK (EARLY_HPT_ENTRIES - 1)         /* the trailing 12 */

#define ECPT_4K_WAY 2
#define ECPT_2M_WAY 2
#define ECPT_1G_WAY 0

#define ECPT_4K_USER_WAY 2
#define ECPT_2M_USER_WAY 0
#define ECPT_1G_USER_WAY 0

#define ECPT_KERNEL_WAY (ECPT_4K_WAY + ECPT_2M_WAY + ECPT_1G_WAY)
#define ECPT_USER_WAY (ECPT_4K_USER_WAY + ECPT_2M_USER_WAY + ECPT_1G_USER_WAY)

#define ECPT_TOTAL_WAY (ECPT_KERNEL_WAY + ECPT_USER_WAY)
/* ECPT_TOTAL_WAY <= ECPT_MAX_WAY*/
#define ECPT_MAX_WAY 9

#define ECPT_WAY_TO_CR_SEQ 3,1,5,6,7,9,10,11,12

#endif /* _ASM_X86_ECPT_DEFS_H */