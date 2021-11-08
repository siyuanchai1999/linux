#ifndef _ASM_X86_ECPT_DEFS_H
#define _ASM_X86_ECPT_DEFS_H

#define HPT_SIZE_MASK (0xfff)      	/* 16 * cr3[0:11] for number of entries */
#define HPT_SIZE_HIDDEN_BITS (4)    
#define HPT_NUM_ENTRIES_TO_CR3(cr3) (((uint64_t) cr3 ) >> HPT_SIZE_HIDDEN_BITS)
#define HPT_BASE_MASK (~(HPT_SIZE_MASK))
#define GET_HPT_SIZE(cr3) ((((uint64_t) cr3) & HPT_SIZE_MASK ) << HPT_SIZE_HIDDEN_BITS)
#define GET_HPT_BASE(cr3) (((uint64_t) cr3) & HPT_BASE_MASK )



#define PAGE_HEADER_MASK (0xffff000000000000)
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

#define ADDR_REMOVE_OFFSET_4KB(x)   ((x) & ~PAGE_TAIL_MASK_4KB)
#define ADDR_REMOVE_OFFSET_2MB(x)   ((x) & ~PAGE_TAIL_MASK_2MB)
#define ADDR_REMOVE_OFFSET_1GB(x)   ((x) & ~PAGE_TAIL_MASK_1GB)

#define ADDR_TO_OFFSET_4KB(x)   ((x) & PAGE_TAIL_MASK_4KB)
#define ADDR_TO_OFFSET_2MB(x)   ((x) & PAGE_TAIL_MASK_2MB)
#define ADDR_TO_OFFSET_1GB(x)   ((x) & PAGE_TAIL_MASK_1GB)

#define ADDR_TO_PAGE_NUM_4KB(x)   ((ADDR_REMOVE_OFFSET_4KB(x)) >> PAGE_SHIFT_4KB)
#define ADDR_TO_PAGE_NUM_2MB(x)   ((ADDR_REMOVE_OFFSET_2MB(x)) >> PAGE_SHIFT_2MB)
#define ADDR_TO_PAGE_NUM_1GB(x)   ((ADDR_REMOVE_OFFSET_1GB(x)) >> PAGE_SHIFT_1GB)


#define PAGE_NUM_TO_ADDR_4KB(x)   (((uint64_t) x) << PAGE_SHIFT_4KB)
#define PAGE_NUM_TO_ADDR_2MB(x)   (((uint64_t) x) << PAGE_SHIFT_2MB)
#define PAGE_NUM_TO_ADDR_1GB(x)   (((uint64_t) x) << PAGE_SHIFT_1GB)

#define EARLY_HPT_ENTRIES (512 * 8)
#define EARLY_HPT_ENTRY_SIZE (8)
#define EARLY_HPT_SIZE (EARLY_HPT_ENTRIES * EARLY_HPT_ENTRY_SIZE)
#define EARLY_HPT_OFFSET_MASK (EARLY_HPT_ENTRIES - 1)         /* the trailing 12 */

#define HPT_SIZE_MASK (0xfff)      /* 16 * cr3[0:11] for number of entries */
#define HPT_SIZE_HIDDEN_BITS (4)   



#endif /* _ASM_X86_ECPT_DEFS_H */