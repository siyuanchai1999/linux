/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_INIT_H
#define _ASM_X86_INIT_H

struct x86_mapping_info {
	void *(*alloc_pgt_page)(void *); /* allocate buf for page table */
	void *context;			 /* context for alloc_pgt_page */
	unsigned long page_flag;	 /* page flag for PMD or PUD entry */
	unsigned long offset;		 /* ident mapping offset */
	bool direct_gbpages;		 /* PUD level 1GB page support */
	unsigned long kernpg_flag;	 /* kernel pagetable flag override */


#ifdef CONFIG_X86_64_ECPT
	uint64_t hpt_size;
	uint64_t hpt_page_size;		/* bit x */
#endif
};

int kernel_ident_mapping_init(struct x86_mapping_info *info, pgd_t *pgd_page,
				unsigned long pstart, unsigned long pend);
// int kernel_ident_mapping_init(struct x86_mapping_info *info, uint64_t cr3,
// 			      unsigned long pstart, unsigned long pend);
#endif /* _ASM_X86_INIT_H */
