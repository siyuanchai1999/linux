#ifndef BOOT_COMPRESSED_ECPT_H
#define BOOT_COMPRESSED_ECPT_H

#include <asm/ECPT.h>
#include <asm/pgtable.h>

/* used in compressed kernel, will be replaced in the future */
int hpt_insert(uint64_t cr3, uint64_t vaddr, uint64_t paddr, ecpt_pgprot_t prot, uint32_t override);


#endif /* BOOT_COMPRESSED_ECPT_H */
