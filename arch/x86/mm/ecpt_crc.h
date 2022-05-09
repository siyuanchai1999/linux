
#ifndef __X86_MM_ECPT_CRC_H
#define __X86_MM_ECPT_CRC_H

#include <linux/types.h>

#define NUM_CRC64_TABLE 4

inline uint64_t ecpt_crc64_hash(uint64_t vpn, uint32_t way);
inline uint64_t ecpt_crc64_hash_early(uint64_t vpn, uint32_t way, uint64_t kernel_start, uint64_t physaddr);

#endif	/* __X86_MM_ECPT_CRC_H */