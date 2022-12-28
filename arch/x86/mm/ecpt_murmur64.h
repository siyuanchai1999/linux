#ifndef __X86_MM_ECPT_MURMUR64_H
#define __X86_MM_ECPT_MURMUR64_H

#include <linux/types.h>

uint64_t MurmurHash64(const void *key, uint64_t len, uint64_t seed);

#endif	/* __X86_MM_ECPT_MURMUR64_H */
