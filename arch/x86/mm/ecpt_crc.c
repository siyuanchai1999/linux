#include <linux/types.h>

#include "ecpt_crc.h"
#include "ecpt_crc64table.h"

static uint64_t ecpt_crc64_be(uint64_t crc, const void* p, uint64_t len, const uint64_t * table) {
	uint64_t i, t;

	const unsigned char* _p = (const unsigned char*) (p);

	for (i = 0; i < len; i++) {
		t = ((crc >> 56) ^ (*_p++)) & 0xFF;
		crc = table[t] ^ (crc << 8);
	}
	return (crc);
}

inline uint64_t ecpt_crc64_hash(uint64_t vpn, uint32_t way) {
	/* TODO: fix which hash table maps to which way */
	return ecpt_crc64_be(0,
	 	&vpn, 
		5,	/* vpn at most have 5 bytes */
		&ecpt_crc64table[way % NUM_CRC64_TABLE][0] /* beginning of crc64 table */
		);
}

inline uint64_t ecpt_crc64_hash_early(uint64_t vpn, uint32_t way, uint64_t kernel_start, uint64_t physaddr) {
	
	const uint64_t * table = &ecpt_crc64table[way % NUM_CRC64_TABLE][0];
	const uint64_t * fixup_crc64_table = (uint64_t *) ((void *) table - (void *)kernel_start + (void *)physaddr);

	return ecpt_crc64_be(0,
	 	&vpn, 
		5,	/* vpn at most have 5 bytes */
		fixup_crc64_table
		);
}