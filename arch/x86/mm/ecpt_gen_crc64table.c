// SPDX-License-Identifier: GPL-2.0
#include <inttypes.h>
#include <stdio.h>

#include "ecpt_crc.h"

/* source of the polynomials: https://en.wikipedia.org/wiki/Cyclic_redundancy_check */
#define CRC64_ECMA182_POLY_0 0x42F0E1EBA9EA3693ULL
#define CRC64_ECMA182_POLY_1 0xC96C5795D7870F42ULL
#define CRC64_ECMA182_POLY_2 0x92D8AF2BAF0E1E85ULL
#define CRC64_ECMA182_POLY_3 0xA17870F5D4F51B49ULL

static uint64_t polynomials[NUM_CRC64_TABLE] = {
	CRC64_ECMA182_POLY_0,
	CRC64_ECMA182_POLY_1,
	CRC64_ECMA182_POLY_2,
	CRC64_ECMA182_POLY_3
};

static uint64_t crc64_table[NUM_CRC64_TABLE][256] = {0};

static void generate_crc64_table(uint64_t poly, int n_table)
{
	uint64_t i, j, c, crc;

	for (i = 0; i < 256; i++) {
		crc = 0;
		c = i << 56;

		for (j = 0; j < 8; j++) {
			if ((crc ^ c) & 0x8000000000000000ULL)
				crc = (crc << 1) ^ poly;
			else
				crc <<= 1;
			c <<= 1;
		}

		crc64_table[n_table][i] = crc;
	}
}

static void print_crc64_table(void)
{
	int i, t;

	printf("/* this file is generated - do not edit */\n\n");
	printf("#include <linux/types.h>\n");
	printf("#include <linux/cache.h>\n\n");
	printf("static const u64 ____cacheline_aligned ecpt_crc64table[%d][256] = {\n", NUM_CRC64_TABLE);
	for (t = 0; t < NUM_CRC64_TABLE; t++) {
		printf("{");
		for (i = 0; i < 256; i++) {
			printf("\t0x%016" PRIx64 "ULL", crc64_table[t][i]);
			if (i & 0x1)
				printf(",\n");
			else
				printf(", ");
		}
		printf("},\n");
	}
	printf("};\n");
}

int main(int argc, char *argv[])
{
	int i;
	for (i = 0; i < NUM_CRC64_TABLE; i++) {
		generate_crc64_table(polynomials[i], i);
	}
	print_crc64_table();
	return 0;
}