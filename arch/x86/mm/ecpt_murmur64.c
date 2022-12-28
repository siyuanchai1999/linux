
#include <linux/types.h>

/* refer to https://github.com/abrandoned/murmur2 */
// uint64_t MurmurHash64(const void *key, int len, uint64_t seed)

/* adapted from https://gcc.gnu.org/git/?p=gcc.git;a=blob_plain;f=libstdc%2b%2b-v3/libsupc%2b%2b/hash_bytes.cc;hb=HEAD */

static inline uint64_t unaligned_load(const char* p)
{
	uint64_t result;
	__builtin_memcpy(&result, p, sizeof(result));
	return result;
}

static inline uint64_t load_bytes(const char* p, int n)
{
	uint64_t result = 0;
	--n;
	do {
		result = (result << 8) + (unsigned char) (p[n]);
	} while (--n >= 0);
	return result;
}

static inline uint64_t shift_mix(uint64_t v)
{ 
	return v ^ (v >> 47);
}

uint64_t MurmurHash64(const void* ptr, uint64_t len, uint64_t seed)
{
	static const uint64_t mul = (((uint64_t) 0xc6a4a793ULL) << 32ULL)
				+ (uint64_t) 0x5bd1e995ULL;
	const char* buf = (const char*) (ptr);
	char* p; 
	// Remove the bytes not divisible by the sizeof(uint64_t).  This
	// allows the main loop to process the data as 64-bit integers.
	const uint64_t len_aligned = len & ~(uint64_t)0x7;
	const char* end = buf + len_aligned;
	uint64_t hash = seed ^ (len * mul);

	for (p = (char *) buf; p != end; p += 8)
	{
		const uint64_t data = shift_mix(unaligned_load(p) * mul) * mul;
		hash ^= data;
		hash *= mul;
	}

	if ((len & 0x7) != 0)
	{
		const uint64_t data = load_bytes(end, len & 0x7);
		hash ^= data;
		hash *= mul;
	}

	hash = shift_mix(hash) * mul;
	hash = shift_mix(hash);
	return hash;
}
