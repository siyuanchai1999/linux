#ifndef _ECPT_SPECIAL_INST_H
#define _ECPT_SPECIAL_INST_H

/**
 * @brief  ## concatenates symbol together e.g. native_write_cr##N -> native_write_cr1
 * 			# turns input into string tokens e.g. "mov %0,%%cr"#N -> "mov %0,%%cr" "1" -> "mov %0,%%cr1"
 * 
 */
#define DEFINE_native_write_crN(N)                                             \
	static inline void native_write_cr##N(unsigned long val)               \
	{                                                                      \
		asm volatile("mov %0,%%cr" #N : : "r"(val) : "memory");        \
	}

#define DEFINE_native_read_crN(N)                                             \
	static __always_inline unsigned long __native_read_cr##N(void)		\
	{									\
		unsigned long val;						\
		asm volatile("mov %%cr" #N ",%0\n\t" : "=r" (val) : __FORCE_ORDER); \
		return val; 							\
	}


DEFINE_native_write_crN(1)
DEFINE_native_write_crN(5)
DEFINE_native_write_crN(6)
DEFINE_native_write_crN(7)
DEFINE_native_write_crN(9)
DEFINE_native_write_crN(10)
DEFINE_native_write_crN(11)
DEFINE_native_write_crN(12)
DEFINE_native_write_crN(13)
DEFINE_native_write_crN(14)
DEFINE_native_write_crN(15)

DEFINE_native_read_crN(1)
DEFINE_native_read_crN(5)
DEFINE_native_read_crN(6)
DEFINE_native_read_crN(7)
DEFINE_native_read_crN(9)
DEFINE_native_read_crN(10)
DEFINE_native_read_crN(11)
DEFINE_native_read_crN(12)
DEFINE_native_read_crN(13)
DEFINE_native_read_crN(14)
DEFINE_native_read_crN(15)

/**
 *  adding register 16 - 23 will make the
 * assembler throws error Error: bad register name `%cr16'
 * it seems like gcc 11.3 supports cr up to 15.
 *   */

// DEFINE_native_write_crN(16);
// DEFINE_native_write_crN(17);
// DEFINE_native_write_crN(18);
// DEFINE_native_write_crN(19);
// DEFINE_native_write_crN(20);
// DEFINE_native_write_crN(21);
// DEFINE_native_write_crN(22);
// DEFINE_native_write_crN(23);

#endif /* _ECPT_SPECIAL_INST_H */