#ifndef X86_EARLY_DEBUG_H
#define X86_EARLY_DEBUG_H

#define DEBUG_STR(__x) { \
		debug_putstr(__FILE__); \
		debug_putstr(":"); \
		debug_putstr(__func__); \
		debug_putstr("  "); \
		debug_putstr(__x); \
	}

#define DEBUG_VAR(__x) { \
		debug_putstr(__FILE__); \
		debug_putstr(":"); \
		debug_putstr(__func__); \
		debug_putstr("  "); \
		debug_putaddr(__x); \
	}


#define debug_putstr(__x)  __putstr(__x)
#define debug_puthex(__x)  __puthex(__x)
#define debug_putaddr(__x) { \
		debug_putstr(#__x ": 0x"); \
		debug_puthex((unsigned long)(__x)); \
		debug_putstr("\n"); \
	}

void __putstr(const char *s);
void __puthex(unsigned long value);
void early_debug_init(void);


#endif /* X86_EARLY_DEBUG_H */
