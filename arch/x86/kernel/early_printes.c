/* Developed by Yifei, intend to do debug hpt before high end mapping was created
	So far as I tested, it didn't really work, but it can be helpful in the future.


 */


__attribute__((__format__(printf, 1, 2)))
static void printes(const char *format, ...);

#define printes_fmt_on_stack(format, ...) do { 			\
	char fmt_on_stack[] = (format);				\
	printes(fmt_on_stack __VA_OPT__(,) __VA_ARGS__);	\
} while (0)

static unsigned long pes_strlen(const char *s)
{
	register unsigned long len = 0;
	while (s[len] != '\0')
		len++;
	return len;
}

static char *pes_strrev(char *s)
{
	register char tmp;
	register unsigned long beg = 0;
	register unsigned long end = pes_strlen(s) - 1;

	while (beg < end) {
		tmp = s[end];
		s[end] = s[beg];
		s[beg] = tmp;
		beg++;
		end--;
	}
	return s;
}

static char *pes_itoa(unsigned long value, char *buf, int radix)
{
	const char lookup[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	char *newbuf = buf;
	int i;
	unsigned long newval = value;

	/* Special case for zero */
	if (value == 0) {
		buf[0] = '0';
		buf[1] = '\0';
		return buf;
	}

	/* Go through the number one place value at a time, and add the
	* correct digit to "newbuf".  We actually add characters to the
	* ASCII string from lowest place value to highest, which is the
	* opposite of how the number should be printed.  We'll reverse the
	* characters later. */
	while (newval > 0) {
		i = newval % radix;
		*newbuf = lookup[i];
		newbuf++;
		newval /= radix;
	}

	/* Add a terminating NULL */
	*newbuf = '\0';

	/* Reverse the string and return */
	return pes_strrev(buf);
}

static unsigned long pes_atoi(const char *nptr, const char **endptr)
{
	unsigned long ret = 0;
	const char *end;

	if (!endptr)
		endptr = &end;

	*endptr = nptr;

	for (; **endptr; (*endptr)++) {
		if (**endptr < '0' || **endptr > '9')
			break;
		ret = ret * 10 + (**endptr - '0');
	}

	return ret;
}

static inline void pes_outb(unsigned short port, unsigned char val)
{
	asm volatile ( "outb %0, %1" : : "a"(val), "Nd"(port) );
}

static inline unsigned char pes_inb(unsigned short port)
{
	unsigned char ret;
	asm volatile ( "inb %1, %0"
		: "=a"(ret)
		: "Nd"(port) );
	return ret;
}

static void pes_emit(const char *str)
{
	while (*str) {
		while ((pes_inb(0x3f8 + 5) & 0x20) == 0);
		pes_outb(0x3f8, *str++);
	}
}

/* Standard printf().
 * Only supports the following format strings:
 * %%  - print a literal '%' character
 * %x  - print a number in hexadecimal
 * %u  - print a number as an unsigned integer
 * %d  - print a number as a signed integer
 * %c  - print a character
 * %s  - print a string
 * %#x - print a number in 64-bit aligned hexadecimal, i.e.
 *       print 16 hexadecimal digits, zero-padded on the left.
 *       For example, the hex number "E" would be printed as
 *       "000000000000000E".
 *       Note: This is slightly different than the libc specification
 *       for the "#" modifier (this implementation doesn't add a "0x" at
 *       the beginning), but I think it's more flexible this way.
 *       Also note: %x is the only conversion specifier that can use
 *       the "#" modifier to alter output. */
static void pes_do(const char *format, __builtin_va_list ap)
{
	bool alternate, zero_pad, left_adjust, space, always_sign;
	unsigned int width;
	bool precision_given;
	unsigned int precision;
	char size;
	long value, value_abs;
	char conv_buf[40];
	long num_len;
	long precision_pad, space_pad;
	char *prefix;
	char *value_str;
	long len;
	int i;

	for (; *format; format++) {
		if (*format != '%') {
			pes_emit((char []){*format, 0});
			continue;
		}

		format++;

		alternate = false;
		zero_pad = false;
		left_adjust = false;
		space = false;
		always_sign = false;

// flags:
		for (; *format; format++) {
			switch (*format) {
			case '#':
				alternate = true;
				break;
			case '0':
				zero_pad = true;
				break;
			case '-':
				left_adjust = true;
				break;
			case ' ':
				space = true;
				break;
			case '+':
				always_sign = true;
				break;
			default:
				goto width;
			}
		}

		if (left_adjust)
			zero_pad = false;
		if (always_sign)
			space = false;

width:;
		width = pes_atoi(format, &format);

// precision:
		precision_given = false;
		precision = 0;
		if (*format == '.') {
			format++;
			precision = pes_atoi(format, &format);
			precision_given = true;
		} else if (zero_pad) {
			precision = width;
			width = 0;
			precision_given = true;
		}
		zero_pad = false;

// length:
		size = 32;
		if (format[0] == 'h' && format[1] == 'h') {
			size = 8;
			format += 2;
		} else if (format[0] == 'l' && format[1] == 'l') {
			size = 64;
			format += 2;
		} else if (format[0] == 'h') {
			size = 16;
			format += 1;
		} else if (format[0] == 'l') {
			format += 1;
		} else if (format[0] == 'q' || format[0] == 'j' || format[0] == 'z' || format[0] == 't') {
			size = 64;
			format += 1;
		}

// specifier:
		switch (*format) {
		case 'd':
		case 'i': {
			switch (size) {
			case 8:
				value = (char)__builtin_va_arg(ap, int);
				break;
			case 16:
				value = (short)__builtin_va_arg(ap, int);
				break;
			case 32:
				value = __builtin_va_arg(ap, int);
				break;
			case 64:
				value = __builtin_va_arg(ap, long long);
				break;
			}
			value_abs = value < 0 ? -value : value;

			pes_itoa(value_abs, conv_buf, 10);

			if (!precision_given)
				precision = 1;

			if (!value && !precision)
				conv_buf[0] = '\0';

			num_len = pes_strlen(conv_buf);
			precision_pad = precision - num_len;
			if (precision_pad < 0)
				precision_pad = 0;

			space_pad = width - num_len - precision_pad - (value < 0 || space || always_sign);
			if (space_pad < 0)
				space_pad = 0;

			if (!left_adjust) {
				for (i = 0; i < space_pad; i++)
					pes_emit((char []){' ', 0});
			}

			if (value < 0)
				pes_emit((char []){'-', 0});
			else if (always_sign)
				pes_emit((char []){'+', 0});
			else if (space)
				pes_emit((char []){' ', 0});

			for (i = 0; i < precision_pad; i++)
				pes_emit((char []){'0', 0});

			pes_emit(conv_buf);

			if (left_adjust) {
				for (i = 0; i < space_pad; i++)
					pes_emit((char []){' ', 0});
			}
			break;
		}
		case 'o':
		case 'u':
		case 'p':
		case 'x':
		case 'X': {
			if (*format == 'p') {
				alternate = true;
				size = 64;
			}

			switch (size) {
			case 8:
				value = (char)__builtin_va_arg(ap, int);
				break;
			case 16:
				value = (short)__builtin_va_arg(ap, int);
				break;
			case 32:
				value = __builtin_va_arg(ap, int);
				break;
			case 64:
				value = __builtin_va_arg(ap, long long);
				break;
			}

			prefix = (char []){0};
			if (alternate) {
				switch (*format) {
				case 'o':
					prefix = (char []){'0', 0};
					break;
				case 'p':
				case 'x':
				case 'X':
					precision_given = true;
					precision = 16;
					break;
				}
			}

			switch (*format) {
			case 'o':
				pes_itoa(value, conv_buf, 8);
				break;
			case 'u':
				pes_itoa(value, conv_buf, 10);
				break;
			default:
				pes_itoa(value, conv_buf, 16);
				break;
			}

			if (!precision_given)
				precision = 1;

			if (!value && !precision)
				conv_buf[0] = '\0';

			num_len = pes_strlen(conv_buf);
			precision_pad = precision - num_len;
			if (precision_pad < 0)
				precision_pad = 0;

			space_pad = width - num_len - precision_pad - pes_strlen(prefix);
			if (space_pad < 0)
				space_pad = 0;

			if (*format == 'x' || *format == 'p') {
				for (i = 0; i < num_len; i++) {
					if (conv_buf[i] >= 'A' && conv_buf[i] <= 'F')
						conv_buf[i] = conv_buf[i] - 'A' + 'a';
				}
			}

			if (!left_adjust) {
				for (i = 0; i < space_pad; i++)
					pes_emit((char []){' ', 0});
			}

			pes_emit(prefix);

			for (i = 0; i < precision_pad; i++)
				pes_emit((char []){'0', 0});

			pes_emit(conv_buf);

			if (left_adjust) {
				for (i = 0; i < space_pad; i++)
					pes_emit((char []){' ', 0});
			}
			break;
		}
		case 'c':
			pes_emit((char []){(char)__builtin_va_arg(ap, int), 0});
			break;
		case 's': {
			value_str = __builtin_va_arg(ap, char *);
			len = pes_strlen(value_str);

			num_len = len;
			if (num_len > precision && precision_given)
				num_len = precision;

			space_pad = width - num_len;
			if (space_pad < 0)
				space_pad = 0;

			if (!left_adjust) {
				for (i = 0; i < space_pad; i++)
					pes_emit((char []){' ', 0});
			}

			if (!precision_given || precision >= len)
				pes_emit(value_str);
			else {
				for (i = 0; i < precision; i++) {
					pes_emit((char []){value_str[i], 0});
				}
			}

			if (left_adjust) {
				for (i = 0; i < space_pad; i++)
					pes_emit((char []){' ', 0});
			}

			break;
		}
		case '%':
			pes_emit((char []){'%', 0});
			break;
		default:
			break;
		}
	}
}


static void printes(const char *format, ...)
{
	__builtin_va_list ap;
	__builtin_va_start(ap, format);

	pes_do(format, ap);

	__builtin_va_end(ap);
}
