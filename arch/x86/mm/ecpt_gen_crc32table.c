/**
 * Reference to generate crc32 table 
 * 	https://github.com/gcc-mirror/gcc/blob/master/libiberty/crc32.c
 */


/* crc32.c
   Copyright (C) 2009-2022 Free Software Foundation, Inc.
   This file is part of the libiberty library.
   This file is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   In addition to the permissions in the GNU General Public License, the
   Free Software Foundation gives you unlimited permission to link the
   compiled version of this file into combinations with other programs,
   and to distribute those combinations without any restriction coming
   from the use of this file.  (The General Public License restrictions
   do apply in other respects; for example, they cover modification of
   the file, and distribution when not linked into a combined
   executable.)
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston, MA 02110-1301, USA.
*/

#include <stdio.h>
int
main ()
{
		unsigned int i, j;
		unsigned int c;
		int table[256];
		for (i = 0; i < 256; i++)
		{
		for (c = i << 24, j = 8; j > 0; --j)
		c = c & 0x80000000 ? (c << 1) ^ 0x04c11db7 : (c << 1);
		table[i] = c;
		}
		printf ("static const unsigned int crc32_table[] =\n{\n");
		for (i = 0; i < 256; i += 4)
		{
		printf ("  0x%08x, 0x%08x, 0x%08x, 0x%08x",
			table[i + 0], table[i + 1], table[i + 2], table[i + 3]);
		if (i + 4 < 256)
		putchar (',');
		putchar ('\n');
		}
		printf ("};\n");
		return 0;
	}
