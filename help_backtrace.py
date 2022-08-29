import subprocess
import sys
import os

# These 2 functions are from the old fixup_addrs.py
def filter_text(nm_line):
	# T/t means text(code) symbol
	return len(nm_line) == 3 and nm_line[1].lower() == 't'

def get_symbols(vmlinux):
	result = subprocess.run(['nm', vmlinux], check=True, capture_output=True)
	return map(lambda l: l.strip().split(),
			   result.stdout.decode('utf-8').split('\n'))

def gen_stubs(vmlinux):
	# Construct a func -> addr map
	# ffffffff811745c0 T ZSTD_freeDStream
	# l[0]			  l[1]		l[2]
	text_syms = sorted(map(lambda l: (int(l[0], 16), l[2]),
						 filter(filter_text, get_symbols(vmlinux))),
					   key=lambda l: l[0])
	return text_syms
	# print('\n'.join(["%s %s" % (hex(i[0]), i[1]) for i in text_syms]))
	# output = stubs % tuple(map(lambda f: text_syms[f], helpers))
	# with open(os.path.join('src', 'stub.rs'), 'w') as stub_f:
		# stub_f.write(output)
def find_function(addr_to_symbol, address):
	prev_addr = 0
	prev_func = '?'
	# print(addr_to_symbol)
	# print(address)
	for addr,func in reversed(addr_to_symbol):
		if (addr <= address):
			return func
		# prev_addr = addr
		# prev_func = func


def rewrite_log(log_path, addr_to_symbol):

	with open(log_path) as log:
		lines = log.readlines()
		for i, line in enumerate(lines):
			#  ? 0xffffffff81200625
			if (line.startswith(' ?')):
				addr = int(line.split(' ')[2], 16)	
				func = find_function(addr_to_symbol, addr)
				lines[i] = line.replace('?', func)
	# print(lines)
	with open(log_path, 'w') as log:
		log.write(''.join(lines))

def main(argv):
	
	if(len(argv) < 2):
		linux_path = 'ecpt.log' 
	else:
		linux_path = argv[1]

	addr_to_symbol = gen_stubs(os.path.join('.', 'vmlinux'))
	rewrite_log(linux_path, addr_to_symbol)

	# prep_headers(os.path.join(linux_path, 'usr/include'))
	return 0

if __name__ == '__main__':
	exit(main(sys.argv))