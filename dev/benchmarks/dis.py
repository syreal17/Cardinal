from __future__ import print_function

from capstone import *
from elftools.elf.elffile import ELFFile

import sys

if __name__ == "__main__":

    filename = sys.argv[1]
    with open(filename, 'rb') as f:
        elffile = ELFFile(f)
        entry_section = elffile.get_section_by_name('.text')
        f.seek(entry_section['sh_offset'])
        CODE = f.read(entry_section['sh_size'])

        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = True
        for inst in md.disasm(CODE, 0):
            print("%s %s" % (inst.mnemonic, inst.op_str))
