#-----------------------------------------------------------------------------
# A Three-Pronged Approach to Exploring the Limits of Static Malware Analyses:
# Callsite Parameter Cardinality (CPC) Counting: cpc_extract.py
#
# The driver for ennumerating CPC for a Linux AMD64 binary.
#
# Luke Jones (luke.t.jones.814@gmail.com)
#
#-----------------------------------------------------------------------------
from __future__ import print_function
import sys

from elftools.elf.elffile import ELFFile

from capstone import *
from capstone.x86 import *

from asm_helper import *
from context import *

DEV_ONLY_CALLS = True

def find_section_by_addr(elffile, fstream, addr):
    """ Finds a section by its base address and returns the index
    """
    # Try to find the entry section
    for i in range(elffile['e_shnum']):
        section_offset = elffile['e_shoff'] + i * elffile['e_shentsize']
        # Parse the section header using structs.Elf_Shdr
        fstream.seek(section_offset)
        section_header = elffile.structs.Elf_Shdr.parse_stream(fstream)

        if section_header['sh_addr'] == addr:
            return i
    else:
        print('find_section_by_addr: Address not found in sections')

def process_file(filename):
    print('Processing file: ', filename)
    with open(filename, 'rb') as f:
        elffile = ELFFile(f)

        #Find the entry point
        print('Entry Point: ', elffile.header.e_entry)
        entry = elffile.header.e_entry

        #Find the section associated with the entry point
        entry_section_i = find_section_by_addr(elffile, f, entry)
        if not entry_section_i:
            print('Entry section not found. Perhaps the sample is obfuscated?')
            return
        entry_section = elffile.get_section(entry_section_i)
        print('Entry section found: ', entry_section.name)
        entry_section_end = entry + entry_section['sh_size']

        #Find the PLT section
        plt_section = elffile.get_section_by_name('.plt')
        if not plt_section:
            print('PLT section not found. Jump reasoning degraded')
        else:
            print('PLT section found.')

        #copy out the entry section
        f.seek(entry_section['sh_offset'])
        CODE = b""
        CODE = f.read(entry_section['sh_size'])

        simple_linear_sweep_extract(CODE, entry, entry_section_end)

#Merits: similar structure between O0 samples stands out
#Negatives: cardinality often wrong
def simple_linear_sweep_extract(CODE, entry, entry_end):
    context = CContext()

    #start disassembly
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    for inst in md.disasm(CODE, entry):
        context.count += 1
        #print("0x%x:\t%s\t%s\t" % (inst.address, inst.mnemonic, inst.op_str))

        #Basic arguments: other instructions applicable
        #TODO:(push, pop, possibly others)
        if is_mov(inst.mnemonic) or is_lea(inst.mnemonic):
            if len(inst.operands) >= 1:
                dst_op = inst.operands[0]
        #Basic arguments: other operand types applicable
        #TODO:(MEM, esp. stack)
                if dst_op.type == X86_OP_REG:
                    dst_op_name = inst.reg_name(dst_op.value.reg)
                    if is_arg_reg(dst_op_name):
                        context.add_arg(dst_op_name)

        #heuristic: removing rcx as arg register when set for cmp
        #if is_cmp(inst.mnemonic):
        #    dst_op = inst.operands[0]

        #Basic calls: linear sweep of entry section
        if is_call(inst.mnemonic):
            #only counts calls made to code within entry section
            #trying to focus on invariant code between compilers
            if DEV_ONLY_CALLS:
                dst_op = inst.operands[0]
                if dst_op.type == X86_OP_IMM:
                    if dst_op.value.imm >= entry and dst_op.value.imm <= entry_end:
                        context.found_call()
            else:
                context.found_call()

            #raw_input("Pausing")

        if is_ret(inst.mnemonic):
            context.found_ret()

        #reset arguments if we've waited too long
        if context.count > context.dump_wait:
            context.dump()

    print("%s" % context.cpc_chain)

if __name__ == '__main__':
    for filename in sys.argv[1:]:
        process_file(filename)
