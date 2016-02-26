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
from callee_context import *

DEV_ONLY_CALLS = True
MAX_PROLOG = 180

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
    #print('Processing file: ', filename)
    with open(filename, 'rb') as f:
        elffile = ELFFile(f)

        #Find the entry point
        #print('Entry Point: ', elffile.header.e_entry)
        entry = elffile.header.e_entry

        #Find the section associated with the entry point
        entry_section_i = find_section_by_addr(elffile, f, entry)
        if not entry_section_i:
            print('Entry section not found. Perhaps the sample is obfuscated?')
            return
        entry_section = elffile.get_section(entry_section_i)
        #print('Entry section found: ', entry_section.name)
        entry_section_end = entry + entry_section['sh_size']

        #Find the PLT section
        plt_section = elffile.get_section_by_name('.plt')
        if not plt_section:
            pass
            #print('PLT section not found. Jump reasoning degraded')
        else:
            pass
            #print('PLT section found.')

        #copy out the entry section
        f.seek(entry_section['sh_offset'])
        CODE = b""
        CODE = f.read(entry_section['sh_size'])

        #simple_linear_sweep_extract(CODE, entry, entry_section_end)
        caller_cpc_sweep(CODE, entry, entry_section_end)

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

def caller_cpc_sweep(CODE, entry, entry_end):
    cpc_dict = dict()
    cpc_chain = ""
    cpc_list = ""
    cpc_list_nl = False

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    for inst in md.disasm(CODE, entry):
        #print("0x%x:\t%s\t%s\t" % (inst.address, inst.mnemonic, inst.op_str))
        if is_call(inst.mnemonic):
            una_op = inst.operands[0]
            if una_op.type == X86_OP_IMM:
                if una_op.value.imm >= entry and una_op.value.imm <= entry_end:
                    #cpc = cpc_dict[una_op.value.imm]
                    cpc = cpc_dict.get(una_op.value.imm, None)
                    if cpc is None:
                        offset = una_op.value.imm - entry
                        #print("Entering callee...")
                        FUNC = CODE[offset:offset+MAX_PROLOG]
                        cpc = callee_arg_sweep(FUNC, entry+offset)
                        cpc_dict[una_op.value.imm] = cpc
                        cpc_chain += str(cpc)
                        cpc_list += str(cpc)
                        cpc_list_nl = False
                    else:
                        #print("Stored CPC used")
                        cpc_chain += str(cpc)
                        cpc_list += str(cpc)
                        cpc_list_nl = False

        if is_ret(inst.mnemonic) or is_hlt(inst.mnemonic):
            cpc_chain += ","
            if not cpc_list_nl:
                cpc_list += "\n"
                cpc_list_nl = True

    #print("# of CPCs %d" % len(cpc_dict))
    print(cpc_chain)
    #print(cpc_list)

def callee_arg_sweep(FUNC, entry):
    context = CalleeContext()

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    for inst in md.disasm(FUNC, entry):
        #print("0x%x:\t%s\t%s\t" % (inst.address, inst.mnemonic, inst.op_str))
        if len(inst.operands) == 1:
            una_op = inst.operands[0]
            if una_op.type == X86_OP_REG:
                una_op_name = inst.reg_name(una_op.value.reg)
                if is_arg_reg(una_op_name):
                    #unary operands are set before use, try and add as src
                    context.add_src_arg(una_op_name)

        if (len(inst.operands) == 2):
            dst_op = inst.operands[0]
            src_op = inst.operands[1]

            if dst_op.type == X86_OP_REG:
                dst_op_name = inst.reg_name(dst_op.value.reg)
                if is_arg_reg(dst_op_name):
                    context.add_set_arg(dst_op_name)
            if src_op.type == X86_OP_REG:
                src_op_name = inst.reg_name(src_op.value.reg)
                if is_arg_reg(src_op_name):
                    context.add_src_arg(src_op_name)

        if is_ret(inst.mnemonic) or is_hlt(inst.mnemonic):
            break

    return context.callee_calculate_cpc()

if __name__ == '__main__':
    for filename in sys.argv[1:]:
        process_file(filename)
