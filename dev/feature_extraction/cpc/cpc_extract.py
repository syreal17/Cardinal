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

from capstone import *
from capstone.x86 import *

from file_processing import *
from asm_helper import *
from context import *
from callee_context import *

DEV_ONLY_CALLS = True
MAX_PROLOG_BYTES = 300
DISASM_DEBUG = False
ADDR_DEBUG = False
PRINT_CPC_LIST = False #Alternate is printing cpc_chain #TODO: make this switch

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
    cpc_dict = dict()   #keeps track of function cardinalities already found
    cpc_chain = ""      #this is the more readable form
    cpc_list = ""       #this is the more consumable form
    cpc_list_nl = False #Whether we need a newline in the cpc_list

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    for inst in md.disasm(CODE, entry):

        if DISASM_DEBUG:
            print("0x%x:\t%s\t%s\t" % (inst.address, inst.mnemonic,
                inst.op_str))

        if is_call(inst.mnemonic):
            una_op = inst.operands[0]
            if una_op.type == X86_OP_IMM:
                if una_op.value.imm >= entry and una_op.value.imm <= entry_end:
                    cpc = cpc_dict.get(una_op.value.imm, None)
                    if cpc is None:
                        offset = una_op.value.imm - entry
                        if DISASM_DEBUG:
                            print("Entering callee @ %x" % una_op.value.imm)
                        FUNC = CODE[offset:offset+MAX_PROLOG_BYTES]
                        cpc = callee_arg_sweep(FUNC, entry+offset)
                        cpc_dict[una_op.value.imm] = cpc
                        cpc_chain += str(cpc)
                        cpc_list += str(cpc)
                        cpc_list_nl = False
                    else:
                        cpc_chain += str(cpc)
                        cpc_list += str(cpc)
                        cpc_list_nl = False

        if is_ret(inst.mnemonic) or is_hlt(inst.mnemonic) or is_nop(inst.mnemonic):
            if not cpc_list_nl:     #only add one newline between cpc's
                cpc_list += "\n"
                cpc_list_nl = True
                if ADDR_DEBUG:
                    cpc_chain += str(hex(inst.address))
            cpc_chain += ","        #helpful to provide structure to eye

    if PRINT_CPC_LIST:
        print(cpc_list)
    else:
        print(cpc_chain)

def callee_arg_sweep(FUNC, entry):
    context = CalleeContext()

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    for inst in md.disasm(FUNC, entry):

        if DISASM_DEBUG:
            print("0x%x:\t%s\t%s\t" % (inst.address, inst.mnemonic,
                inst.op_str))

        if len(inst.operands) == 1:
            una_op = inst.operands[0]
            if una_op.type == X86_OP_REG:
                una_op_name = inst.reg_name(una_op.value.reg)
                if is_arg_reg(una_op_name):
                    if inst.mnemonic in r_group or inst.mnemonic in rw_group:
                        context.add_src_arg(una_op_name)
                    elif inst.mnemonic in w_group:
                        context.add_set_arg(una_op_name)
                    else:
                        print("Unrecognized mnemonic: %s" % inst.mnemonic)

        if (len(inst.operands) == 2):
            dst_op = inst.operands[0]
            src_op = inst.operands[1]

            #XOR REG1 REG1 case:
            if dst_op.value.reg == src_op.value.reg:
                if inst.mnemonic in xor_insts or inst.mnemonic in xorx_insts:
                    context.add_set_arg(inst.reg_name(dst_op.value.reg))

            if dst_op.type == X86_OP_REG:
                dst_op_name = inst.reg_name(dst_op.value.reg)
                if is_arg_reg(dst_op_name):
                    if inst.mnemonic in w_r_group:
                        context.add_set_arg(dst_op_name)
                    elif inst.mnemonic in r_r_group or inst.mnemonic in rw_r_group:
                        context.add_src_arg(dst_op_name)
                    else:
                        print("Unrecognized mnemonic: %s" % inst.mnemonic)
            if src_op.type == X86_OP_REG:
                src_op_name = inst.reg_name(src_op.value.reg)
                if is_arg_reg(src_op_name):
                    context.add_src_arg(src_op_name)

        if is_ret(inst.mnemonic) or is_hlt(inst.mnemonic) or \
                                                is_call(inst.mnemonic):
            break

    if DISASM_DEBUG:
        print("leaving callee, cpc=%d" % context.callee_calculate_cpc())

    return context.callee_calculate_cpc()

if __name__ == '__main__':
    for filename in sys.argv[1:]:
        einfo = ELFInfo()
        einfo.process_file(filename)
        #simple_linear_sweep_extract(CODE, entry, entry_section_end)
        caller_cpc_sweep(einfo.code, einfo.entry_point, einfo.entry_end)
