#-----------------------------------------------------------------------------
# A Three-Pronged Approach to Exploring the Limits of Static Malware Analyses:
# Callsite Parameter Cardinality (CPC) Counting: cpc_extract.py
#
# The driver for ennumerating CPC for a Linux AMD64 binary with Capstone.
#
# Luke Jones (luke.t.jones.814@gmail.com)
#
# The MIT License (MIT)
# Copyright (c) 2016 Chthonian Cyber Services
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
#  in the Software without restriction, including without limitation the rights
#  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#-----------------------------------------------------------------------------
from __future__ import print_function
import sys

from capstone import *
from capstone.x86 import *

from file_processing import *
from asm_helper import *
from context import *
from callee_context import *
from bb import *
from func import *

DEV_ONLY_CALLS = True
MAX_PROLOG_BYTES = 300
DISASM_DEBUG = False
ADDR_DEBUG = False
DICT_DEBUG = False
PRINT_CPC_CHAIN = False
PRINT_CPC_LIST = False #this is used for bloom and jaccard
PRINT_CPC_DICT = False

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


bb_list = list()
bb_dict = dict()

def boundary_sweep(CODE, entry, entry_end):
    in_bb = False
    end_bb = False
    need_fall_bb = False
    nop_block = False
    call_targets = list()

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    for inst in md.disasm(CODE, entry):
        bb = None
        #If we're not already in basic block, find existing or create new one
        if not in_bb:
            in_bb = True
            try:
                bb = bb_dict[inst.address]
                bb.index = len(bb_list)
            except KeyError:
                bb = BasicBlock(len(bb_list),inst.address, None, None, None, None)
                bb_dict[inst.address] = bb
            bb_list.append(bb)

            #If previously we needed to end a basic block, supply next_addr
            pbb = bb_list[len(bb_list)-2]
            if end_bb:
                end_bb = False
                pbb.next_addr = inst.address

            #Not an effective solution to the align problem
            #if nop_block:
            #    nop_block = False
            #    ppbb = bb_list[len(bb_list)-3]
            #    ppbb.next_addr = inst.address

            #If previously we needed a fall through block, supply it
            if need_fall_bb:
                need_fall_bb = False
                pbb.fall_block = bb

        #If we're still in a basic block from before...
        else:
            #If this ins has already been jumped to, make a bb, a close the prv
            try:
                bb = bb_dict[inst.address]
                bb.index = len(bb_list)
                bb_list.append(bb)
                pbb = bb_list[len(bb_list)-2]
                pbb.next_addr = inst.address
                pbb.fall_block = bb
            #Other wise, just get the current bb from the list
            except KeyError:
                bb = bb_list[len(bb_list)-1]

        #Always update bb with new ending and new addr
        bb.end_addr = inst.address
        bb.addrs.append(inst.address)
        bb_dict[inst.address] = bb

        if is_jcc(inst.mnemonic):
            una_op = inst.operands[0]
            #If the address is an immediate, make a provisional
            #bb for it
            if una_op.type == X86_OP_IMM:
                in_bb = False
                end_bb = True
                need_fall_bb = True
                if una_op.value.imm >= entry and una_op.value.imm <= entry_end:
                    try:
                        jbb = bb_dict[una_op.value.imm]
                        if jbb.start_addr == una_op.value.imm:
                            bb.jump_block = jbb
                        else:
                            bb.jump_block = jbb.split(una_op.value.imm)
                            for addr in bb.jump_block.addrs:
                                bb_dict[addr] = bb.jump_block
                            i = bb_list.index(jbb)
                            bb_list.insert(i+1, bb.jump_block)
                    except KeyError:
                        jbb = BasicBlock(None, una_op.value.imm, None, None, None, None)
                        bb_dict[una_op.value.imm] = jbb
                        bb.jump_block = jbb

        if is_jmp(inst.mnemonic):
            una_op = inst.operands[0]
            #If the address is an immediate, make a provisional
            #bb for it
            if una_op.type == X86_OP_IMM:
                in_bb = False
                end_bb = True
                need_fall_bb = False
                if una_op.value.imm >= entry and una_op.value.imm <= entry_end:
                    try:
                        jbb = bb_dict[una_op.value.imm]
                        if jbb.start_addr == una_op.value.imm:
                            bb.jump_block = jbb
                        else:
                            bb.jump_block = jbb.split(una_op.value.imm)
                            for addr in bb.jump_block.addrs:
                                bb_dict[addr] = bb.jump_block
                            i = bb_list.index(jbb)
                            bb_list.insert(i+1, bb.jump_block)
                    except KeyError:
                        jbb = BasicBlock(None, una_op.value.imm, None, None, None, None)
                        bb_dict[una_op.value.imm] = jbb
                        bb.jump_block = jbb

        #remember calls for later (starting points)
        if is_call(inst.mnemonic):
            una_op = inst.operands[0]
            if una_op.type == X86_OP_IMM:
                if una_op.value.imm >= entry and una_op.value.imm <= entry_end:
                    call_targets.append(una_op.value.imm)

        if is_ret(inst.mnemonic) or is_hlt(inst.mnemonic):
            in_bb = False
            end_bb = True
            need_fall_bb = False

        if is_nop(inst.mnemonic):
            in_bb = False
            end_bb = True
            need_fall_bb = True
            nop_block = True

    for bb in bb_list:
        bb.debug_print()
    find_funcs()
    for func in func_list:
        func.debug_print()
    #raw_input()

bb_func = list()
func_list = list()
def add_bb(bb):
    #print("%x" % bb.start_addr)
    #raw_input()
    bb_func.append(bb)
    if bb.fall_block != None and bb_func.count(bb.fall_block) == 0:
        add_bb(bb.fall_block)
    if bb.jump_block != None and bb_func.count(bb.jump_block) == 0:
        add_bb(bb.jump_block)

def find_funcs():
    while len(bb_list) != 0:
        head_bb = bb_list[0]
        func = Func(head_bb.start_addr, None)
        #print("%x------------" % head_bb.start_addr)
        add_bb(head_bb)
        #sort bb_func on starting address
        bb_func.sort(cmp=lambda x,y: int(x.start_addr - y.start_addr))
        #walk start and end addr to check adjacency
        #remove bb_func bbs from bb_list
        i = bb_func.index(head_bb)
        next_addr = head_bb.start_addr
        for x in range(i,len(bb_func)):
            bb = bb_func[x]
            #print("%x %x" % (bb.start_addr, bb.next_addr))
            if bb.start_addr == next_addr:
                #print("%x" % bb.start_addr)
                if bb_list.count(bb) != 0:
                    bb_list.remove(bb)
                func.end_addr = bb.end_addr
                next_addr = bb.next_addr
            else:
                break
        #raw_input()

        func_list.append(func)

def caller_cpc_sweep(CODE, entry, entry_end, addr_to_sym):
    cpc_dict = dict()   #keeps track of function cardinalities already found
    cpc_chain = ""      #this is the more readable form
    cpc_list = ""       #this is the more consumable form
    cpc_list_nl = False  #Whether we need a newline in the cpc_list
    cpc_first = True
    found_lib_call = False

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
                        #raw_input("Press key to continue")
                        FUNC = CODE[offset:offset+MAX_PROLOG_BYTES]
                        cpc = callee_arg_sweep(FUNC, entry+offset)
                        cpc_dict[una_op.value.imm] = cpc
                        if cpc_list_nl and not cpc_first:
                            cpc_list += "\n"
                            #cpc_chain += ","
                        cpc_list += str(cpc)
                        cpc_list_nl = False
                        cpc_chain += str(cpc)
                        cpc_first = False
                    else:
                        if cpc_list_nl and not cpc_first:
                            cpc_list += "\n"
                            #cpc_chain += ","
                        cpc_list += str(cpc)
                        cpc_list_nl = False
                        cpc_chain += str(cpc)
                        cpc_first = False
                else:
                    found_lib_call = True

        if is_ret(inst.mnemonic) or is_hlt(inst.mnemonic) or\
                                                is_nop(inst.mnemonic):
            if not cpc_list_nl:     #only add one newline between cpc's
                #cpc_list += "\n"
                cpc_list_nl = True
                if ADDR_DEBUG:
                    cpc_chain += str(hex(inst.address))
            cpc_chain += ","
            if is_ret(inst.mnemonic):
                if found_lib_call:
                    pass
                    #cpc_chain += ":"
                else:
                    pass
                    #cpc_chain += "."
            elif is_nop(inst.mnemonic):
                if found_lib_call:
                    pass
                    #cpc_chain += ";"
                else:
                    pass
                    #cpc_chain += ","
            else:
                pass
                #cpc_chain += "_"

            found_lib_call = False


    if PRINT_CPC_LIST:
        print(cpc_list)
    if PRINT_CPC_CHAIN:
        print(cpc_chain)
    if PRINT_CPC_DICT:
        if DICT_DEBUG:
            print("cpc_dict = %d long" % len(cpc_dict))
        for addr in cpc_dict:
            try:
                func_name = addr_to_sym[addr]
                cpc = cpc_dict[addr]
                print("%s: %d" % (func_name, cpc))
            except KeyError:
                if DICT_DEBUG:
                    print("Addr %x not in dictionary" % addr)
                pass

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
            if una_op.type == X86_OP_MEM:
                if una_op.value.mem.base != 0:
                    base_op_name = inst.reg_name(una_op.value.mem.base)
                    if is_arg_reg(base_op_name):
                        context.add_src_arg(base_op_name)
                if una_op.value.mem.index != 0:
                    index_op_name = inst.reg_name(una_op.value.mem.index)
                    if is_arg_reg(index_op_name):
                        context.add_src_arg(index_op_name)

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
            elif dst_op.type == X86_OP_MEM:
                if dst_op.value.mem.base != 0:
                    base_op_name = inst.reg_name(dst_op.value.mem.base)
                    if is_arg_reg(base_op_name):
                        context.add_src_arg(base_op_name)
                if dst_op.value.mem.index != 0:
                    index_op_name = inst.reg_name(dst_op.value.mem.index)
                    if is_arg_reg(index_op_name):
                        context.add_src_arg(index_op_name)
            if src_op.type == X86_OP_REG:
                src_op_name = inst.reg_name(src_op.value.reg)
                if is_arg_reg(src_op_name):
                    context.add_src_arg(src_op_name)
            elif src_op.type == X86_OP_MEM:
                if src_op.value.mem.base != 0:
                    base_op_name = inst.reg_name(src_op.value.mem.base)
                    if is_arg_reg(base_op_name):
                        context.add_src_arg(base_op_name)
                if src_op.value.mem.index != 0:
                    index_op_name = inst.reg_name(src_op.value.mem.index)
                    if is_arg_reg(index_op_name):
                        context.add_src_arg(index_op_name)

        #TODO: 3 operand instructions. acquire example code first

        if is_ret(inst.mnemonic) or is_hlt(inst.mnemonic) or \
                            is_call(inst.mnemonic) or is_nop(inst.mnemonic):
            break

    if DISASM_DEBUG:
        print("leaving callee, cpc=%d" % context.callee_calculate_cpc())

    #print("-----")
    #context.print_arg_regs()
    return context.callee_calculate_cpc()

if __name__ == '__main__':
    if sys.argv[1] == '-c':
        PRINT_CPC_CHAIN = True
    elif sys.argv[1] == '-l':
        PRINT_CPC_LIST = True
    elif sys.argv[1] == '-d':
        PRINT_CPC_DICT = True
    else:
        print("Unknown option: %s. c for chain, l for list, d for dictionary"
              % sys.argv[1])

    for filename in sys.argv[2:]:
        einfo = ELFInfo()
        einfo.process_file(filename)
        #simple_linear_sweep_extract(CODE, entry, entry_section_end)
        #boundary_sweep(einfo.code, einfo.entry_point, einfo.entry_end)
        caller_cpc_sweep(einfo.code, einfo.entry_point, einfo.entry_end,
                         einfo.addr_to_sym)
