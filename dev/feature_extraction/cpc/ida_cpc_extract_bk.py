# -----------------------------------------------------------------------------
# A Three-Pronged Approach to Exploring the Limits of Static Malware Analyses:
# Callsite Parameter Cardinality (CPC) Counting: ida_cpc_extract_bk.py
#
# The driver for ennumerating CPC for a Linux AMD64 binary using IDA Pro.
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
# -----------------------------------------------------------------------------
from idaapi import *
from idautils import *
from idc import *
import re
import sys
import copy
idaapi.require("asm_helper")
idaapi.require("callee_context")
idaapi.require("caller_context")

MAX_DEPTH = 4
MAX_CALLEE_SWEEP = 1000
def callee_arg_sweep(ea, debug, next_func_ea, n):
    if debug:
        print("next_func_ea:%x" % next_func_ea)

    context = callee_context.CalleeContext()
    stack_args = list()

    for head in Heads(ea, ea+MAX_CALLEE_SWEEP):
        mnem = GetMnem(head)
        num_opnds = 0
        opnd_1 = GetOpnd(head, 0)
        opnd_2 = GetOpnd(head, 1)
        opnd_3 = GetOpnd(head, 2)

        if opnd_1 != "":
            num_opnds = 1
        if opnd_2 != "":
            num_opnds = 2
        if opnd_3 != "":
           num_opnds = 3

        if head >= next_func_ea:
            break

        if asm_helper.is_jmp(mnem) or asm_helper.is_call(mnem):
            op_type = GetOpType(head, 0)
            if op_type == o_near or op_type == o_far:
                op_val = GetOperandValue(head, 0)
                if op_val in func_ea_list:
                    if n < MAX_DEPTH:
                        child_context = callee_context_dict.get(op_val, None)
                        if child_context is None:
                            i = func_ea_list.index(op_val)
                            if func_name_list[i] == '//':
                                child_context = callee_arg_sweep(op_val, True, func_ea_list[i+1], n+1)
                            else:
                                child_context = callee_arg_sweep(op_val, False, func_ea_list[i+1], n+1)
                            callee_context_dict[op_val] = child_context

                        cpc = child_context.calculate_cpc()
                        if debug:
                            print("child cpc: %d" % cpc)
                        if cpc < 14: #ltj: clumsy checking for varargs function
                            context.add_child_context(child_context)
                    break

        if "arg_" in opnd_2:
            if debug:
                print("here2")
            if opnd_2 not in stack_args:
                stack_args.append(opnd_2)
                if debug:
                    print("stack arg: %s" % opnd_2)

        if "arg_" in opnd_3:
            if debug:
                print("here3")
            if opnd_3 not in stack_args:
                stack_args.append(opnd_3)
                if debug:
                    print("stack arg: %s" % opnd_3)

        if num_opnds == 0:
            if debug:
                print("%x: %s" % (head,mnem))

        if num_opnds == 1:
            if debug:
                print("%x: %s %s" % (head,mnem,opnd_1))

            opnd_1_type = GetOpType(head, 0)
            if opnd_1_type == o_reg:
                if asm_helper.is_arg_reg(opnd_1):
                    if mnem in asm_helper.r_group or mnem in asm_helper.rw_group:
                        context.add_src_arg(opnd_1)
                    elif mnem in asm_helper.w_group:
                        context.add_set_arg(opnd_1)
                    else:
                        print("Unrecognized mnemonic: %x: %s %s" % (head,mnem,opnd_1))
            if opnd_1_type == o_phrase or opnd_1_type == o_displ:
                for arg in arg_extract(opnd_1):
                    context.add_src_arg(arg)

        if num_opnds == 2:
            opnd_1_type = GetOpType(head, 0)
            opnd_2_type = GetOpType(head, 1)

            if debug:
                print("%x: %s %s %s" % (head,mnem,opnd_1,opnd_2))

            #XOR REG1 REG1 case:
            if opnd_1 == opnd_2:
                if mnem in asm_helper.xor_insts or mnem in asm_helper.xorx_insts:
                    context.add_set_arg(opnd_1)

            # ltj:moved this before opnd_1 to fix case of movsxd rdi edi making rdi set
            if opnd_2_type == o_reg:
                if asm_helper.is_arg_reg(opnd_2):
                    context.add_src_arg(opnd_2)
            elif opnd_2_type == o_phrase or opnd_2_type == o_displ:
                for arg in arg_extract(opnd_2):
                    context.add_src_arg(arg)

            if opnd_1_type == o_reg:
                if asm_helper.is_arg_reg(opnd_1):
                    if mnem in asm_helper.w_r_group:
                        context.add_set_arg(opnd_1)
                    elif mnem in asm_helper.r_r_group or mnem in asm_helper.rw_r_group:
                        context.add_src_arg(opnd_1)
                    else:
                        print("Unrecognized mnemonic: %x: %s %s %s" % (head,mnem,opnd_1,opnd_2))
            elif opnd_1_type == o_phrase or opnd_1_type == o_displ:
                for arg in arg_extract(opnd_1):
                    context.add_src_arg(arg)

        if num_opnds == 3:
            opnd_1_type = GetOpType(head, 0)
            opnd_2_type = GetOpType(head, 1)
            opnd_3_type = GetOpType(head, 2)

            if debug:
                print("%x: %s %s %s %s" % (head,mnem,opnd_1,opnd_2,opnd_3))

            if opnd_1_type == o_reg:
                if asm_helper.is_arg_reg(opnd_1):
                    context.add_set_arg(opnd_1)
            elif opnd_1_type == o_phrase or opnd_1_type == o_displ:
                for arg in arg_extract(opnd_1):
                    context.add_src_arg(arg)

            if opnd_2_type == o_reg:
                if asm_helper.is_arg_reg(opnd_2):
                    context.add_src_arg(opnd_2)
            elif opnd_2_type == o_phrase or opnd_2_type == o_displ:
                for arg in arg_extract(opnd_2):
                    context.add_src_arg(arg)

            if opnd_3_type == o_reg:
                if asm_helper.is_arg_reg(opnd_3):
                    context.add_src_arg(opnd_3)
            elif opnd_3_type == o_phrase or opnd_3_type == o_displ:
                for arg in arg_extract(opnd_3):
                    context.add_src_arg(arg)

    if debug:
        print("stack_args len: %d" % len(stack_args))
    context.extra_args = len(stack_args)

    if debug:
        context.print_arg_regs()

    return context

def arg_extract(opnd):
    arg_list = list()

    arg_rdi = check_arg(asm_helper.arg_reg_rdi, opnd)
    arg_rsi = check_arg(asm_helper.arg_reg_rsi, opnd)
    arg_rdx = check_arg(asm_helper.arg_reg_rdx, opnd)
    arg_rcx = check_arg(asm_helper.arg_reg_rcx, opnd)
    arg_r10 = check_arg(asm_helper.arg_reg_r10, opnd)
    arg_r8 = check_arg(asm_helper.arg_reg_r8, opnd)
    arg_r9 = check_arg(asm_helper.arg_reg_r9, opnd)
    arg_xmm0 = check_arg(asm_helper.arg_reg_xmm0, opnd)
    arg_xmm1 = check_arg(asm_helper.arg_reg_xmm1, opnd)
    arg_xmm2 = check_arg(asm_helper.arg_reg_xmm2, opnd)
    arg_xmm3 = check_arg(asm_helper.arg_reg_xmm3, opnd)
    arg_xmm4 = check_arg(asm_helper.arg_reg_xmm4, opnd)
    arg_xmm5 = check_arg(asm_helper.arg_reg_xmm5, opnd)
    arg_xmm6 = check_arg(asm_helper.arg_reg_xmm6, opnd)
    arg_xmm7 = check_arg(asm_helper.arg_reg_xmm7, opnd)

    if arg_rdi != "":
        arg_list.append(arg_rdi)
    if arg_rsi != "":
        arg_list.append(arg_rsi)
    if arg_rdx != "":
        arg_list.append(arg_rdx)
    if arg_rcx != "":
        arg_list.append(arg_rcx)
    if arg_r10 != "":
        arg_list.append(arg_r10)
    if arg_r8 != "":
        arg_list.append(arg_r8)
    if arg_r9 != "":
        arg_list.append(arg_r9)
    if arg_xmm0 != "":
        arg_list.append(arg_xmm0)
    if arg_xmm1 != "":
        arg_list.append(arg_xmm1)
    if arg_xmm2 != "":
        arg_list.append(arg_xmm2)
    if arg_xmm3 != "":
        arg_list.append(arg_xmm3)
    if arg_xmm4 != "":
        arg_list.append(arg_xmm4)
    if arg_xmm5 != "":
        arg_list.append(arg_xmm5)
    if arg_xmm6 != "":
        arg_list.append(arg_xmm6)
    if arg_xmm7 != "":
        arg_list.append(arg_xmm7)

    return arg_list

def check_arg(arg_regs, opnd):
    for reg in arg_regs:
        if reg in opnd:
            return reg
    return ""

callee_context_dict = dict()    # function ea -> resulting context from callee
                                # analysis
caller_context_dict = dict()    # function ea -> list of resulting contexts from
                                # caller analysis at each callsite
cpc_dict = dict()               # function ea -> cpc
DICT_OUTPUT = False
CPC_OUTPUT = False
ADDR_DEBUG = False
NAME_DEBUG = False
SPLIT_CPC = False
batch = True
CALLER_CPC_THRESH = 0.75
CALLER_CONTEXT_REFRESH = 15
sep = ","

if __name__ == '__main__':
    if batch:
        if ARGV[1] == '-c':
            sep = ","
            CPC_OUTPUT = True
            ext = "chain"
        elif ARGV[1] == '-f':
            sep = "\n"
            NAME_DEBUG = True
            CPC_OUTPUT = True
            ext = "func"
        elif ARGV[1] == '-l':
            sep = "\n"
            CPC_OUTPUT = True
            ext = "feature"
        elif ARGV[1] == '-d':
            DICT_OUTPUT = True
            ext = "dict"
        else:
            print("Must pass -c (chain), -f (per function), -l (list), or -d (dictionary)")
            sys.exit(1)

    debug = False
    autoWait()
    print("Starting")
    #ea = ScreenEA()    #ltj:screen ea not set in -A mode
    #ea = GetEntryPoint(GetEntryOrdinal(0)) #ltj: not always 0...
    sel = SegByName(".text")
    ea = SegByBase(sel)
    #print("%x" % ea)
    func_ea_list = list()
    func_name_list = list()
    func_dict = dict()

    for function_ea in Functions(SegStart(ea), SegEnd(ea)):
        #print hex(function_ea), GetFunctionName(function_ea)
        func_ea_list.append(function_ea)
        func_name_list.append(GetFunctionName(function_ea))
        func_dict[function_ea] = GetFunctionName(function_ea)
    func_ea_list.append(sys.maxint)

    cpc_chain = ""
    addr_chain = list()

    context = caller_context.CallerContext()
    f = 0
    h = 0
    for head in Heads(SegStart(ea), SegEnd(ea)):
        #print("%x" % head)
        if head > func_ea_list[f]:
            if NAME_DEBUG:
                addr_chain.append(sep+func_name_list[f]+": ")
            else:
                addr_chain.append(sep)
            context.init_regs()
            #cpc_chain += sep
            # if NAME_DEBUG:
            #     cpc_chain = cpc_chain + func_name_list[f] + " "
            # if ADDR_DEBUG:
            #     cpc_chain += hex(head)
            f += 1
        # TODO: have addr_chain and complementary, parallel structure for names/addrs

        if h >= CALLER_CONTEXT_REFRESH:
            h = 0
            context.init_regs()

        if isCode(GetFlags(head)):
            mnem = GetMnem(head)
            num_opnds = 0
            opnd_1 = GetOpnd(head, 0)
            opnd_2 = GetOpnd(head, 1)
            opnd_3 = GetOpnd(head, 2)

            #disassemble a particular function:
            # if func_name_list[f-1] == "CreateParams":
            #     print("%x: %s %s %s %s" % (head,mnem,opnd_1,opnd_2,opnd_3))

            if opnd_1 != "":
                num_opnds = 1
            if opnd_2 != "":
                num_opnds = 2
            if opnd_3 != "":
               num_opnds = 3

            if asm_helper.is_jmp(mnem) or asm_helper.is_call(mnem):
                op_type = GetOpType(head, 0)
                if op_type == o_near or op_type == o_far:
                    op_val = GetOperandValue(head, 0)
                    if op_val in func_ea_list:
                        context_rval = callee_context_dict.get(op_val, None)
                        if context_rval is None:
                            i = func_ea_list.index(op_val)
                            if func_name_list[i] == '//':
                                context_rval = callee_arg_sweep(op_val, True, func_ea_list[i+1], 0)
                            else:
                                context_rval = callee_arg_sweep(op_val, False, func_ea_list[i+1], 0)

                            callee_context_dict[op_val] = context_rval
                        #ltj: move this to outermost block to make contexts for all calls.
                        #will have to add functionality during cpc_dict construction that
                        #looks at not just callee_context_dict for ea's
                        if op_val != func_ea_list[f-1]: # don't use recursive callsites as caller_contexts
                            l = caller_context_dict.get(op_val, None)
                            if l == None:
                                caller_context_dict[op_val] = list()
                            cur_context = copy.copy(context)
                            caller_context_dict[op_val].append(cur_context)
                            context.init_regs()
                        else:
                            #print skipped functions:
                            #print("op_val: %x. func: %s" % (op_val,func_name_list[f-1]))
                            pass

                        addr_chain.append(op_val)
                        #cpc_chain += str(context_rval.callee_calculate_cpc())
                if asm_helper.is_call(mnem):
                    context.init_regs()

            if num_opnds == 0:
                if debug:
                    print("%x: %s" % (head,mnem))

            if num_opnds == 1:
                if debug:
                    print("%x: %s %s" % (head,mnem,opnd_1))

                opnd_1_type = GetOpType(head, 0)
                if opnd_1_type == o_reg:
                    if asm_helper.is_arg_reg(opnd_1):
                        if mnem in asm_helper.r_group:
                            context.add_src_arg(opnd_1)
                        elif mnem in asm_helper.w_group or mnem in asm_helper.rw_group:
                            context.add_set_arg(opnd_1)
                            h = 0
                        else:
                            print("Unrecognized mnemonic: %x: %s %s" % (head,mnem,opnd_1))
                if opnd_1_type == o_phrase or opnd_1_type == o_displ:
                    for arg in arg_extract(opnd_1):
                        context.add_src_arg(arg)

            if num_opnds == 2:
                opnd_1_type = GetOpType(head, 0)
                opnd_2_type = GetOpType(head, 1)

                if debug:
                    print("%x: %s %s %s" % (head,mnem,opnd_1,opnd_2))

                #XOR REG1 REG1 case:
                if opnd_1 == opnd_2:
                    if mnem in asm_helper.xor_insts or mnem in asm_helper.xorx_insts:
                        context.add_set_arg(opnd_1)
                        h = 0

                # ltj:moved this before opnd_1 to fix case of movsxd rdi edi making rdi set
                if opnd_2_type == o_reg:
                    if asm_helper.is_arg_reg(opnd_2):
                        context.add_src_arg(opnd_2)
                elif opnd_2_type == o_phrase or opnd_2_type == o_displ:
                    for arg in arg_extract(opnd_2):
                        context.add_src_arg(arg)

                if opnd_1_type == o_reg:
                    if asm_helper.is_arg_reg(opnd_1):
                        if mnem in asm_helper.w_r_group or mnem in asm_helper.rw_r_group:
                            context.add_set_arg(opnd_1)
                            h = 0
                        elif mnem in asm_helper.r_r_group:
                            context.add_src_arg(opnd_1)
                        else:
                            print("Unrecognized mnemonic: %x: %s %s %s" % (head,mnem,opnd_1,opnd_2))
                elif opnd_1_type == o_phrase or opnd_1_type == o_displ:
                    for arg in arg_extract(opnd_1):
                        context.add_src_arg(arg)

            if num_opnds == 3:
                opnd_1_type = GetOpType(head, 0)
                opnd_2_type = GetOpType(head, 1)
                opnd_3_type = GetOpType(head, 2)

                if debug:
                    print("%x: %s %s %s %s" % (head,mnem,opnd_1,opnd_2,opnd_3))

                if opnd_1_type == o_reg:
                    if asm_helper.is_arg_reg(opnd_1):
                        context.add_set_arg(opnd_1)
                        h = 0
                elif opnd_1_type == o_phrase or opnd_1_type == o_displ:
                    for arg in arg_extract(opnd_1):
                        context.add_src_arg(arg)

                if opnd_2_type == o_reg:
                    if asm_helper.is_arg_reg(opnd_2):
                        context.add_src_arg(opnd_2)
                elif opnd_2_type == o_phrase or opnd_2_type == o_displ:
                    for arg in arg_extract(opnd_2):
                        context.add_src_arg(arg)

                if opnd_3_type == o_reg:
                    if asm_helper.is_arg_reg(opnd_3):
                        context.add_src_arg(opnd_3)
                elif opnd_3_type == o_phrase or opnd_3_type == o_displ:
                    for arg in arg_extract(opnd_3):
                        context.add_src_arg(arg)

            h += 1
            # if head == 0x430AEE:
            #     context.caller_print_arg_regs()

    #ltj: do we need to check on caller_cpc's that don't exist as callee_cpcs?
    #are there any caller_contexts that don't have callee contexts? Yes, indirect
    #or library calls, but we currently don't operate on those
    for ea in callee_context_dict:
        callee_cpc = callee_context_dict[ea].calculate_cpc()
        callee_cpcspl = callee_context_dict[ea].calculate_cpc_split()

        caller_cpc_list = list()
        caller_cpcspl_list = list()
        try:
            for caller_cxt in caller_context_dict[ea]:
                # if ea == 0x40D230:
                #     print("caller cpc: %d" % caller_cxt.caller_calculate_cpc())
                caller_cpc_list.append(caller_cxt.calculate_cpc())
                caller_cpcspl_list.append(caller_cxt.calculate_cpc_split())

            max_num = 0
            caller_cpc = -1
            caller_cpcspl = ""
            #for cpc in caller_cpc_list:
            for i in range(0,len(caller_cpc_list)):
                cpc = caller_cpc_list[i]
                if caller_cpc_list.count(cpc) > max_num:
                    max_num = caller_cpc_list.count(cpc)
                    caller_cpc = cpc
                    caller_cpcspl = caller_cpcspl_list[i]
            maj = float(max_num) / float(len(caller_cpc_list))

            if callee_cpc >= 14:
                callee_cpc = -1
            else:
                if maj < CALLER_CPC_THRESH:
                    caller_cpc = -1
            #Turn off unused argument finding
            #max_cpc = -1

            # if ea == 0x40D230:
            #     print("max_cpc: %d" % max_cpc)

            #cpc_dict[ea] = max(caller_cpc, callee_cpc)
            if caller_cpc > callee_cpc:
                if SPLIT_CPC:
                    cpc_dict[ea] = caller_cpcspl
                else:
                    cpc_dict[ea] = caller_cpc
            else:
                if SPLIT_CPC:
                    cpc_dict[ea] = callee_cpcspl
                else:
                    cpc_dict[ea] = callee_cpc

            # if ea == 0x40D230:
            #     print("cpc: %d" % cpc_dict[ea])
        except KeyError:
            if SPLIT_CPC:
                cpc_dict[ea] = callee_cpcspl
            else:
                cpc_dict[ea] = callee_cpc

    for i in addr_chain:
        if sep in str(i):
        #if i == sep:
            cpc_chain += i
        else:
            cpc_chain += str(cpc_dict[i])

    if CPC_OUTPUT:
        # ltj: this hangs on very long strings
        # print cpc_chain
        filename = GetInputFilePath() + ".cpc." + ext
        f = open(filename, 'w')
        f.write(cpc_chain)
        f.close()
    elif DICT_OUTPUT:
        dict_out = ""
        for ea in cpc_dict:
            try:
                dict_out += func_dict[ea] + ": " + str(cpc_dict[ea]) + "\n"
            except KeyError:
                pass
                #dict_out += str(ea) + " not found as start of function"
        print dict_out
        filename = GetInputFilePath() + ".cpc." + ext
        f = open(filename, 'w')
        f.write(dict_out)
        f.close()

    if batch:
        Exit(0)