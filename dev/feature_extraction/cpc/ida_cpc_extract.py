# -----------------------------------------------------------------------------
# A Three-Pronged Approach to Exploring the Limits of Static Malware Analyses:
# Callsite Parameter Cardinality (CPC) Counting: ida_cpc_extract.py
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
#
# -----------------------------------------------------------------------------
# Notes
# * "arg regs" are often referenced. These are the "argument registers" used by
#   the System V calling convention. They can be found in asm_helper.py
# * "caller" variables are abbreviated with "er" and "callee" with "ee"
# * "ea" stands for "effective address"
# * Dictionaries are in the form "key_type"_to_"value_type"
# * Lists are in a pluralized form, "ea" becomes "eas" etc.
# -----------------------------------------------------------------------------
from idaapi import *
from idautils import *
from idc import *
import re
import sys
import copy
import asm_helper
import callee_context
import caller_context
import operands
idaapi.require("asm_helper")
idaapi.require("callee_context")
idaapi.require("caller_context")
idaapi.require("operands")

BATCH_MODE = True              # switch to false if testing manually in IDA
MAX_CALLEE_RECURSION = 4        # how far to pursue child contexts in callee
                                # analysis
MAX_CALLEE_SWEEP = 1000         # how many bytes past function start to analyze
                                #  for callee analysis
MAX_ARG_REGS = 14
INVALID_CPC = -1
DICT_OUTPUT = False             # output function name to cpc dictionary
CPC_OUTPUT = False              # output cpc chains
NAME_DEBUG = False              # include function name with cpc chain
SPLIT_CPC = False               # split CPC value into integer and float parts
                                # (more correct but harder to debug as split)
                                # set to true if using testing framework
CALLER_CPC_THRESH = 0.75        # What percentage of caller determined cpcs
                                # must agree for value to be considered as cpc
CALLER_CONTEXT_REFRESH = 15     # how many instructions w/o arg reg before context reset
SEP = ","                       # what to print between cpc chains

f_ea_to_ee_ctx = dict()         # function ea -> resulting context from callee
                                # analysis
f_ea_to_er_ctxs = dict()        # function ea -> list of resulting contexts
                                # from caller analysis at each callsite
f_eas, f_names, f_ea_to_name = list(), list(), dict()


def caller_arg_analysis(ea):
    """
    Linearly proceeds through whole binary, spinning off callee analyses at
    callsites and recording possible CPCs at each callsite
    :param ea: Effective address where analysis is started
    :return: Linear list of all called effective addresses
    """
    dst_eas = list()
    er_ctx = caller_context.CallerContext()
    i_nextf = 0
    i_ins = 0
    for h_ea in Heads(SegStart(ea), SegEnd(ea)):
        if h_ea >= f_eas[i_nextf]:  # have we reached the next function?
            if NAME_DEBUG:
                dst_eas.append(SEP + f_names[i_nextf] + ": ")
            else:
                dst_eas.append(SEP)
            er_ctx.reset()
            i_nextf += 1

        if i_ins >= CALLER_CONTEXT_REFRESH:  # have we passed so many instructions without a set arg reg?
            i_ins = 0
            er_ctx.reset()

        if isCode(GetFlags(h_ea)):
            mnem = GetMnem(h_ea)
            ops = operands.Operands(h_ea)
            i_curf = i_nextf-1

            if asm_helper.is_jmp(mnem) or asm_helper.is_call(mnem):
                er_ctx, dst_eas = caller_add_contexts(h_ea, mnem, ops, i_curf, er_ctx, dst_eas)

            er_ctx, i_ins = caller_update_context(h_ea, mnem, ops, er_ctx, i_ins)

            i_ins += 1

    return dst_eas


def caller_add_contexts(h_ea, mnem, ops, i_curf, er_ctx, dst_eas):
    """
    At a function call, adds a caller context and callee context for the
    callsite. Multiple caller contexts are created but only one callee context
    is created
    :param h_ea: effective address of the call instruction
    :param mnem: mnemonic of call instruction
    :param ops: operands object of the call instruction
    :param i_curf: index of the current function
    :param er_ctx: caller context
    :param dst_eas: destination or called effective addresses
    :return: er_ctx, dst_eas
    """
    if is_addr(ops.o1.type):
        called_ea = ops.o1.val
        if called_ea in f_eas:
            #debug target func names of cpc chain
            if f_names[i_curf] == '/debug_function/':
                print("%x: %s" % (h_ea, f_ea_to_name[called_ea]))

            ee_ctx = f_ea_to_ee_ctx.get(called_ea, None)
            if ee_ctx is None:
                j_f = f_eas.index(called_ea)
                j_nextf = j_f + 1

                #debug callee analysis
                if f_ea_to_name[called_ea] == '/debug_function/':
                    ee_ctx = callee_arg_analysis(called_ea, True, f_eas[j_nextf], 0)
                else:
                    ee_ctx = callee_arg_analysis(called_ea, False, f_eas[j_nextf], 0)

                f_ea_to_ee_ctx[called_ea] = ee_ctx
            # ltj: move this out one indent to make er contexts for all calls,
            # not just internal calls.
            # ------------------------------------------------------
            if called_ea != f_eas[i_curf]: #called_ea not recursive
                l = f_ea_to_er_ctxs.get(called_ea, None)
                if l is None:
                    f_ea_to_er_ctxs[called_ea] = list()
                cur_context = copy.copy(er_ctx)
                f_ea_to_er_ctxs[called_ea].append(cur_context)
                er_ctx.reset()
            else:
                #print skipped functions:
                #print("called_ea: %x. func: %s" % (called_ea,func_name_list[i_nextf-1]))
                pass

            dst_eas.append(called_ea)
            # ------------------------------------------------------
    if asm_helper.is_call(mnem):
        # ltj:keeping this in case parsing plt at beginning doesn't always work
        # add target function name to dictionary
        # try:
        #    func_dict[called_ea]
        # except KeyError:
        #    func_dict[called_ea] = GetFunctionName(called_ea)
        er_ctx.reset()

    return er_ctx, dst_eas


def caller_update_context(h_ea, mnem, ops, er_ctx, i_ins):
    """
    Updates the caller context with appropriate registers set and used
    :param h_ea: effective address of the instruction we're updating with
    :param mnem: mnemonic of the instruction we're updating with
    :param ops: operands of the instruction we're updating with
    :param er_ctx: caller context to update
    :param i_ins: count of instructions since an arg reg setter has been seen
    :return: er_ctx, i_ins
    """
    if ops.count == 0:
        if debug:
            print("%x: %s" % (h_ea, mnem))

    if ops.count == 1:
        if debug:
            print("%x: %s %s" % (h_ea, mnem, ops.o1.text))

        if ops.o1.type == o_reg:
            if asm_helper.is_arg_reg(ops.o1.text):
                if mnem in asm_helper.r_group:
                    er_ctx.add_src_arg(ops.o1.text)
                elif mnem in asm_helper.w_group or mnem in asm_helper.rw_group:
                    er_ctx.add_set_arg(ops.o1.text)
                    i_ins = 0
                else:
                    print("Unrecognized mnemonic: %x: %s %s" % (h_ea, mnem, ops.o1.text))
        if ops.o1.type == o_phrase or ops.o1.type == o_displ:  #o_displ is part of idaapi - more details
            for arg in arg_extract(ops.o1.text):
                er_ctx.add_src_arg(arg)

    if ops.count == 2:
        if debug:
            print("%x: %s %s %s" % (h_ea, mnem, ops.o1.text, ops.o2.text))

        # XOR REG1 REG1 case:
        if ops.o1.text == ops.o2.text:
            if mnem in asm_helper.xor_insts or mnem in asm_helper.xorx_insts:
                er_ctx.add_set_arg(ops.o1.text)
                i_ins = 0

        if ops.o2.type == o_reg:
            if asm_helper.is_arg_reg(ops.o2.text):
                er_ctx.add_src_arg(ops.o2.text)
        elif ops.o2.type == o_phrase or ops.o2.type == o_displ:
            for arg in arg_extract(ops.o2.text):
                er_ctx.add_src_arg(arg)

        if ops.o1.type == o_reg:
            if asm_helper.is_arg_reg(ops.o1.text):
                if mnem in asm_helper.w_r_group or mnem in asm_helper.rw_r_group:
                    er_ctx.add_set_arg(ops.o1.text)
                    i_ins = 0
                elif mnem in asm_helper.r_r_group:
                    er_ctx.add_src_arg(ops.o1.text)
                else:
                    print("Unrecognized mnemonic: %x: %s %s %s" % (h_ea, mnem, ops.o1.text, ops.o2.text))
        elif ops.o1.type == o_phrase or ops.o1.type == o_displ:
            for arg in arg_extract(ops.o1.text):
                er_ctx.add_src_arg(arg)

    if ops.count == 3:
        if debug:
            print("%x: %s %s %s %s" % (h_ea, mnem, ops.o1.text, ops.o2.text, ops.o3.text))

        if ops.o1.type == o_reg:
            if asm_helper.is_arg_reg(ops.o1.text):
                er_ctx.add_set_arg(ops.o1.text)
                i_ins = 0
        elif ops.o1.type == o_phrase or ops.o1.type == o_displ:
            for arg in arg_extract(ops.o1.text):
                er_ctx.add_src_arg(arg)

        if ops.o2.type == o_reg:
            if asm_helper.is_arg_reg(ops.o2.text):
                er_ctx.add_src_arg(ops.o2.text)
        elif ops.o2.type == o_phrase or ops.o2.type == o_displ:
            for arg in arg_extract(ops.o2.text):
                er_ctx.add_src_arg(arg)

        if ops.o3.type == o_reg:
            if asm_helper.is_arg_reg(ops.o3.text):
                er_ctx.add_src_arg(ops.o3.text)
        elif ops.o3.type == o_phrase or ops.o3.type == o_displ:
            for arg in arg_extract(ops.o3.text):
                er_ctx.add_src_arg(arg)

    return er_ctx, i_ins


def callee_arg_analysis(cur_f_ea, debug, next_f_ea, depth):
    """
    Analyzing a callee for number of arguments
    :param cur_f_ea: effective address that callee starts at
    :param debug:  enable debugging or not
    :param next_f_ea: effective address of next function
    :param depth: how deep in recursion this call is
    :return: ee_ctx, a callee context
    """
    if debug:
        print("next_func_ea:%x" % next_f_ea)

    ee_ctx = callee_context.CalleeContext()
    stack_args = list()

    f = idaapi.get_func(cur_f_ea)
    if f.regvarqty > 0:
        add_aliased_regs(f, cur_f_ea, ee_ctx, f.regvarqty)

    for h_ea in Heads(cur_f_ea, cur_f_ea+MAX_CALLEE_SWEEP):
        # if we've reached the next function
        if h_ea >= next_f_ea:
            break

        mnem = GetMnem(h_ea)

        ops = operands.Operands(h_ea)
        if "+arg_" in ops.o2.text:
            stack_args = add_stack_arg(stack_args, ops, debug)
        if "+arg_" in ops.o3.text:
            stack_args = add_stack_arg(stack_args, ops, debug)

        if asm_helper.is_jmp(mnem) or asm_helper.is_call(mnem):
            b, ee_ctx = callee_add_child_context(ops, ee_ctx, depth)
            if b:
                break

        ee_ctx = callee_update_context(h_ea, mnem, ops, ee_ctx, debug)

    if debug:
        print("stack_args len: %d" % len(stack_args))

    ee_ctx.stack_arg_count = len(stack_args)

    if debug:
        ee_ctx.print_arg_regs()

    return ee_ctx


def callee_add_child_context(ops, ee_ctx, depth):
    """
    Add child callee context at new function call to parent callee context
    :param ops: operands of call instruction
    :param ee_ctx: parent callee context
    :param depth: depth of recursion
    :return: b, ee_ctx (b is boolean on whether to break callee arg analysis loop)
    """
    b = False

    if is_addr(ops.o1.type):
        called_ea = ops.o1.val
        if called_ea in f_eas:
            if depth < MAX_CALLEE_RECURSION:
                child_ee_ctx = f_ea_to_ee_ctx.get(called_ea, None)
                if child_ee_ctx is None:
                    j_f = f_eas.index(called_ea)
                    j_nextf = j_f + 1
                    if f_ea_to_name[called_ea] == '/debug_func_name/':
                        child_ee_ctx = callee_arg_analysis(called_ea, True, f_eas[j_nextf], depth + 1)
                    else:
                        child_ee_ctx = callee_arg_analysis(called_ea, False, f_eas[j_nextf], depth + 1)
                    f_ea_to_ee_ctx[called_ea] = child_ee_ctx

                cpc = child_ee_ctx.calculate_cpc()
                if debug:
                    print("child cpc: %d" % cpc)
                if cpc < 14:  # ltj: imprecise checking for varargs
                    ee_ctx.add_child_context(child_ee_ctx)
            b = True  # whether to break callee_arg_analysis loop

    return b, ee_ctx


def callee_update_context(h_ea, mnem, ops, ee_ctx, debug):
    """
    Updates callee context with arg regs used but not set
    :param h_ea: effective address of instruction updating context
    :param mnem: mnemonic of instruction updating context
    :param ops: operands of instruction updating context
    :param ee_ctx: callee context
    :param debug: debug or not
    :return: ee_ctx
    """
    if ops.count == 0:
        if debug:
            print("%x: %s" % (h_ea, mnem))

    # Add source and set register arguments for instruction with 1 operand
    if ops.count == 1:
        if debug:
            print("%x: %s %s" % (h_ea, mnem, ops.o1.text))

        if ops.o1.type == o_reg:
            if asm_helper.is_arg_reg(ops.o1.text):
                if mnem in asm_helper.r_group or mnem in asm_helper.rw_group:
                    added = ee_ctx.add_src_arg(ops.o1.text)
                    if debug and added:
                        print("%s added" % ops.o1.text)
                elif mnem in asm_helper.w_group:
                    ee_ctx.add_set_arg(ops.o1.text)
                else:
                    print("Unrecognized mnemonic: %x: %s %s" % (h_ea, mnem, ops.o1.text))
        if ops.o1.type == o_phrase or ops.o1.type == o_displ:
            for arg in arg_extract(ops.o1.text):
                added = ee_ctx.add_src_arg(arg)
                if debug and added:
                    print("%s arg added" % arg)

    # Add source and set register arguments for instruction with 2 operands
    if ops.count == 2:
        if debug:
            print("%x: %s %s %s" % (h_ea, mnem, ops.o1.text, ops.o2.text))

        # XOR REG1 REG1 case:
        if ops.o1.text == ops.o2.text:
            if mnem in asm_helper.xor_insts or mnem in asm_helper.xorx_insts:
                ee_ctx.add_set_arg(ops.o1.text)

        if ops.o2.type == o_reg:
            if asm_helper.is_arg_reg(ops.o2.text):
                added = ee_ctx.add_src_arg(ops.o2.text)
                if debug and added:
                    print("%s added" % ops.o2.text)
        elif ops.o2.type == o_phrase or ops.o2.type == o_displ:
            for arg in arg_extract(ops.o2.text):
                added = ee_ctx.add_src_arg(arg)
                if debug and added:
                    print("%s arg added" % arg)

        if ops.o1.type == o_reg:
            if asm_helper.is_arg_reg(ops.o1.text):
                if mnem in asm_helper.w_r_group:
                    ee_ctx.add_set_arg(ops.o1.text)
                elif mnem in asm_helper.r_r_group or mnem in asm_helper.rw_r_group:
                    added = ee_ctx.add_src_arg(ops.o1.text)
                    if debug and added:
                        print("%s added" % ops.o1.text)
                else:
                    print("Unrecognized mnemonic: %x: %s %s %s" % (h_ea, mnem, ops.o1.text, ops.o2.text))
        elif ops.o1.type == o_phrase or ops.o1.type == o_displ:
            for arg in arg_extract(ops.o1.text):
                added = ee_ctx.add_src_arg(arg)
                if debug and added:
                    print("%s arg added" % arg)

    # Add source and set register arguments for instruction with 3 operands
    if ops.count == 3:
        if debug:
            print("%x: %s %s %s %s" % (h_ea, mnem, ops.o1.text, ops.o2.text, ops.o3.text))

        if ops.o1.type == o_reg:
            if asm_helper.is_arg_reg(ops.o1.text):
                ee_ctx.add_set_arg(ops.o1.text)
        elif ops.o1.type == o_phrase or ops.o1.type == o_displ:
            for arg in arg_extract(ops.o1.text):
                added = ee_ctx.add_src_arg(arg)
                if debug and added:
                    print("%s arg added" % arg)

        if ops.o2.type == o_reg:
            if asm_helper.is_arg_reg(ops.o2.text):
                added = ee_ctx.add_src_arg(ops.o2.text)
                if debug and added:
                    print("%s added" % ops.o2.text)
        elif ops.o2.type == o_phrase or ops.o2.type == o_displ:
            for arg in arg_extract(ops.o2.text):
                added = ee_ctx.add_src_arg(arg)
                if debug and added:
                    print("%s arg added" % arg)

        if ops.o3.type == o_reg:
            if asm_helper.is_arg_reg(ops.o3.text):
                added = ee_ctx.add_src_arg(ops.o3.text)
                if debug and added:
                    print("%s added" % ops.o3.text)
        elif ops.o3.type == o_phrase or ops.o3.type == o_displ:
            for arg in arg_extract(ops.o3.text):
                added = ee_ctx.add_src_arg(arg)
                if debug and added:
                    print("%s arg added" % arg)

    return ee_ctx


def add_stack_arg(stack_args, ops, debug):
    """
    Add second operand to stack_args
    :param stack_args: current arguments from stack
    :param ops: operands with second operand to add to stack
    :param debug: debug prints or not
    :return: stack_args
    """
    if ops.o2.text not in stack_args:
        stack_args.append(ops.o2.text)
        if debug:
            print("stack arg: %s" % ops.o2.text)

    return stack_args


def arg_extract(opnd):
    """
    Extracts all argument registers found in an operand
    :param opnd: the operand to search for argument registers
    :return: list of arguments found in operand.
    """
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
    """
    Check for argument register text in various possible formats
    :param arg_regs: list of argument registers
    :param opnd: operand to search for matches
    :return: register text if found in opnd
    """
    for reg in arg_regs:
        # if reg in opnd:
        m = re.search('[+*\[]'+reg+'[+*\]]', opnd)
        if m is not None:
            return reg
    return ""


def add_aliased_regs(f, ea, context):
    """
    Goes through every possible argument register and determines if function
    is calling it something else. Adds them as src args
    :param f: idaapi function
    :param ea: effective address of function
    :param context: context to add arg regs to
    :return: none
    """
    for reg in asm_helper.arg_regs_all:
        rv = idaapi.find_regvar(f, ea, reg)
        if rv is not None:
            # ltj: simplistic way is assuming that this regvar is used as src
            # ltj: make this more robust by just adding it to list of possible
            # names of arg reg for this function.
            context.add_src_arg(reg)


def is_addr(op_type):
    """
    Is op_type an address type?
    :param op_type: op_type to check
    :return: Bool
    """
    if op_type == o_near or op_type == o_far:
        return True
    else:
        return False


def construct_cpc_aggregate(dst_eas):
    """
    Chooses between caller(s) or callee CPC to use as final output
    :param dst_eas: All the called functions
    :return: dst_eas and a dictionary of function ea to cpc
    """
    dst_cpcs, f_ea_to_cpc = "", dict()
    for ea in f_ea_to_ee_ctx:
        ee_cpc = f_ea_to_ee_ctx[ea].calculate_cpc()
        ee_cpcspl = f_ea_to_ee_ctx[ea].calculate_cpc_split()

        try:
            er_cpcs, er_cpcspls = list(), list()
            for er_cxt in f_ea_to_er_ctxs[ea]:
                er_cpcs.append(er_cxt.calculate_cpc())
                er_cpcspls.append(er_cxt.calculate_cpc_split())
            del f_ea_to_er_ctxs[ea] # so remainder can be handled later

            maj, er_cpc, er_cpcspl = find_most_frequent_cpc(er_cpcs, er_cpcspls)

            if ee_cpc >= MAX_ARG_REGS:
                ee_cpc = INVALID_CPC
            else:
                if maj < CALLER_CPC_THRESH:
                    er_cpc = INVALID_CPC

            if er_cpc > ee_cpc:
                if SPLIT_CPC:
                    f_ea_to_cpc[ea] = er_cpcspl
                else:
                    f_ea_to_cpc[ea] = er_cpc
            else:
                if SPLIT_CPC:
                    f_ea_to_cpc[ea] = ee_cpcspl
                else:
                    f_ea_to_cpc[ea] = ee_cpc

        except KeyError: #TODO: what could throw this exception?
            if SPLIT_CPC:
                f_ea_to_cpc[ea] = ee_cpcspl
            else:
                f_ea_to_cpc[ea] = ee_cpc
    # now check remaining contexts in caller_context_dict
    for ea in f_ea_to_er_ctxs:
        er_cpcs, er_cpcspls = list(), list()
        for er_cxt in f_ea_to_er_ctxs[ea]:
            er_cpcs.append(er_cxt.calculate_cpc())
            er_cpcspls.append(er_cxt.calculate_cpc_split())

        maj, er_cpc, er_cpcspl = find_most_frequent_cpc(er_cpcs, er_cpcspls)

        if SPLIT_CPC:
            f_ea_to_cpc[ea] = er_cpcspl
        else:
            f_ea_to_cpc[ea] = er_cpc

    for ea in dst_eas:
        if SEP in str(ea):
            dst_cpcs += ea
        else:
            dst_cpcs += str(f_ea_to_cpc[ea])

    return dst_cpcs, f_ea_to_cpc


def find_most_frequent_cpc(er_cpcs, er_cpcspls):
    """
    Out of all the caller cpcs, find the most common ont
    :param er_cpcs: caller cpcs
    :param er_cpcspls: caller cpcs, split between integer and float arguments
    :return: the percentage that the most common cpc takes up, and the chosen cpc
    """
    max_num = 0
    er_cpc = -1
    er_cpcspl = ""
    for i in range(0,len(er_cpcs)):
        cpc = er_cpcs[i]
        if er_cpcs.count(cpc) > max_num:
            max_num = er_cpcs.count(cpc)
            er_cpc = cpc
            er_cpcspl = er_cpcspls[i]
    maj = float(max_num) / float(len(er_cpcs))
    return maj, er_cpc, er_cpcspl


def output_cpc(dst_cpcs, f_ea_to_cpc):
    """
    Output results as either list of cpcs or dictionary
    :param dst_cpcs: all the called function's cpcs
    :param f_ea_to_cpc: dictionary of function ea to cpc
    :return: none
    """
    if CPC_OUTPUT:
        filename = GetInputFilePath() + ".cpc." + ext
        f = open(filename, 'w')
        f.write(dst_cpcs)
        f.close()
    elif DICT_OUTPUT:
        dict_out = ""
        for ea in f_ea_to_cpc:
            try:
                dict_out += f_ea_to_name[ea] + ": " + str(f_ea_to_cpc[ea]) + "\n"
            except KeyError:
                pass
                # debug:
                # dict_out += str(ea) + " not found as start of function"
        print dict_out
        filename = GetInputFilePath() + ".cpc." + ext
        f = open(filename, 'w')
        f.write(dict_out)
        f.close()


def get_functions_in_section(ea):
    """
    Fill in function eas list, function names list and function ea to name
    dictionary
    :param ea: effective address of section to start finding functions
    :return: f_eas, f_names, f_ea_to_name
    """
    for f_ea in Functions(SegStart(ea), SegEnd(ea)):
        f_eas.append(f_ea)
        f_names.append(GetFunctionName(f_ea))
        f_ea_to_name[f_ea] = GetFunctionName(f_ea)
    return f_eas, f_names, f_ea_to_name


if __name__ == '__main__':
    if BATCH_MODE:
        if ARGV[1] == '-c':
            SEP = ","
            CPC_OUTPUT = True
            ext = "chain"
        elif ARGV[1] == '-f':
            SEP = "\n"
            NAME_DEBUG = True
            CPC_OUTPUT = True
            ext = "func"
        elif ARGV[1] == '-l':
            SEP = "\n"
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

    textSel = SegByName(".text")
    textEa = SegByBase(textSel)
    pltSel = SegByName(".plt")
    pltEa = SegByBase(pltSel)

    # find functions so we can easily tell function boundaries, debug specific
    # functions and find jumps to functions
    f_eas, f_names, f_ea_to_name = get_functions_in_section(textEa)
    f_eas, f_names, f_ea_to_name = get_functions_in_section(pltEa)
    f_eas.append(sys.maxint)

    # visit every callsite, start callee analyses at callsites,
    # build context dicts, return called addresses chained per function
    dst_eas = caller_arg_analysis(debug, textEa)

    dst_cpcs, f_ea_to_cpc = "", dict()
    dst_cpcs, f_ea_to_cpc = construct_cpc_aggregate(dst_eas)

    output_cpc(dst_cpcs, f_ea_to_cpc)

    print("Finished")
    if BATCH_MODE:
        Exit(0)