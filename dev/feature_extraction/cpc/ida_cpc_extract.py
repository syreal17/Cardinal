# -----------------------------------------------------------------------------
# A Three-Pronged Approach to Exploring the Limits of Static Malware Analyses:
# Callsite Parameter Cardinality (CPC) Counting: ida_cpc_extract.py
#
# The driver for ennumerating CPC for a Linux AMD64 binary using IDA Pro.
#
# Luke Jones (luke.t.jones.814@gmail.com)
#
# -----------------------------------------------------------------------------
# Notes
# * "arg regs" are often referenced. These are the "argument registers" used by
#   the System V calling convention. They can be found in asm_helper.py
# * "caller" variables are abbreviated with "er" and "callee" with "ee"
# * "ea" stands for "effective address"
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

#TODO: outline, clarify, simplify, comment (hopefully just when python ida api
#unclear

# TODO: rename MAX_DEPTH to MAX_CALLEE_RECURSION
MAX_DEPTH = 4                   # how far to pursue child contexts in callee
                                # analysis
MAX_CALLEE_SWEEP = 1000         # how many bytes past function start to analyze
                                #  for callee analysis
# TODO: change callee_context_dict to func_ea_to_ee_ctx
callee_context_dict = dict()    # function ea -> resulting context from callee
                                # analysis
# TODO: change caller_context_dict to func_ea_to_er_ctx_list
caller_context_dict = dict()    # function ea -> list of resulting contexts
                                # from caller analysis at each callsite
# TODO: change cpc_dict to func_ea_to_cpc
cpc_dict = dict()               # function ea -> cpc
DICT_OUTPUT = False             # output function name to cpc dictionary
CPC_OUTPUT = False              # output cpc chains
NAME_DEBUG = False              # include function name with cpc chain
SPLIT_CPC = False               # split CPC value into integer and float parts
                                # (more correct but harder to debug as split)
batch = True                    # switch to false if testing manually in IDA
                                # set to true if using testing framework
CALLER_CPC_THRESH = 0.75        # What percentage of caller determined cpcs
                                # must agree for value to be considered as cpc
CALLER_CONTEXT_REFRESH = 15     # how many instructions w/o arg reg before context reset
sep = ","                       # what to print between cpc chains


# TODO: rename callee_arg_sweep to Callee_Arg_Analysis
#TODO: rename ea to cur_func_ea
def callee_arg_sweep(ea, debug, next_func_ea, n):
    if debug:
        print("next_func_ea:%x" % next_func_ea)

    #TODO: rename to clarify context
    context = callee_context.CalleeContext()
    stack_args = list()

    f = idaapi.get_func(ea)
    if f.regvarqty > 0:
        #TODO: rename to add_aliased_regs
        add_regvars(f, ea, context, f.regvarqty)

    #TODO: rename head to addr
    for head in Heads(ea, ea+MAX_CALLEE_SWEEP):
        #TODO: rename mnem to m, clarify
        mnem = GetMnem(head)
        num_opnds = 0

        #if there is not that operand, it's an empty string
        #TODO: outline to Get_Operands, return tuple
        opnd_1 = GetOpnd(head, 0)
        opnd_2 = GetOpnd(head, 1)
        opnd_3 = GetOpnd(head, 2)

        #TODO: outline to Get_Operand_Count, return count
        if opnd_1 != "":
            num_opnds = 1
        if opnd_2 != "":
            num_opnds = 2
        if opnd_3 != "":
           num_opnds = 3

        #TODO: move to right after for statement, clarify
        if head >= next_func_ea:
            break

        if asm_helper.is_jmp(mnem) or asm_helper.is_call(mnem):
        #TODO: outline to Callee_Follow_Call
            #TODO: deal with this at other operand stuff
            op_type = GetOpType(head, 0)
            #TODO: outline to Is_Addr
            if op_type == o_near or op_type == o_far:
                op_val = GetOperandValue(head, 0)
                #TODO: outline to Is_Local_Function_Addr
                if op_val in func_eas:
                    if n < MAX_DEPTH:
                        child_context = callee_context_dict.get(op_val, None)
                        if child_context is None:
                            #TODO: just use func_dict
                            i = func_eas.index(op_val)
                            if func_names[i] == '/debug_func_name/':
                                child_context = callee_arg_sweep(op_val, True, func_eas[i + 1], n + 1)
                            else:
                                child_context = callee_arg_sweep(op_val, False, func_eas[i + 1], n + 1)
                            callee_context_dict[op_val] = child_context

                        cpc = child_context.callee_calculate_cpc()
                        if debug:
                            print("child cpc: %d" % cpc)
                        if cpc < 14: #ltj: clumsy checking for varargs function
                            context.add_child_context(child_context)
                    break

        if "+arg_" in opnd_2:
        #TODO: outline to add_stack_arg
            if debug:
                print("here2")
            if opnd_2 not in stack_args:
                stack_args.append(opnd_2)
                if debug:
                    print("stack arg: %s" % opnd_2)

        if "+arg_" in opnd_3:
        #TODO: reference add_stack_arg
            if debug:
                print("here3")
            if opnd_3 not in stack_args:
                stack_args.append(opnd_3)
                if debug:
                    print("stack arg: %s" % opnd_3)

        #======================================================================
        if num_opnds == 0:
            if debug:
                print("%x: %s" % (head,mnem))
        #======================================================================

        #======================================================================
        #Add source and set register arguments for instruction with 1 operand
        if num_opnds == 1:
        #TODO: outline Callee_Update_Context_1
            if debug:
                print("%x: %s %s" % (head,mnem,opnd_1))

            #TODO: simplify, put this stuff at beginning with operand stuff
            opnd_1_type = GetOpType(head, 0)
            if opnd_1_type == o_reg:
                if asm_helper.is_arg_reg(opnd_1):
                    if mnem in asm_helper.r_group or mnem in asm_helper.rw_group:
                        added = context.add_src_arg(opnd_1)
                        if debug and added:
                            print("%s added" % opnd_1)
                    elif mnem in asm_helper.w_group:
                        context.add_set_arg(opnd_1)
                    else:
                        print("Unrecognized mnemonic: %x: %s %s" % (head,mnem,opnd_1))
            #TODO: outline: Is_Mem_Ref
            if opnd_1_type == o_phrase or opnd_1_type == o_displ:
            #TODO: outline: Add_Mem_Regs
                for arg in arg_extract(opnd_1):
                    added = context.add_src_arg(arg)
                    if debug and added:
                        print("%s arg added" % arg)
        #======================================================================

        #======================================================================
        #Add source and set register arguments for instruction with 2 operands
        if num_opnds == 2:
        #TODO: outline to Callee_Update_Context_2
            opnd_1_type = GetOpType(head, 0)
            opnd_2_type = GetOpType(head, 1)

            if debug:
                print("%x: %s %s %s" % (head,mnem,opnd_1,opnd_2))

            #XOR REG1 REG1 case:
            if opnd_1 == opnd_2:
                if mnem in asm_helper.xor_insts or mnem in asm_helper.xorx_insts:
                    context.add_set_arg(opnd_1)

            if opnd_2_type == o_reg:
                if asm_helper.is_arg_reg(opnd_2):
                    added = context.add_src_arg(opnd_2)
                    if debug and added:
                        print("%s added" % opnd_2)
            elif opnd_2_type == o_phrase or opnd_2_type == o_displ:
                for arg in arg_extract(opnd_2):
                    added = context.add_src_arg(arg)
                    if debug and added:
                        print("%s arg added" % arg)

            if opnd_1_type == o_reg:
                if asm_helper.is_arg_reg(opnd_1):
                    if mnem in asm_helper.w_r_group:
                        context.add_set_arg(opnd_1)
                    elif mnem in asm_helper.r_r_group or mnem in asm_helper.rw_r_group:
                        added = context.add_src_arg(opnd_1)
                        if debug and added:
                            print("%s added" % opnd_1)
                    else:
                        print("Unrecognized mnemonic: %x: %s %s %s" % (head,mnem,opnd_1,opnd_2))
            #TODO: outline
            elif opnd_1_type == o_phrase or opnd_1_type == o_displ:
            #TODO:  outline
                for arg in arg_extract(opnd_1):
                    added = context.add_src_arg(arg)
                    if debug and added:
                        print("%s arg added" % arg)
        #======================================================================

        #======================================================================
        #Add source and set register arguments for instruction with 3 operands
        if num_opnds == 3:
        #TODO: outline to Callee_Update_Context_3
            opnd_1_type = GetOpType(head, 0)
            opnd_2_type = GetOpType(head, 1)
            opnd_3_type = GetOpType(head, 2)

            if debug:
                print("%x: %s %s %s %s" % (head,mnem,opnd_1,opnd_2,opnd_3))

            if opnd_1_type == o_reg:
                if asm_helper.is_arg_reg(opnd_1):
                    context.add_set_arg(opnd_1)
            #TODO: outline
            elif opnd_1_type == o_phrase or opnd_1_type == o_displ:
                for arg in arg_extract(opnd_1):
                    added = context.add_src_arg(arg)
                    if debug and added:
                        print("%s arg added" % arg)

            if opnd_2_type == o_reg:
                if asm_helper.is_arg_reg(opnd_2):
                    added = context.add_src_arg(opnd_2)
                    if debug and added:
                        print("%s added" % opnd_2)
            #TODO: outline
            elif opnd_2_type == o_phrase or opnd_2_type == o_displ:
                for arg in arg_extract(opnd_2):
                    added = context.add_src_arg(arg)
                    if debug and added:
                        print("%s arg added" % arg)

            if opnd_3_type == o_reg:
                if asm_helper.is_arg_reg(opnd_3):
                    added = context.add_src_arg(opnd_3)
                    if debug and added:
                        print("%s added" % opnd_3)
            #TODO: outline
            elif opnd_3_type == o_phrase or opnd_3_type == o_displ:
                for arg in arg_extract(opnd_3):
                    added = context.add_src_arg(arg)
                    if debug and added:
                        print("%s arg added" % arg)
        #======================================================================

    if debug:
        print("stack_args len: %d" % len(stack_args))

    #TODO:change context.extra_args to stack_arg_count
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
        #TODO: replace with regex
        #if reg in opnd:
        m = re.search('[+*\[]'+reg+'[+*\]]', opnd)
        if m is not None:
            return reg
    return ""

# TODO: change to Add_Aliased_Regs
def add_regvars(f, ea, context, c):
    for reg in asm_helper.arg_regs_all:
        rv = idaapi.find_regvar(f, ea, reg)
        if rv is not None:
            #ltj: simplistic way is assuming that this regvar is used as src
            #ltj: make this more robust by just adding it to list of possible
            #names of arg reg for this function.
            context.add_src_arg(reg)

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
    sel = SegByName(".text")
    ea = SegByBase(sel)
    pltSel = SegByName(".plt")
    pltEa = SegByBase(pltSel)
    func_eas = list()
    func_names = list()
    func_ea_to_name = dict()

    for function_ea in Functions(SegStart(ea), SegEnd(ea)):
        #print hex(function_ea), GetFunctionName(function_ea)
        func_eas.append(function_ea)
        func_names.append(GetFunctionName(function_ea))
        func_ea_to_name[function_ea] = GetFunctionName(function_ea)
    #func_ea_list.append(sys.maxint)

    for function_ea in Functions(SegStart(pltEa), SegEnd(pltEa)):
        func_eas.append(function_ea)
        func_names.append(GetFunctionName(function_ea))
        func_ea_to_name[function_ea] = GetFunctionName(function_ea)
    func_eas.append(sys.maxint)

    # TODO: outline to Caller_Arg_Analysis
    cpc_chain = ""
    addr_chain = list()

    # TODO: rename context to ctx
    context = caller_context.CallerContext()
    # TODO: rename f to i_f
    f = 0
    # TODO: rename h to i_h
    h = 0
    # TODO: rename head to h
    for head in Heads(SegStart(ea), SegEnd(ea)):
        # TODO: outline to Is_New_Func
        if head >= func_eas[f]:
            if NAME_DEBUG:
                addr_chain.append(sep + func_names[f] + ": ")
            else:
                addr_chain.append(sep)
            # TODO: add reset_regs that references init_regs
            context.init_regs()
            #cpc_chain += sep
            # if NAME_DEBUG:
            #     cpc_chain = cpc_chain + func_name_list[f] + " "
            # if ADDR_DEBUG:
            #     cpc_chain += hex(head)
            f += 1

        if h >= CALLER_CONTEXT_REFRESH:
            h = 0
            # TODO: reference reset_regs
            context.init_regs()

        if isCode(GetFlags(head)):
            # TODO: rename to m
            mnem = GetMnem(head)

            # TODO: outline these similarly to callee
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

            if asm_helper.is_jmp(mnem) or asm_helper.is_call(mnem):
                # TODO: outline to Caller_Add_Contexts
                # TODO: do op stuff all at once
                op_type = GetOpType(head, 0)
                # TODO: outline
                if op_type == o_near or op_type == o_far:
                    op_val = GetOperandValue(head, 0)
                    # TODO: outline
                    if op_val in func_eas:
                        #debug members of cpc chain
                        # TODO: outline Get_Cur_Func_Name
                        if func_names[f-1] == '//':
                            print("%x: %s" % (head, func_ea_to_name[op_val]))

                        # TODO: rename context_rval to ee_ctx
                        context_rval = callee_context_dict.get(op_val, None)
                        if context_rval is None:
                            # TODO: outline Get_Func_Index
                            # TODO: rename i to j_f
                            i = func_eas.index(op_val)

                            #debug callee analysis
                            #TODO: outline Get_Func_Name
                            if func_names[i] == '//':
                                context_rval = callee_arg_sweep(op_val, True, func_eas[i + 1], 0)
                            else:
                                context_rval = callee_arg_sweep(op_val, False, func_eas[i + 1], 0)

                            callee_context_dict[op_val] = context_rval
                        #ltj: move this out one level to make contexts for all calls.
                        #------------------------------------------------------
                        # TODO: outline to Is_Recursive_Call
                        if op_val != func_eas[f-1]:
                            l = caller_context_dict.get(op_val, None)
                            if l == None:
                                caller_context_dict[op_val] = list()
                            cur_context = copy.copy(context)
                            caller_context_dict[op_val].append(cur_context)
                            # TODO: change name
                            context.init_regs()
                        else:
                            #print skipped functions:
                            #print("op_val: %x. func: %s" % (op_val,func_name_list[f-1]))
                            pass

                        addr_chain.append(op_val)
                        #------------------------------------------------------
                if asm_helper.is_call(mnem):
                    #ltj:keeping this in case parsing plt doesn't always work
                    #add target function name to dictionary
                    #try:
                    #    func_dict[op_val]
                    #except KeyError:
                    #    func_dict[op_val] = GetFunctionName(op_val)
                    # TODO: rename to .reset
                    context.init_regs()

            if num_opnds == 0:
                if debug:
                    print("%x: %s" % (head,mnem))

            if num_opnds == 1:
            # TODO: outline to Caller_Update_Context_1
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
            # TODO: outline to Caller_Update_Context_2
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
            # TODO: outline to Caller_Update_Context_3
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

    # TODO: outline to Construct_CPC_Aggregate and Construct_CPC_Aggregate_Split
    for ea in callee_context_dict:
        # TODO: rename callee_cpc to ee_cpc
        callee_cpc = callee_context_dict[ea].callee_calculate_cpc()
        callee_cpcspl = callee_context_dict[ea].callee_calculate_cpc_split()

        # TODO: rename caller_cpc_list to er_cpcs
        caller_cpc_list = list()
        caller_cpcspl_list = list()
        try:
            for caller_cxt in caller_context_dict[ea]:
                # if ea == 0x40D230:
                #     print("caller cpc: %d" % caller_cxt.caller_calculate_cpc())
                caller_cpc_list.append(caller_cxt.caller_calculate_cpc())
                caller_cpcspl_list.append(caller_cxt.caller_calculate_cpc_split())
            del caller_context_dict[ea] # so remainder can be handled later

            # TODO: outline Find_Most_Frequent_CPC
            max_num = 0
            caller_cpc = -1
            caller_cpcspl = ""
            for i in range(0,len(caller_cpc_list)):
                cpc = caller_cpc_list[i]
                if caller_cpc_list.count(cpc) > max_num:
                    max_num = caller_cpc_list.count(cpc)
                    caller_cpc = cpc
                    caller_cpcspl = caller_cpcspl_list[i]
            maj = float(max_num) / float(len(caller_cpc_list))

            # TODO: replace 14 with MAX_ARG_REGS
            if callee_cpc >= 14:
                callee_cpc = -1
            else:
                if maj < CALLER_CPC_THRESH:
                    caller_cpc = -1

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

        except KeyError:
            if SPLIT_CPC:
                cpc_dict[ea] = callee_cpcspl
            else:
                cpc_dict[ea] = callee_cpc
    #now check remaining contexts in caller_context_dict
    for ea in caller_context_dict:
        for caller_cxt in caller_context_dict[ea]:
            # if ea == 0x40D230:
            #     print("caller cpc: %d" % caller_cxt.caller_calculate_cpc())
            caller_cpc_list.append(caller_cxt.caller_calculate_cpc())
            caller_cpcspl_list.append(caller_cxt.caller_calculate_cpc_split())

        # TODO: outline
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

        if SPLIT_CPC:
            cpc_dict[ea] = caller_cpcspl
        else:
            cpc_dict[ea] = caller_cpc

    for i in addr_chain:
        if sep in str(i):
            cpc_chain += i
        else:
            cpc_chain += str(cpc_dict[i])

    # TODO: outline to output
    if CPC_OUTPUT:
        filename = GetInputFilePath() + ".cpc." + ext
        f = open(filename, 'w')
        f.write(cpc_chain)
        f.close()
    elif DICT_OUTPUT:
        dict_out = ""
        for ea in cpc_dict:
            try:
                dict_out += func_ea_to_name[ea] + ": " + str(cpc_dict[ea]) + "\n"
            except KeyError:
                pass
                # debug:
                #dict_out += str(ea) + " not found as start of function"
        print dict_out
        filename = GetInputFilePath() + ".cpc." + ext
        f = open(filename, 'w')
        f.write(dict_out)
        f.close()

    if batch:
        Exit(0)