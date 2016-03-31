# -----------------------------------------------------------------------------
# A Three-Pronged Approach to Exploring the Limits of Static Malware Analyses:
# Callsite Parameter Cardinality (CPC) Counting: ida_cpc_extract.py
#
# The driver for ennumerating CPC for a Linux AMD64 binary using IDA Pro.
#
# Luke Jones (luke.t.jones.814@gmail.com)
#
# -----------------------------------------------------------------------------
from idaapi import *
from idautils import *
from idc import *
from asm_helper import *
from callee_context import *

ADDR_DEBUG = False
NAME_DEBUG = True

MAX_CALLEE_SWEEP = 200
def callee_arg_sweep(ea, debug, next_func_ea):
    context = CalleeContext()
    for head in Heads(ea, ea+MAX_CALLEE_SWEEP):
        mnem = GetMnem(head)
        num_opnds = 0
        opnd_1 = GetOpnd(head, 0)
        opnd_2 = GetOpnd(head, 1)

        if opnd_1 != "":
            num_opnds = 1
        if opnd_2 != "":
            num_opnds = 2

        if num_opnds == 1:
            opnd_1_type = GetOpType(head, 0)
            if opnd_1_type == o_reg:
                if is_arg_reg(opnd_1):
                    if mnem in r_group or mnem in rw_group:
                        context.add_src_arg(opnd_1)
                        if debug:
                            print("%x: %s %s" % (head,mnem,opnd_1))
                    elif mnem in w_group:
                        context.add_set_arg(opnd_1)
                    else:
                        print("Unrecognized mnemonic: %s" % mnem)
            if opnd_1_type == o_phrase or opnd_1_type == o_displ:
                if debug:
                    print("%x: %s %s" % (head,mnem,opnd_1))
                for arg in arg_extract(opnd_1):
                    context.add_src_arg(arg)

        if num_opnds == 2:
            opnd_1_type = GetOpType(head, 0)
            opnd_2_type = GetOpType(head, 1)

            #XOR REG1 REG1 case:
            if opnd_1 == opnd_2:
                if mnem in xor_insts or mnem in xorx_insts:
                    context.add_set_arg(opnd_1)

            if opnd_1_type == o_reg:
                if is_arg_reg(opnd_1):
                    if mnem in w_r_group:
                        context.add_set_arg(opnd_1)
                    elif mnem in r_r_group or mnem in rw_r_group:
                        context.add_src_arg(opnd_1)
                        if debug:
                            print("%x: %s %s %s" % (head,mnem,opnd_1,opnd_2))
                    else:
                        print("Unrecognized mnemonic: %s" % mnem)
            elif opnd_1_type == o_phrase or opnd_1_type == o_displ:
                if debug:
                    print("%x: %s %s %s" % (head,mnem,opnd_1,opnd_2))
                for arg in arg_extract(opnd_1):
                    context.add_src_arg(arg)

            if opnd_2_type == o_reg:
                if is_arg_reg(opnd_2):
                    context.add_src_arg(opnd_2)
                    if debug:
                        print("%x: %s %s %s" % (head,mnem,opnd_1,opnd_2))
            elif opnd_2_type == o_phrase or opnd_2_type == o_displ:
                if debug:
                    print("%x: %s %s %s" % (head,mnem,opnd_1,opnd_2))
                for arg in arg_extract(opnd_2):
                    context.add_src_arg(arg)

        if is_ret(mnem) or is_hlt(mnem) or is_call(mnem) or (is_jmp(mnem) and
        GetOperandValue(head,0) in func_ea_list) or head > next_func_ea:
            break

    if debug:
        context.print_arg_regs()
    return context.callee_calculate_cpc()

def arg_extract(opnd):
    arg_list = list()

    arg_rdi = check_arg(arg_reg_rdi, opnd)
    arg_rsi = check_arg(arg_reg_rsi, opnd)
    arg_rdx = check_arg(arg_reg_rdx, opnd)
    arg_rcx = check_arg(arg_reg_rcx, opnd)
    arg_r10 = check_arg(arg_reg_r10, opnd)
    arg_r8 = check_arg(arg_reg_r8, opnd)
    arg_r9 = check_arg(arg_reg_r9, opnd)
    arg_xmm0 = check_arg(arg_reg_xmm0, opnd)
    arg_xmm1 = check_arg(arg_reg_xmm1, opnd)
    arg_xmm2 = check_arg(arg_reg_xmm2, opnd)
    arg_xmm3 = check_arg(arg_reg_xmm3, opnd)
    arg_xmm4 = check_arg(arg_reg_xmm4, opnd)
    arg_xmm5 = check_arg(arg_reg_xmm5, opnd)
    arg_xmm6 = check_arg(arg_reg_xmm6, opnd)
    arg_xmm7 = check_arg(arg_reg_xmm7, opnd)

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

ea = get_screen_ea()
func_ea_list = list()
func_name_list = list()
sep = "\n"

for function_ea in Functions(SegStart(ea), SegEnd(ea)):
    #print hex(function_ea), GetFunctionName(function_ea)
    func_ea_list.append(function_ea)
    func_name_list.append(GetFunctionName(function_ea))

cpc_dict = dict()
cpc_chain = ""

f = 0
for head in Heads(SegStart(ea), SegEnd(ea)):
    if head > func_ea_list[f]:
        cpc_chain += sep
        if NAME_DEBUG:
            cpc_chain = cpc_chain + func_name_list[f] + " "
        if ADDR_DEBUG:
            cpc_chain += hex(head)
        f += 1
        #func_ea_list.remove(func_ea_list[f])
        #func_name_list.remove(func_name_list[f])

    if isCode(GetFlags(head)):
        mnem = GetMnem(head)
        if is_call(mnem):
            op_type = GetOpType(head, 0)
            if op_type == o_near or op_type == o_far:
                op_val = GetOperandValue(head, 0)
                if op_val < SegEnd(head) and op_val > SegStart(head):
                    #print("@%x, %d" % (op_val, op_type))
                    cpc = cpc_dict.get(op_val, None)
                    if cpc is None:
                        i = func_ea_list.index(op_val)
                        if func_name_list[i] == 'TreeCCNodeHasAbstracts':
                            cpc = callee_arg_sweep(op_val, True, func_ea_list[i+1])
                        else:
                            cpc = callee_arg_sweep(op_val, False, func_ea_list[i+1])
                        cpc_dict[op_val] = cpc

                    cpc_chain += str(cpc)

        if is_jmp(mnem):
            op_type = GetOpType(head, 0)
            if op_type == o_near or op_type == o_far:
                op_val = GetOperandValue(head, 0)
                if op_val in func_ea_list:
                    cpc = cpc_dict.get(op_val, None)
                    if cpc is None:
                        cpc = callee_arg_sweep(op_val, False, func_ea_list[i+1])
                        cpc_dict[op_val] = cpc

                    cpc_chain += str(cpc)


print cpc_chain
