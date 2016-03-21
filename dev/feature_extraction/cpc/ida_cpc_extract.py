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

ea = get_screen_ea()

#TODO: these will be our boundaries for commas
for function_ea in Functions(SegStart(ea), SegEnd(ea)):
    print hex(function_ea), GetFunctionName(function_ea)

for head in Heads(SegStart(ea), SegEnd(ea)):
    if isCode(GetFlags(head)):
        mnem = GetMnem(head)
        if is_call(mnem):
            op_type = GetOpType(head, 0)
            if op_type == o_near or op_type == o_far:
                op_val = GetOperandValue(head, 0)
                if op_val < SegEnd(head) and op_val > SegStart(head):
                    print("@%x, %d" % (op_val, op_type))