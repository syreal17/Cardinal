# -----------------------------------------------------------------------------
# A Three-Pronged Approach to Exploring the Limits of Static Malware Analyses:
# Callsite Parameter Cardinality (CPC) Counting: operands.py
#
# Wrapper class for handling operands as a whole and individually
#
# Luke Jones (luke.t.jones.814@gmail.com)
#
# -----------------------------------------------------------------------------

from idaapi import *
from idautils import *
from idc import *


class Operand(object):
    def __init__(self):
        self.text = None
        self.val = None
        self.type = None


class Operands(object):
    def __init__(self, head):
        self.o1 = Operand()
        self.o1.text = GetOpnd(head, 0)
        self.o1.type = GetOpType(head, 0)
        self.o1.val = GetOperandValue(head, 0)
        self.o2 = Operand()
        self.o2.text = GetOpnd(head, 1)
        self.o2.type = GetOpType(head, 1)
        self.o2.val = GetOperandValue(head, 1)
        self.o3 = Operand()
        self.o3.text = GetOpnd(head, 2)
        self.o3.type = GetOpType(head, 2)
        self.o3.val = GetOperandValue(head, 2)
        self.count = 0
        if self.o1 != "":
            self.count = 1
        if self.o2 != "":
            self.count = 2
        if self.o3 != "":
           self.count = 3