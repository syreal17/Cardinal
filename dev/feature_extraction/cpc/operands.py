# -----------------------------------------------------------------------------
# A Three-Pronged Approach to Exploring the Limits of Static Malware Analyses:
# Callsite Parameter Cardinality (CPC) Counting: operands.py
#
# Wrapper class for handling operands as a whole and individually
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