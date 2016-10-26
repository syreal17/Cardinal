# -----------------------------------------------------------------------------
# A Three-Pronged Approach to Exploring the Limits of Static Malware Analyses:
# Callsite Parameter Cardinality (CPC) Counting: callee_context.py
#
# This is keeps track of argument registers at the callee level and performs
# cpc calculation based on the registers used as source
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

from asm_helper import *


class CalleeContext(object):
    def __init__(self):
        self.stack_arg_count = 0
        self.def_chain = list()  # for debugging purpose, functions for ea cpc
        self.init_regs()

    def init_regs(self):
        self.rdi_set = False
        self.rsi_set = False
        self.rdx_set = False
        self.rcx_set = False
        self.r10_set = False
        self.r8_set = False
        self.r9_set = False
        self.xmm0_set = False
        self.xmm1_set = False
        self.xmm2_set = False
        self.xmm3_set = False
        self.xmm4_set = False
        self.xmm5_set = False
        self.xmm6_set = False
        self.xmm7_set = False

        self.rdi_src = False
        self.rsi_src = False
        self.rdx_src = False
        self.rcx_src = False
        self.r10_src = False
        self.r8_src = False
        self.r9_src = False
        self.xmm0_src = False
        self.xmm1_src = False
        self.xmm2_src = False
        self.xmm3_src = False
        self.xmm4_src = False
        self.xmm5_src = False
        self.xmm6_src = False
        self.xmm7_src = False

    def reset(self):
        self.init_regs()

    def print_arg_regs(self):
        if self.rdi_src is True:
            print("rdi,")
        if self.rsi_src is True:
            print("rsi,")
        if self.rdx_src is True:
            print("rdx,")
        if self.rcx_src is True:
            print("rcx,")
        if self.r10_src is True:
            print("r10,")
        if self.r8_src is True:
            print("r8,")
        if self.r9_src is True:
            print("r9,")
        if self.xmm0_src is True:
            print("xmm0,")
        if self.xmm1_src is True:
            print("xmm1,")
        if self.xmm2_src is True:
            print("xmm2,")
        if self.xmm3_src is True:
            print("xmm3,")
        if self.xmm4_src is True:
            print("xmm4,")
        if self.xmm5_src is True:
            print("xmm5,")
        if self.xmm6_src is True:
            print("xmm6,")
        if self.xmm7_src is True:
            print("xmm7,")

    def add_set_arg(self,operand):
        """ Adds a possible argument to args
        """
        if operand in arg_reg_rdi and not self.rdi_src:
            self.rdi_set = True
            return True
        elif operand in arg_reg_rsi and not self.rsi_src:
            self.rsi_set = True
            return True
        elif operand in arg_reg_rdx and not self.rdx_src:
            self.rdx_set = True
            return True
        elif operand in arg_reg_rcx and not self.rcx_src:
            self.rcx_set = True
            return True
        elif operand in arg_reg_r10 and not self.r10_src:
            self.r10_set = True
            return True
        elif operand in arg_reg_r8 and not self.r8_src:
            self.r8_set = True
            return True
        elif operand in arg_reg_r9 and not self.r9_src:
            self.r9_set = True
            return True
        elif operand in arg_reg_xmm0 and not self.xmm0_src:
            self.xmm0_set = True
            return True
        elif operand in arg_reg_xmm1 and not self.xmm1_src:
            self.xmm1_set = True
            return True
        elif operand in arg_reg_xmm2 and not self.xmm2_src:
            self.xmm2_set = True
            return True
        elif operand in arg_reg_xmm3 and not self.xmm3_src:
            self.xmm3_set = True
            return True
        elif operand in arg_reg_xmm4 and not self.xmm4_src:
            self.xmm4_set = True
            return True
        elif operand in arg_reg_xmm5 and not self.xmm5_src:
            self.xmm5_set = True
            return True
        elif operand in arg_reg_xmm6 and not self.xmm6_src:
            self.xmm6_set = True
            return True
        elif operand in arg_reg_xmm7 and not self.xmm7_src:
            self.xmm7_set = True
            return True

        return False

    def add_src_arg(self,operand):
        """ Adds a possible argument to args
        """
        if operand in arg_reg_rdi and not self.rdi_set:
            self.rdi_src = True
            return True
        elif operand in arg_reg_rsi and not self.rsi_set:
            self.rsi_src = True
            return True
        elif operand in arg_reg_rdx and not self.rdx_set:
            self.rdx_src = True
            return True
        elif operand in arg_reg_rcx and not self.rcx_set:
            self.rcx_src = True
            return True
        elif operand in arg_reg_r10 and not self.r10_set:
            self.r10_src = True
            return True
        elif operand in arg_reg_r8 and not self.r8_set:
            self.r8_src = True
            return True
        elif operand in arg_reg_r9 and not self.r9_set:
            self.r9_src = True
            return True
        elif operand in arg_reg_xmm0 and not self.xmm0_set:
            self.xmm0_src = True
            return True
        elif operand in arg_reg_xmm1 and not self.xmm1_set:
            self.xmm1_src = True
            return True
        elif operand in arg_reg_xmm2 and not self.xmm2_set:
            self.xmm2_src = True
            return True
        elif operand in arg_reg_xmm3 and not self.xmm3_set:
            self.xmm3_src = True
            return True
        elif operand in arg_reg_xmm4 and not self.xmm4_set:
            self.xmm4_src = True
            return True
        elif operand in arg_reg_xmm5 and not self.xmm5_set:
            self.xmm5_src = True
            return True
        elif operand in arg_reg_xmm6 and not self.xmm6_set:
            self.xmm6_src = True
            return True
        elif operand in arg_reg_xmm7 and not self.xmm7_set:
            self.xmm7_src = True
            return True

        return False

    def add_child_context(self, child):
        if child.rdi_src and not self.rdi_set:
            self.rdi_src = True
        if child.rsi_src and not self.rsi_set:
            self.rsi_src = True
        if child.rdx_src and not self.rdx_set:
            self.rdx_src = True
        if child.rcx_src and not self.rcx_set:
            self.rcx_src = True
        if child.r10_src and not self.r10_set:
            self.r10_src = True
        if child.r8_src and not self.r8_set:
            self.r8_src = True
        if child.r9_src and not self.r9_set:
            self.r9_src = True
        if child.xmm0_src and not self.xmm0_set:
            self.xmm0_src = True
        if child.xmm1_src and not self.xmm1_set:
            self.xmm1_src = True
        if child.xmm2_src and not self.xmm2_set:
            self.xmm2_src = True
        if child.xmm3_src and not self.xmm3_set:
            self.xmm3_src = True
        if child.xmm4_src and not self.xmm4_set:
            self.xmm4_src = True
        if child.xmm5_src and not self.xmm5_set:
            self.xmm5_src = True
        if child.xmm6_src and not self.xmm6_set:
            self.xmm6_src = True
        if child.xmm7_src and not self.xmm7_set:
            self.xmm7_src = True

    def calculate_cpc(self):
        """ Determine callsite parameter cardinality based on argument
            registers seen in assignment commands and their order
        """
        int_regs = 0
        fp_regs = 0

        #Calculate number of int-ptr arguments used in context 
        if self.rdi_src is False:
            int_regs = 0
        elif self.rdi_src is True and self.rsi_src is False:
            int_regs = 1
        elif self.rsi_src is True and self.rdx_src is False:
            int_regs = 2
        #special handling for syscalls where r10 is used
        elif self.rdx_src is True and self.rcx_src is False and self.r10_src is False:
            int_regs = 3
        elif (self.rcx_src is True or self.r10_src is True) and self.r8_src is False:
            int_regs = 4
        elif self.r8_src is True and self.r9_src is False:
            int_regs = 5
        elif self.r9_src is True:
            int_regs = 6

        #Calculate number of fp arguments used in context
        if self.xmm0_src is False:
            fp_regs = 0
        elif self.xmm0_src is True and self.xmm1_src is False:
            fp_regs = 1
        elif self.xmm1_src is True and self.xmm2_src is False:
            fp_regs = 2
        elif self.xmm2_src is True and self.xmm3_src is False:
            fp_regs = 3
        elif self.xmm3_src is True and self.xmm4_src is False:
            fp_regs = 4
        elif self.xmm4_src is True and self.xmm5_src is False:
            fp_regs = 5
        elif self.xmm5_src is True and self.xmm6_src is False:
            fp_regs = 6
        elif self.xmm6_src is True and self.xmm7_src is False:
            fp_regs = 7
        elif self.xmm7_src is True:
            fp_regs = 8

        return int_regs + fp_regs + self.stack_arg_count

    def calculate_cpc_split(self):
        """ Determine callsite parameter cardinality based on argument
            registers seen in assignment commands and their order
        """
        int_regs = 0
        fp_regs = 0

        #Calculate number of int-ptr arguments used in context
        if self.rdi_src is False:
            int_regs = 0
        elif self.rdi_src is True and self.rsi_src is False:
            int_regs = 1
        elif self.rsi_src is True and self.rdx_src is False:
            int_regs = 2
        #special handling for syscalls where r10 is used
        elif self.rdx_src is True and self.rcx_src is False and self.r10_src is False:
            int_regs = 3
        elif (self.rcx_src is True or self.r10_src is True) and self.r8_src is False:
            int_regs = 4
        elif self.r8_src is True and self.r9_src is False:
            int_regs = 5
        elif self.r9_src is True:
            int_regs = 6

        #Calculate number of fp arguments used in context
        if self.xmm0_src is False:
            fp_regs = 0
        elif self.xmm0_src is True and self.xmm1_src is False:
            fp_regs = 1
        elif self.xmm1_src is True and self.xmm2_src is False:
            fp_regs = 2
        elif self.xmm2_src is True and self.xmm3_src is False:
            fp_regs = 3
        elif self.xmm3_src is True and self.xmm4_src is False:
            fp_regs = 4
        elif self.xmm4_src is True and self.xmm5_src is False:
            fp_regs = 5
        elif self.xmm5_src is True and self.xmm6_src is False:
            fp_regs = 6
        elif self.xmm6_src is True and self.xmm7_src is False:
            fp_regs = 7
        elif self.xmm7_src is True:
            fp_regs = 8

        return str(int_regs) + "i" + str(fp_regs) + "f."