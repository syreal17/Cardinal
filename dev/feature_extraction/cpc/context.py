#-----------------------------------------------------------------------------
# A Three-Pronged Approach to Exploring the Limits of Static Malware Analyses:
# Callsite Parameter Cardinality (CPC) Counting: context.py
#
# This is the container object for sections, registers and cardinality chains
# for the CPC extractor driver
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

from asm_helper import *

class CContext(object):
    def __init__(self, dump_wait=4):
        self.dump_wait = dump_wait
        self.count = 0
        self.extra_args = 0
        self.branch_queue = list()
        self.root_queue = list()
        self.branch_history = list()
        self.root_history = list()
        self.cpc_chain = ""
        self.def_chain = list() #for debugging purpose, functions for ea cpc
        self.init_regs()

    def init_regs(self):
        self.rdi_set = False;
        self.rsi_set = False;
        self.rdx_set = False;
        self.rcx_set = False;
        self.r10_set = False;
        self.r8_set = False;
        self.r9_set = False;
        self.xmm0_set = False;
        self.xmm1_set = False;
        self.xmm2_set = False;
        self.xmm3_set = False;
        self.xmm4_set = False;
        self.xmm5_set = False;
        self.xmm6_set = False;
        self.xmm7_set = False;

    def print_int_regs(self):
        if self.rdi_set is True:
            print("rdi,")
        if self.rsi_set is True:
            print("rsi,")
        if self.rdx_set is True:
            print("rdx,")
        if self.rcx_set is True:
            print("rcx,")
        if self.r10_set is True:
            print("r10,")
        if self.r8_set is True:
            print("r8,")
        if self.r9_set is True:
            print("r9,")

    def add_arg(self,operand):
        """ Adds a possible argument to args
        """
        self.count = 0

        if operand in arg_reg_rdi:
            self.rdi_set = True
        elif operand in arg_reg_rsi:
            self.rsi_set = True
        elif operand in arg_reg_rdx:
            self.rdx_set = True
        elif operand in arg_reg_rcx:
            self.rcx_set = True
        elif operand in arg_reg_r10:
            self.r10_set = True
        elif operand in arg_reg_r8:
            self.r8_set = True
        elif operand in arg_reg_r9:
            self.r9_set = True
        elif operand in arg_reg_xmm0:
            self.xmm0_set = True
        elif operand in arg_reg_xmm1:
            self.xmm1_set = True
        elif operand in arg_reg_xmm2:
            self.xmm2_set = True
        elif operand in arg_reg_xmm3:
            self.xmm3_set = True
        elif operand in arg_reg_xmm4:
            self.xmm4_set = True
        elif operand in arg_reg_xmm5:
            self.xmm5_set = True
        elif operand in arg_reg_xmm6:
            self.xmm6_set = True
        elif operand in arg_reg_xmm7:
            self.xmm7_set = True
        else:
            print("Error: Didn't find %s as argument register" % operand)

    def del_arg(self,operand):
        """ Adds a possible argument to args
        """
        self.count = 0

        if operand in arg_reg_rdi:
            self.rdi_set = False
        elif operand in arg_reg_rsi:
            self.rsi_set = False
        elif operand in arg_reg_rdx:
            self.rdx_set = False
        elif operand in arg_reg_rcx:
            self.rcx_set = False
        elif operand in arg_reg_r10:
            self.r10_set = False
        elif operand in arg_reg_r8:
            self.r8_set = False
        elif operand in arg_reg_r9:
            self.r9_set = False
        elif operand in arg_reg_xmm0:
            self.xmm0_set = False
        elif operand in arg_reg_xmm1:
            self.xmm1_set = False
        elif operand in arg_reg_xmm2:
            self.xmm2_set = False
        elif operand in arg_reg_xmm3:
            self.xmm3_set = False
        elif operand in arg_reg_xmm4:
            self.xmm4_set = False
        elif operand in arg_reg_xmm5:
            self.xmm5_set = False
        elif operand in arg_reg_xmm6:
            self.xmm6_set = False
        elif operand in arg_reg_xmm7:
            self.xmm7_set = False
        else:
            print("Error: Didn't find %s as argument register" % operand)

    def dump(self):
        """ Delete all possible arguments in args
        """
        #print('dump')
        self.init_regs()
        self.extra_args = 0
        self.count = 0

    def calculate_cpc(self):
        """ Determine callsite parameter cardinality based on argument
            registers seen in assignment commands and their order
        """
        int_regs = 0
        fp_regs = 0

        #Calculate number of int-ptr arguments used in context 
        if self.rdi_set is False:
            int_regs = 0
        elif self.rdi_set is True and self.rsi_set is False:
            int_regs = 1
        elif self.rsi_set is True and self.rdx_set is False:
            int_regs = 2
        #special handling for syscalls where r10 is used
        elif self.rdx_set is True and self.rcx_set is False and self.r10_set is False:
            int_regs = 3
        elif (self.rcx_set is True or self.r10_set is True) and self.r8_set is False:
            int_regs = 4
        elif self.r8_set is True and self.r9_set is False:
            int_regs = 5
        elif self.r9_set is True:
            int_regs = 6

        #Calculate number of fp arguments used in context
        if self.xmm0_set is False:
            fp_regs = 0
        elif self.xmm0_set is True and self.xmm1_set is False:
            fp_regs = 1
        elif self.xmm1_set is True and self.xmm2_set is False:
            fp_regs = 2
        elif self.xmm2_set is True and self.xmm3_set is False:
            fp_regs = 3
        elif self.xmm3_set is True and self.xmm4_set is False:
            fp_regs = 4
        elif self.xmm4_set is True and self.xmm5_set is False:
            fp_regs = 5
        elif self.xmm5_set is True and self.xmm6_set is False:
            fp_regs = 6
        elif self.xmm6_set is True and self.xmm7_set is False:
            fp_regs = 7
        elif self.xmm7_set is True:
            fp_regs = 8

        return int_regs + fp_regs + self.extra_args

    def found_call(self):
        """ Add current number of args to cardinality chain and dump
        """
        cpc = self.calculate_cpc()
        self.cpc_chain += str(cpc)
        #print("%s" % self.cpc_chain)
        #self.print_int_regs()
        self.dump()

    def found_ret(self):
        """ Add delimiter in cardinality chain and dump
        """
        self.cpc_chain += ","
        self.dump()

    def check_branch(self):
        """ Make sure branch does not already exist in history or queue
        """
        pass

    def add_branch(self):
        """ Add branch to queue to sweep with current context
        """
        pass

    def check_root(self):
        """ Make sure root does not already exist in history or queue
        """
        pass

    def add_root(self):
        """ Add root to queue to sweep with fresh context
        """
        pass
