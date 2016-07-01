#-----------------------------------------------------------------------------
# A Three-Pronged Approach to Exploring the Limits of Static Malware Analyses:
# Callsite Parameter Cardinality (CPC) Counting: caller_context.py
#
# This is the container for registers used at the caller level, and contains
# code to calculate cpc based on the registers set
#
# Luke Jones (luke.t.jones.814@gmail.com)
#
#-----------------------------------------------------------------------------

from asm_helper import *

class CallerContext(object):
    def __init__(self):
        self.extra_args = 0
        self.def_chain = list() #for debugging purpose, functions for ea cpc
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

    def add_src_arg(self,operand):
        """ Adds a possible argument to args
        """
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

    def caller_calculate_cpc(self):
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

    def caller_calculate_cpc_split(self):
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

        return str(int_regs) + "i" + str(fp_regs) + "f."
