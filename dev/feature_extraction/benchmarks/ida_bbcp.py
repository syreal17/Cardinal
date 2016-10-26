# -----------------------------------------------------------------------------
# A Three-Pronged Approach to Exploring the Limits of Static Malware Analyses:
# BBCP Benchmark: ida_bbcp.py
#
# The IDA script for extracting normalized code windows from a binary in IDA
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

from idaapi import *
from idautils import *
from idc import *

def get_op_type_str(op,op_type):
    if "var_" in op:
        return "VAR"
    elif op_type == o_reg:
        return "REG"
    elif op_type == o_far or op_type == o_near:
        return "LOC"
    elif op_type == o_imm:
        return "CONST"
    elif op_type == o_mem or op_type == o_displ or op_type == o_phrase:
        return "MEM"

dis_norm_ins = list()
window = 4

if __name__ == "__main__":
    autoWait()

    sel = SegByName(".text")
    ea = SegByBase(sel)

    for head in Heads(SegStart(ea), SegEnd(ea)):
        if isCode(GetFlags(head)):
            mnem = GetMnem(head)
            opnd_1 = GetOpnd(head, 0)
            opnd_1_type = GetOpType(head, 0)
            opnd_2 = GetOpnd(head, 1)
            opnd_2_type = GetOpType(head, 1)
            opnd_3 = GetOpnd(head, 2)
            opnd_3_type = GetOpType(head, 2)

            if opnd_1 != "":
                opnd_1 = get_op_type_str(opnd_1,opnd_1_type)
            if opnd_2 != "":
                opnd_2 = get_op_type_str(opnd_2,opnd_2_type)
            if opnd_3 != "":
                opnd_3 = get_op_type_str(opnd_3,opnd_3_type)

            inst = "%s %s %s %s" % (mnem, opnd_1, opnd_2, opnd_3)
            #print(inst)
            inst = inst.strip()
            inst += ","
            dis_norm_ins.append(inst)


    filename = GetInputFilePath() + ".bbcp.feature"
    f = open(filename, 'w')
    r = range(len(dis_norm_ins))
    for i in r:
        string = ""
        for inst in dis_norm_ins[i:i+window]:
            string += inst

        #print(string)
        string += "\n"
        f.write(string)

    f.close()

    Exit(0)