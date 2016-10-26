#-----------------------------------------------------------------------------
# A Three-Pronged Approach to Exploring the Limits of Static Malware Analyses:
# Callsite Parameter Cardinality (CPC) Counting: edit_distance.py
#
# Compares two cpc chains and gives their edit distance
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
#-----------------------------------------------------------------------------
from __future__ import print_function
import sys

import editdistance

def edit_distance(filename1, filename2):
    with open(filename1, 'r') as f1:
        with open(filename2, 'r') as f2:
            cpc_chain1 = f1.read()
            cpc_chain2 = f2.read()

            ed = editdistance.eval(cpc_chain1,cpc_chain2)

            tot = len(cpc_chain1) + len(cpc_chain2)
            avg = tot / 2
            percent = (float(avg) - float(ed))/float(avg)
            print("%s %s %f" % (filename1,filename2,percent))

if __name__ == '__main__':
    for filename1 in sys.argv[1:]:
        for filename2 in sys.argv[1:]:
            edit_distance(filename1, filename2)
