#-----------------------------------------------------------------------------
# A Three-Pronged Approach to Exploring the Limits of Static Malware Analyses:
# Callsite Parameter Cardinality (CPC) Counting: machine_code.py
#
# This is a generic implementation of Bitshred which extracts machine code as
# n-grams and puts into a bloom filter
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

import binascii

from file_processing import *

def ngram_extract(CODE,window):
    CODE = binascii.hexlify(CODE)
    b = range(len(CODE))
    for i in b[::2]:
        print(CODE[i:i+window*2])

if __name__ == '__main__':
    for filename in sys.argv[1:]:
        einfo = ELFInfo()
        einfo.process_file(filename)
        ngram_extract(einfo.code, 4)
