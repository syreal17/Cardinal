#-----------------------------------------------------------------------------
# A Three-Pronged Approach to Exploring the Limits of Static Malware Analyses:
# Callsite Parameter Cardinality (CPC) Counting: machine_code.py
#
# This is a generic implementation of Bitshred which extracts machine code as
# n-grams and puts into a bloom filter
#
# Luke Jones (luke.t.jones.814@gmail.com)
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
        ngram_extract(einfo.code, 5)
