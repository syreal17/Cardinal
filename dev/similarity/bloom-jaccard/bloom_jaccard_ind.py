#-----------------------------------------------------------------------------
# A Three-Pronged Approach to Exploring the Limits of Static Malware Analyses:
# Callsite Parameter Cardinality (CPC) Counting: bloom_jaccard_ind.py
#
# Compares two or more Bloom filters by a Jaccard index and prints report
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

from pybloom import BloomFilter

def jaccard_ind(filename_1, filename_2):
    with open(filename_1, 'rb') as f_1:
        with open(filename_2, 'rb') as f_2:
            print(filename_1)
            b_1 = BloomFilter.fromfile(f_1)
            b_2 = BloomFilter.fromfile(f_2)
            b_inter = b_1.intersection(b_2)
            b_union = b_1.union(b_2)
            bits_inter = b_inter.bitarray.count(True)
            bits_union = b_union.bitarray.count(True)
            j_i = float(bits_inter) / float(bits_union)
            #print("%s ~ %s, %f" % filename_1, filename_2, j_i)
            print("%s %s %f" % (filename_1, filename_2, j_i))
        f_2.close()
    f_1.close()


if __name__ == '__main__':
    for filename_1 in sys.argv[1:]:
        for filename_2 in sys.argv[1:]:
            jaccard_ind(filename_1, filename_2)
