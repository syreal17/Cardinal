#-----------------------------------------------------------------------------
# A Three-Pronged Approach to Exploring the Limits of Static Malware Analyses:
# Callsite Parameter Cardinality (CPC) Counting: to_bloom.py
#
# Consumes a list of features into a Bloom filter for Jaccard indexing
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


def to_bloom(filename):
    c = 0
    with open(filename, 'r') as f:
        b = BloomFilter(capacity=100000, error_rate=0.001)

        for line in f:
            if line != "":
                b.add(line)
                c += 1

        new_filename = filename + ".bloom"
        out_f = open(new_filename, 'wb')
        b.tofile(out_f)
        #print("Count: %d" % c)
        #print("bits: %d" % b.bitarray.count(True) )


if __name__ == '__main__':
    for filename in sys.argv[1:]:
        to_bloom(filename)
