#-----------------------------------------------------------------------------
# A Three-Pronged Approach to Exploring the Limits of Static Malware Analyses:
# Callsite Parameter Cardinality (CPC) Counting: to_bloom.py
#
# Consumes a list of features into a Bloom filter for Jaccard indexing
#
# Luke Jones (luke.t.jones.814@gmail.com)
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
