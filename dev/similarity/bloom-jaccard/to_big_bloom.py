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
    with open(filename, 'r') as f:
        b = BloomFilter(capacity=1000000, error_rate=0.001)

        for line in f:
            b.add(line)

        new_filename = filename + ".bloom"
        out_f = open(new_filename, 'w')
        b.tofile(out_f)


if __name__ == '__main__':
    for filename in sys.argv[1:]:
        to_bloom(filename)
