#-----------------------------------------------------------------------------
# A Three-Pronged Approach to Exploring the Limits of Static Malware Analyses:
# Callsite Parameter Cardinality (CPC) Counting: bloom_jaccard_ind.py
#
# Compares two or more Bloom filters by a Jaccard index and prints report
#
# Luke Jones (luke.t.jones.814@gmail.com)
#
#-----------------------------------------------------------------------------
from __future__ import print_function
import sys

from pybloom import BloomFilter

def jaccard_ind(filename_1, filename_2):
    with open(filename_1, 'rb') as f_1:
        with open(filename_2, 'rb') as f_2:
            b_1 = BloomFilter.fromfile(f_1)
            b_2 = BloomFilter.fromfile(f_2)
            b_inter = b_1.intersection(b_2)
            b_union = b_1.union(b_2)
            bits_inter = b_inter.bitarray.count(True)
            bits_union = b_union.bitarray.count(True)
            j_i = float(bits_inter) / float(bits_union)
            #print("%s ~ %s, %f" % filename_1, filename_2, j_i)
            print("%s %s %f" % (filename_1, filename_2, j_i))


if __name__ == '__main__':
    for filename_1 in sys.argv[1:]:
        for filename_2 in sys.argv[1:]:
            jaccard_ind(filename_1, filename_2)
