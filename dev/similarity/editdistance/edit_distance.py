#-----------------------------------------------------------------------------
# A Three-Pronged Approach to Exploring the Limits of Static Malware Analyses:
# Callsite Parameter Cardinality (CPC) Counting: edit_distance.py
#
# Compares two cpc chains and gives their edit distance
#
# Luke Jones (luke.t.jones.814@gmail.com)
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
