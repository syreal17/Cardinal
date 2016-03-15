#!/bin/bash

find ../corpora/ -name *$1*.elf -exec sh -c 'python ../dev/feature_extraction/cpc/cpc_extract.py -d {} > {}.cpc.dict' \;
find ../corpora/lin_bitcode_corpus/ -name *$1*.llvm.o -exec sh -c '../dev/ground_truth/debug/cpc-tool {} > {}.cpc.dict' \;
