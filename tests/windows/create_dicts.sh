#!/bin/bash

find ../../../corpora/ -name *$1*.elf -exec idaw64.exe -A -S"../../dev/feature_extraction/cpc/ida_cpc_extract_standalone.py -d" {} \;
find ../../../corpora/lin_bitcode_corpus/ -name *$1*.llvm.o -exec sh -c '../../dev/ground_truth/build/Debug/cpc-tool.exe {} > {}.cpc.gdict' \;