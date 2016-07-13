#!/bin/bash

find ../../corpora/ -wholename */$1.*.elf -exec idaw64.exe -A -S"../../dev/feature_extraction/cpc/ida_cpc_extract.py -d" {} \;
find ../../corpora/lin_bitcode_corpus/ -wholename */$1.llvm -exec sh -c '../../dev/ground_truth/build/Debug/cpc-tool.exe {} > {}.cpc.gdict' \;
