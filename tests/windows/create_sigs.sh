#!/bin/bash

find ../../../corpora/ -name *$1*.elf -exec idaw64.exe -A -S"../../dev/feature_extraction/cpc/ida_cpc_extract_standalone.py -l" {} \;
find ../../../corpora/ -name *$1*.cpc.feature -exec /cygdrive/c/Python27/python.exe ../../dev/similarity/bloom-jaccard/to_bloom.py {} \;

find ../../../corpora/ -name *$1*.elf -exec sh -c '/cygdrive/c/Python27/python.exe ../../dev/feature_extraction/benchmarks/machine_code.py {} > {}.mc.feature' \;
find ../../../corpora/ -name *$1*.mc.feature -exec /cygdrive/c/Python27/python.exe ../../dev/similarity/bloom-jaccard/to_big_bloom.py {} \;
