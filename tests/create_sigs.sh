#!/bin/bash

find ../corpora/ -name *$1*.elf -exec sh -c 'python ../dev/feature_extraction/cpc/cpc_extract.py -l {} > {}.cpc.feature' \;
find ../corpora/ -name *$1*.cpc.feature -exec python ../dev/similarity/bloom-jaccard/to_bloom.py {} \;

find ../corpora/ -name *$1*.elf -exec sh -c 'python ../dev/feature_extraction/benchmarks/machine_code.py {} > {}.mc.feature' \;
find ../corpora/ -name *$1*.mc.feature -exec python ../dev/similarity/bloom-jaccard/to_big_bloom.py {} \;
