#!/bin/bash

find ../corpora/ -name *$1*.elf -exec sh -c 'python ../dev/feature_extraction/cpc/cpc_extract.py -c {} > {}.cpc.chain' \;
