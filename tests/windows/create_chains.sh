#!/bin/bash

find ../../../corpora/ -name *$1*.elf -exec idaw64.exe -A -S"../../dev/feature_extraction/cpc/ida_cpc_extract_standalone.py -c" {} \;