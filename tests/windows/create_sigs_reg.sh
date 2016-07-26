#!/bin/bash

find regression -wholename "*/$1.*.elf" -exec idaw64.exe -A -S"../../dev/feature_extraction/cpc/ida_cpc_extract.py -l" {} \;