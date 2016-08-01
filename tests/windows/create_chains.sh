#!/bin/bash

#find all binaries to test, these are same source, compiled different ways
bins=$(find ../../corpora/ -wholename "*/$1.*.elf")

#Extract CPC chain from each binary for CARDINAL
for bin in $bins
do
	#clean previous results
	if [ -e "$bin.cpc.chain" ]
	then
		rm "$bin.cpc.chain" 
	fi

	idaw64.exe -A -S"../../dev/feature_extraction/cpc/ida_cpc_extract.py -c" $bin
	if [ -e "$bin.cpc.chain" ]
	then
		:
	else
		printf "CPC chain Extraction unsuccessful on $(basename $bin)\n"
	fi
done

#find ../../corpora/ -wholename "*/$1.*.elf" -exec idaw64.exe -A -S"../../dev/feature_extraction/cpc/ida_cpc_extract.py -c" {} \;
