#!/bin/bash

#find all binaries to test, these are same source, compiled different ways
bins=$(find ../../corpora/ -wholename "*/$1.*.elf")

#Extract function name to CPC dictionaries for each binary
for bin in $bins
do
	#clean previous results
	if [ -e "$bin.cpc.dict" ]
	then
		rm "$bin.cpc.dict" 
	fi

	idaw64.exe -A -S"../../dev/feature_extraction/cpc/ida_cpc_extract.py -d" $bin
	if [ -s "$bin.cpc.dict" ]
	then
		:
	else
		printf "CPC dictionary creation unsuccessful on $(basename $bin)\n"
	fi
done

bcs=$(find ../../corpora/lin_bitcode_corpus/ -wholename "*/$1.llvm")

#Extract function to argument count dictionaries for each llvm bitcode
for bc in $bcs
do
	#clean previous results
	if [ -e "$bc.cpc.gdict" ]
	then
		rm "$bc.cpc.gdict" 
	fi

	sh -c "../../dev/ground_truth/build/Debug/cpc-tool.exe $bc > $bc.cpc.gdict"
	if [ -s "$bc.cpc.gdict" ]
	then
		:
	else
		printf "Argument count dictionary creation unsuccessful on $(basename $bin)\n"
	fi
done

#find ../../corpora/ -wholename "*/$1.*.elf" -exec idaw64.exe -A -S"../../dev/feature_extraction/cpc/ida_cpc_extract.py -d" {} \;
#find ../../corpora/lin_bitcode_corpus/ -wholename "*/$1.llvm" -exec sh -c '../../dev/ground_truth/build/Debug/cpc-tool.exe {} > {}.cpc.gdict' \;
