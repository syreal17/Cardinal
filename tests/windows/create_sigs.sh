#!/bin/bash
# -----------------------------------------------------------------------------
# A Three-Pronged Approach to Exploring the Limits of Static Malware Analyses:
# Callsite Parameter Cardinality (CPC) Counting: create_sigs.sh
#
# Create CARDINAL, generic BitShred, and BBCP features and put them into Bloom
# filters for Jaccard index comparison
#
# Luke Jones (luke.t.jones.814@gmail.com)
#
# -----------------------------------------------------------------------------

#find all binaries to test, these are same source, compiled different ways
bins=$(find ../../corpora/ -wholename "*/$1.*.elf")

#Extract CPCs from each binary for CARDINAL and put in Bloom filter
for bin in $bins
do
	#clean previous results
	if [ -e "$bin.cpc.feature" ]
	then
		rm "$bin.cpc.feature" 
	fi
	
	if [ -e "$bin.cpc.feature.bloom" ]
	then
		rm "$bin.cpc.feature.bloom" 
	fi

	idaw64.exe -A -S"../../dev/feature_extraction/cpc/ida_cpc_extract.py -l" $bin
	if [ -s "$bin.cpc.feature" ]
	then
		/cygdrive/c/Python27/python.exe ../../dev/similarity/bloom-jaccard/to_bloom.py "$bin.cpc.feature"
		
		if [ -e "$bin.cpc.feature.bloom" ]
		then
			:
		else
			printf "Bloom filtering CPCs unsuccessful on $(basename $bin)\n"
		fi
	else
		printf "CPC Extraction unsuccessful on $(basename $bin)\n"
	fi
done

#Extract machine code windows (ala BitShred) and put in Bloom filter
for bin in $bins
do
	#clean previous results
	if [ -e "$bin.mc.feature" ]
	then
		rm "$bin.mc.feature" 
	fi
	
	if [ -e "$bin.mc.feature.bloom" ]
	then
		rm "$bin.mc.feature.bloom" 
	fi

	sh -c "/cygdrive/c/Python27/python.exe ../../dev/feature_extraction/benchmarks/machine_code.py $bin > $bin.mc.feature"
	if [ -s "$bin.mc.feature" ]
	then
		/cygdrive/c/Python27/python.exe ../../dev/similarity/bloom-jaccard/to_big_bloom.py "$bin.mc.feature"
		
		if [ -e "$bin.mc.feature.bloom" ]
		then
			:
		else
			printf "Bloom filtering MCs unsuccessful on $(basename $bin)\n"
		fi
	else
		printf "MC Extraction unsuccessful on $(basename $bin)\n"
	fi
done

#Extract BBCP generalized opcode windows and put in Bloom filter
for bin in $bins
do
	#clean previous results
	if [ -e "$bin.bbcp.feature" ]
	then
		rm "$bin.bbcp.feature" 
	fi
	
	if [ -e "$bin.bbcp.feature.bloom" ]
	then
		rm "$bin.bbcp.feature.bloom" 
	fi

	idaw64.exe -A -S"../../dev/feature_extraction/benchmarks/ida_bbcp.py" $bin
	if [ -s "$bin.bbcp.feature" ]
	then
		/cygdrive/c/Python27/python.exe ../../dev/similarity/bloom-jaccard/to_big_bloom.py "$bin.bbcp.feature"
		
		if [ -e "$bin.bbcp.feature.bloom" ]
		then
			:
		else
			printf "Bloom filtering BBCPs unsuccessful on $(basename $bin)\n"
		fi
	else
		printf "BBCP Extraction unsuccessful on $(basename $bin)\n"
	fi
done

#Short, silent error version:
#find ../../corpora/ -wholename "*/$1.*.elf" -exec idaw64.exe -A -S"../../dev/feature_extraction/cpc/ida_cpc_extract.py -l" {} \;
#find ../../corpora/ -wholename "*/$1.*.cpc.feature" -exec /cygdrive/c/Python27/python.exe ../../dev/similarity/bloom-jaccard/to_bloom.py {} \;

#find ../../corpora/ -wholename "*/$1.*.elf" -exec sh -c '/cygdrive/c/Python27/python.exe ../../dev/feature_extraction/benchmarks/machine_code.py {} > {}.mc.feature' \;
#find ../../corpora/ -wholename "*/$1.*.mc.feature" -exec /cygdrive/c/Python27/python.exe ../../dev/similarity/bloom-jaccard/to_big_bloom.py {} \;

#find ../../corpora/ -wholename "*/$1.*.elf" -exec idaw64.exe -A -S"../../dev/feature_extraction/benchmarks/ida_bbcp.py" {} \;
#find ../../corpora/ -wholename "*/$1.*.bbcp.feature" -exec /cygdrive/c/Python27/python.exe ../../dev/similarity/bloom-jaccard/to_big_bloom.py {} \;
