#!/bin/bash

get_result () {
	file=$1
	sample=$5
	comp=$2
	meth=$3
	iso=$4
	grep "^$sample,$comp,$meth,$iso" multi_sample.report | cut -d " " -f 2 | \
awk '{printf("%s",$0);}' >> $file
	printf " " >> $file
}

#copy passed in sample names
samples=""
for var in "$@"
do
		samples="$samples $var"
done

get_dat () {
	file=$1
	comp=$2
	meth=$3
	printf "" > $file
	isos="O0-O1 O0-O2 O0-O3 O1-O2 O1-O3 O2-O3"
	for iso in $isos
	do
		for sample in $samples
		do
			printf "$iso " >> $file
			get_result $file $comp $meth $iso $sample
			printf "\n" >> $file
		done 
	done
}

get_dat plots/iso.clang.cpc.bloom.dat clang cpc-bloom
get_dat plots/iso.clang.mcn.dat clang mc-bloom
get_dat plots/iso.clang.bbcp.bloom.dat clang bbcp-bloom
get_dat plots/iso.clang.cpc.edit.dat clang cpc-edit
get_dat plots/iso.gcc.cpc.bloom.dat gcc cpc-bloom
get_dat plots/iso.gcc.mcn.dat gcc mc-bloom
get_dat plots/iso.gcc.bbcp.bloom.dat gcc bbcp-bloom
get_dat plots/iso.gcc.cpc.edit.dat gcc cpc-edit
