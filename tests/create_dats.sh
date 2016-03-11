#!/bin/bash

get_result () {
	sample=$5
	comp=$2
	meth=$3
	iso=$4
	grep "$sample,$comp,$meth,$iso" big_four.report.cfd0454 | cut -d " " -f 2 | awk '{printf("%s",$0);}' >> $1 
	printf " " >> $1
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
		printf "$iso " >> $file
		for sample in $samples
		do
			get_result $file $comp $meth $iso $sample
		done 
		printf "\n" >> $file
	done
}

get_dat iso.clang.cpc.bloom.dat clang cpc-bloom
#get_dat iso.clang.mcn.dat clang mc-bloom
#get_dat iso.clang.cpc.edit.dat clang cpc-edit
