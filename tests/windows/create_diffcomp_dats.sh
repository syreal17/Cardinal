#!/bin/bash

get_result () {
	file=$1
	meth=$2
	opt=$3
	sample=$4
	grep "^$sample,$meth,$opt" multi_sample.report | cut -d " " -f 2 | \
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
	meth=$2
	printf "" > $file
	opts="O0-O0 O1-O1 O2-O2 O3-O3"
	for opt in $opts
	do
		printf "$opt " >> $file
		for sample in $samples
		do
			get_result $file $meth $opt $sample
		done 
		printf "\n" >> $file
	done
}

get_dat plots/diff.comp.cpc.bloom.dat cpc-bloom
get_dat plots/diff.comp.mcn.dat mc-bloom
get_dat plots/diff.comp.bbcp.bloom.dat bbcp-bloom
get_dat plots/diff.comp.cpc.edit.dat cpc-edit
