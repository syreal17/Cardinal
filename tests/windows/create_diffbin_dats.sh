#!/bin/bash

get_result () {
	file=$1
	meth=$2
	opt=$3
	sample=$4
	sample2=$5
	grep "^$sample,$sample2,$meth,$opt" multi_sample.report | cut -d " " -f 2 |\
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
	legend=$3
	printf "" > $file
	printf "" > $legend
	opts="clang,O0-O0 clang,O1-O1 clang,O2-O2 clang,O3-O3 \
gcc,O0-O0 gcc,O1-O1 gcc,O2-O2 gcc,O3-O3"
	for opt in $opts
	do
		printf "$opt " >> $file
		for sample in $samples
		do
			for sample2 in $samples
			do
				if [ $sample != $sample2 ]
				then
					printf "$sample,$sample2,$meth\n" >> $legend
					get_result $file $meth $opt $sample $sample2
				fi
			done
		done 
		printf "\n" >> $file
	done
}

get_dat plots/diff.bin.cpc.bloom.dat cpc-bloom plots/diff.bin.cpc.bloom.legend.txt
get_dat plots/diff.bin.mcn.dat mc-bloom plots/diff.bin.mc.bloom.legend.txt
get_dat plots/diff.bin.bbcp.bloom.dat bbcp-bloom plots/diff.bin.bbcp.bloom.legend.txt
get_dat plots/diff.bin.cpc.edit.dat cpc-edit plots/diff.bin.cpc.edit.legend.txt
