#!/bin/bash

#copy passed in sample names                                                    
samples=""  
testee=""
testee_found=0                                                                 
for var in "$@"                                                                 
do       
		if [ $testee_found -eq 0 ] 
		then
			testee="$var"
			testee_found=1
		else
			samples="$samples $var"
		fi
done          
compilers="clang gcc"
features="cpc mc bbcp"
file="$testee.multi_sample.report"

printf "" > $file

#Different binaries, Bloom/Jaccard
for sample1 in $samples
do
	for feature in $features
	do
		printf "Generating different binaries test report for \
($testee,$sample1,$feature-bloom)\n" 
		./view_diffbin_results_bloom.sh $testee $sample1 $feature >> $file
	done
done

#Different binaries, edit distance
for sample1 in $samples
do
	printf "Generating different binaries test report for \
($testee,$sample1)\n"
	./view_diffbin_results_edit.sh $testee $sample1 >> $file
done