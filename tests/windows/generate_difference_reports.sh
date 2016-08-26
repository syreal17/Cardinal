#!/bin/bash

#copy passed in sample names                                                    
samples=""                                                                      
for var in "$@"                                                                 
do                                                                              
        samples="$samples $var"                                                 
done          
compilers="clang gcc"
features="cpc mc bbcp"
file="multi_sample.report"

#samples that won't work
broken=""

#Different binaries, Bloom/Jaccard
for sample1 in $samples
do
	for sample2 in $samples
	do
		for feature in $features
		do
			printf "Generating different binaries test report for \
($sample1,$sample2,$feature-bloom)\n" 
			./view_diffbin_results_bloom.sh $sample1 $sample2 $feature >> $file
		done
	done
done

#Different binaries, edit distance
for sample1 in $samples
do
	for sample2 in $samples
	do
		printf "Generating different binaries test report for \
($sample1,$sample2)\n"
		./view_diffbin_results_edit.sh $sample1 $sample2 >> $file
	done
done