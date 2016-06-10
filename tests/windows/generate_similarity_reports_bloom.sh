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

#clear file
printf "" > $file

#Isocompiler modulation, Bloom/Jaccard
for sample in $samples
do
	for compiler in $compilers
	do
		for feature in $features
		do
			printf "Generating isocompiler modulation test report for \
($sample,$compiler,$feature-bloom)\n"
			./view_isocomp_results_bloom.sh $sample $compiler $feature >> $file
		done
	done
done

#Different compiler, Bloom/Jaccard
for sample in $samples
do
	for feature in $features
	do
		printf "Generating different compiler test report for \
($sample,$feature-bloom)\n"
		./view_diffcomp_results_bloom.sh $sample $feature >> $file
	done
done