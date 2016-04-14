#!/bin/bash

#copy passed in sample names                                                    
samples=""                                                                      
for var in "$@"                                                                 
do                                                                              
        samples="$samples $var"                                                 
done          

#Generate cpc chains (for edit distance) and lists (for Bloom filters) and
#machine code ngrams to simulate BitShred
printf "Starting feature generation\n"

for sample in $samples
do
	printf "Generating $sample features\n"
	./create_sigs.sh $sample
	./create_chains.sh $sample
done

./generate_report.sh $samples
