#!/bin/bash

#copy passed in sample names                                                    
samples=""                                                                      
for var in "$@"                                                                 
do                                                                              
        samples="$samples $var"                                                 
done 

#spin off one process per testee
for testee in $samples
do
	./generate_difference_reports_parallel.sh $testee $samples
done	