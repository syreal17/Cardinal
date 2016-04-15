#!/bin/bash

comps="clang gcc"
#copy passed in sample names                                                    
samples=""                                                                      
for var in "$@"                                                                 
do                                                                              
	samples="$samples $var"                                                
done

printf "" > diff.bin.op.dat

for comp in $comps
do

	printf "\n$comp:O0-O0," >> diff.bin.op.dat

	for sample in $samples
	do
		for sample2 in $samples
		do
			if [ $sample != $sample2 ]
			then
				./graph samples/$sample.simple.lin.$comp.o0.elf.asm \
					samples/$sample2.simple.lin.$comp.o0.elf.asm |
					awk '{printf("%s",$0);}' >> diff.bin.op.dat
				printf "," >> diff.bin.op.dat
			fi
		done
	done


	printf "\n$comp:O1-O1," >> diff.bin.op.dat

	for sample in $samples
	do
		for sample2 in $samples
		do
			if [ $sample != $sample2 ]
			then
				./graph samples/$sample.simple.lin.$comp.o1.elf.asm \
					samples/$sample2.simple.lin.$comp.o1.elf.asm |
					awk '{printf("%s",$0);}' >> diff.bin.op.dat
				printf "," >> diff.bin.op.dat
			fi
		done
	done

	printf "\n$comp:O2-O2," >> diff.bin.op.dat

	for sample in $samples
	do
		for sample2 in $samples
		do
			if [ $sample != $sample2 ]
			then
				./graph samples/$sample.simple.lin.$comp.o2.elf.asm \
					samples/$sample2.simple.lin.$comp.o2.elf.asm |
					awk '{printf("%s",$0);}' >> diff.bin.op.dat
				printf "," >> diff.bin.op.dat
			fi
		done
	done

	printf "\n$comp:O3-O3," >> diff.bin.op.dat

	for sample in $samples
	do
		for sample2 in $samples
		do
			if [ $sample != $sample2 ]
			then
				./graph samples/$sample.simple.lin.$comp.o3.elf.asm \
					samples/$sample2.simple.lin.$comp.o3.elf.asm |
					awk '{printf("%s",$0);}' >> diff.bin.op.dat
				printf "," >> diff.bin.op.dat
			fi
		done
	done
done
