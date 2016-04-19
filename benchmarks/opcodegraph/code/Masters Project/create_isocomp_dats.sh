#!/bin/bash

comps="clang gcc"
#copy passed in sample names                                                    
samples=""                                                                      
for var in "$@"                                                                 
do                                                                              
	samples="$samples $var"                                                
done

for comp in $comps
do
	printf "O0-O1 " > iso.$comp.op.dat

	for sample in $samples
	do
		./graph samples/$sample.simple.lin.$comp.o0.elf.asm \
			samples/$sample.simple.lin.$comp.o1.elf.asm |
			awk '{printf("%s",$0);}' >> iso.$comp.op.dat
		printf " " >> iso.$comp.op.dat
	done


	printf "\nO0-O2 " >> iso.$comp.op.dat

	for sample in $samples
	do
		./graph samples/$sample.simple.lin.$comp.o0.elf.asm \
			samples/$sample.simple.lin.$comp.o2.elf.asm |
			awk '{printf("%s",$0);}' >> iso.$comp.op.dat
		printf " " >> iso.$comp.op.dat
	done


	printf "\nO0-O3 " >> iso.$comp.op.dat

	for sample in $samples
	do
		./graph samples/$sample.simple.lin.$comp.o0.elf.asm \
			samples/$sample.simple.lin.$comp.o3.elf.asm |
			awk '{printf("%s",$0);}' >> iso.$comp.op.dat
		printf " " >> iso.$comp.op.dat
	done


	printf "\nO1-O2 " >> iso.$comp.op.dat

	for sample in $samples
	do
		./graph samples/$sample.simple.lin.$comp.o1.elf.asm \
			samples/$sample.simple.lin.$comp.o2.elf.asm |
			awk '{printf("%s",$0);}' >> iso.$comp.op.dat
		printf " " >> iso.$comp.op.dat
	done


	printf "\nO1-O3 " >> iso.$comp.op.dat

	for sample in $samples
	do
		./graph samples/$sample.simple.lin.$comp.o1.elf.asm \
			samples/$sample.simple.lin.$comp.o3.elf.asm |
			awk '{printf("%s",$0);}' >> iso.$comp.op.dat
		printf " " >> iso.$comp.op.dat
	done


	printf "\nO2-O3 " >> iso.$comp.op.dat

	for sample in $samples
	do
		./graph samples/$sample.simple.lin.$comp.o2.elf.asm \
			samples/$sample.simple.lin.$comp.o3.elf.asm |
			awk '{printf("%s",$0);}' >> iso.$comp.op.dat
		printf " " >> iso.$comp.op.dat
	done
done
