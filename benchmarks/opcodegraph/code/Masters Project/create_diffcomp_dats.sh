#!/bin/bash

comps="clang gcc"
#copy passed in sample names                                                    
samples=""                                                                      
for var in "$@"                                                                 
do                                                                              
	samples="$samples $var"                                                
done

printf "O0-O0 " > diff.comp.op.dat

for sample in $samples
do
	./graph samples/$sample.simple.lin.clang.o0.elf.asm \
		samples/$sample.simple.lin.gcc.o0.elf.asm |
		awk '{printf("%s",$0);}' >> diff.comp.op.dat
	printf " " >> diff.comp.op.dat
done


printf "\nO1-O1 " >> diff.comp.op.dat

for sample in $samples
do
	./graph samples/$sample.simple.lin.clang.o1.elf.asm \
		samples/$sample.simple.lin.gcc.o1.elf.asm |
		awk '{printf("%s",$0);}' >> diff.comp.op.dat
	printf " " >> diff.comp.op.dat
done


printf "\nO2-O2 " >> diff.comp.op.dat

for sample in $samples
do
	./graph samples/$sample.simple.lin.clang.o2.elf.asm \
		samples/$sample.simple.lin.gcc.o2.elf.asm |
		awk '{printf("%s",$0);}' >> diff.comp.op.dat
	printf " " >> diff.comp.op.dat
done


printf "\nO3-O3 " >> diff.comp.op.dat

for sample in $samples
do
	./graph samples/$sample.simple.lin.clang.o3.elf.asm \
		samples/$sample.simple.lin.gcc.o3.elf.asm |
		awk '{printf("%s",$0);}' >> diff.comp.op.dat
	printf " " >> diff.comp.op.dat
done
