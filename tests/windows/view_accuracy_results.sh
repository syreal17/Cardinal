#!/bin/bash

n=$RANDOM
printf "" > accuracy_report.$n.txt
find ../../corpora/lin_bitcode_corpus/ -wholename "*/$1.llvm.cpc.gdict" > gt_dict.$n.txt
find ../../corpora/ -wholename "*/$1.*.elf.cpc.dict" -exec python ../get_cpc_accuracy.py \
	`cat gt_dict.$n.txt` {} \; >> accuracy_report.$n.txt

#printf "accuracy, $1\n"

printf "$1,clang,O0: "
grep "clang.o0.*$" accuracy_report.$n.txt | cut -d " " -f 2,5

printf "$1,clang,O1: "
grep "clang.o1.*$" accuracy_report.$n.txt | cut -d " " -f 2,5

printf "$1,clang,O2: "
grep "clang.o2.*$" accuracy_report.$n.txt | cut -d " " -f 2,5

printf "$1,clang,O3: "
grep "clang.o3.*$" accuracy_report.$n.txt | cut -d " " -f 2,5

printf "$1,gcc,O0: "
grep "gcc.o0.*$" accuracy_report.$n.txt | cut -d " " -f 2,5

printf "$1,gcc,O1: "
grep "gcc.o1.*$" accuracy_report.$n.txt | cut -d " " -f 2,5

printf "$1,gcc,O2: "
grep "gcc.o2.*$" accuracy_report.$n.txt | cut -d " " -f 2,5

printf "$1,gcc,O3: "
grep "gcc.o3.*$" accuracy_report.$n.txt | cut -d " " -f 2,5

rm gt_dict.$n.txt accuracy_report.$n.txt
