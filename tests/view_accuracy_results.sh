#!/bin/bash

printf "" > report.txt
find ../corpora/lin_bitcode_corpus/ -name *$1*.llvm.o.cpc.dict > gt_dict.txt
find ../corpora/ -name *$1*.elf.cpc.dict -exec python get_cpc_accuracy.py \
	`cat gt_dict.txt` {} \; >> report.txt

printf "accuracy, $1\n"

printf "$1,clang,O0: "
grep "clang.o0.*$" report.txt | cut -d " " -f 2,5

printf "$1,clang,O1: "
grep "clang.o1.*$" report.txt | cut -d " " -f 2,5

printf "$1,clang,O2: "
grep "clang.o2.*$" report.txt | cut -d " " -f 2,5

printf "$1,clang,O3: "
grep "clang.o3.*$" report.txt | cut -d " " -f 2,5

printf "$1,gcc,O0: "
grep "gcc.o0.*$" report.txt | cut -d " " -f 2,5

printf "$1,gcc,O1: "
grep "gcc.o1.*$" report.txt | cut -d " " -f 2,5

printf "$1,gcc,O2: "
grep "gcc.o2.*$" report.txt | cut -d " " -f 2,5

printf "$1,gcc,O3: "
grep "gcc.o3.*$" report.txt | cut -d " " -f 2,5
