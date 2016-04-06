#!/bin/bash

function helptext {
	printf "view_isocomp_results [name of binary 1] [name of binary 2] [name of feature]\n"
}

if [ -z "$1" ]
then
	helptext
	exit 1
fi

if [ -z "$2" ]
then
	helptext
	exit 1
fi

if [ -z "$3" ]
then
	helptext
	exit 1
fi

find ../../../corpora/ -name *$1*.$3.feature.bloom > blooms.txt
find ../../../corpora/ -name *$2*.$3.feature.bloom >> blooms.txt
python ../../dev/similarity/bloom-jaccard/bloom_jaccard_ind.py `cat blooms.txt` > report.txt

printf "diffbin bloom, $1-$2-$3:\n" 

printf "$1,$2,$3-bloom,clang,O0-O0: "
grep "$1.simple.lin.clang.o0.*$2.simple.lin.clang.o0.*$" report.txt | cut -d " " -f 3

printf "$1,$2,$3-bloom,clang,O1-O1: "
grep "$1.simple.lin.clang.o1.*$2.simple.lin.clang.o1.*$" report.txt | cut -d " " -f 3

printf "$1,$2,$3-bloom,clang,O2-O2: "
grep "$1.simple.lin.clang.o2.*$2.simple.lin.clang.o2.*$" report.txt | cut -d " " -f 3

printf "$1,$2,$3-bloom,clang,O3-O3: "
grep "$1.simple.lin.clang.o3.*$2.simple.lin.clang.o3.*$" report.txt | cut -d " " -f 3

printf "$1,$2,$3-bloom,gcc,O0-O0: "
grep "$1.simple.lin.gcc.o0.*$2.simple.lin.gcc.o0.*$" report.txt | cut -d " " -f 3

printf "$1,$2,$3-bloom,gcc,O1-O1: "
grep "$1.simple.lin.gcc.o1.*$2.simple.lin.gcc.o1.*$" report.txt | cut -d " " -f 3

printf "$1,$2,$3-bloom,gcc,O2-O2: "
grep "$1.simple.lin.gcc.o2.*$2.simple.lin.gcc.o2.*$" report.txt | cut -d " " -f 3

printf "$1,$2,$3-bloom,gcc,O3-O3: "
grep "$1.simple.lin.gcc.o3.*$2.simple.lin.gcc.o3.*$" report.txt | cut -d " " -f 3
