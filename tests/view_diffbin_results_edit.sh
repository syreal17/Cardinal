#!/bin/bash

function helptext {
	printf "view_isocomp_results [name of binary 1] [name of binary 2]\n"
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

find ../corpora/ -name *$1*.cpc.chain > edits.txt
find ../corpora/ -name *$2*.cpc.chain >> edits.txt
python ../dev/similarity/editdistance/edit_distance.py `cat edits.txt` > report.txt

printf "diffbin, edit distance, $1-$2:\n" 

printf "$1,$2,cpc-edit,clang,O0-O0: "
grep "$1.simple.lin.clang.o0.*$2.simple.lin.clang.o0.*$" report.txt | cut -d " " -f 3

printf "$1,$2,cpc-edit,clang,O1-O1: "
grep "$1.simple.lin.clang.o1.*$2.simple.lin.clang.o1.*$" report.txt | cut -d " " -f 3

printf "$1,$2,cpc-edit,clang,O2-O2: "
grep "$1.simple.lin.clang.o2.*$2.simple.lin.clang.o2.*$" report.txt | cut -d " " -f 3

printf "$1,$2,cpc-edit,clang,O3-O3: "
grep "$1.simple.lin.clang.o3.*$2.simple.lin.clang.o3.*$" report.txt | cut -d " " -f 3

printf "$1,$2,cpc-edit,gcc,O0-O0: "
grep "$1.simple.lin.gcc.o0.*$2.simple.lin.gcc.o0.*$" report.txt | cut -d " " -f 3

printf "$1,$2,cpc-edit,gcc,O1-O1: "
grep "$1.simple.lin.gcc.o1.*$2.simple.lin.gcc.o1.*$" report.txt | cut -d " " -f 3

printf "$1,$2,cpc-edit,gcc,O2-O2: "
grep "$1.simple.lin.gcc.o2.*$2.simple.lin.gcc.o2.*$" report.txt | cut -d " " -f 3

printf "$1,$2,cpc-edit,gcc,O3-O3: "
grep "$1.simple.lin.gcc.o3.*$2.simple.lin.gcc.o3.*$" report.txt | cut -d " " -f 3
