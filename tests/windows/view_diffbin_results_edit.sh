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

n=$RANDOM
find ../../../corpora/ -wholename */$1.*.cpc.chain > edits.$1.$2.txt
find ../../../corpora/ -wholename */$2.*.cpc.chain >> edits.$1.$2.txt
python ../../dev/similarity/editdistance/edit_distance.py `cat edits.$1.$2.txt` > report.$1.$2.txt

printf "diffbin, edit distance, $1-$2:\n" 

printf "$1,$2,cpc-edit,clang,O0-O0: "
grep "$1.simple.lin.clang.o0.*$2.simple.lin.clang.o0.*$" report.$1.$2.txt | cut -d " " -f 3

printf "$1,$2,cpc-edit,clang,O1-O1: "
grep "$1.simple.lin.clang.o1.*$2.simple.lin.clang.o1.*$" report.$1.$2.txt | cut -d " " -f 3

printf "$1,$2,cpc-edit,clang,O2-O2: "
grep "$1.simple.lin.clang.o2.*$2.simple.lin.clang.o2.*$" report.$1.$2.txt | cut -d " " -f 3

printf "$1,$2,cpc-edit,clang,O3-O3: "
grep "$1.simple.lin.clang.o3.*$2.simple.lin.clang.o3.*$" report.$1.$2.txt | cut -d " " -f 3

printf "$1,$2,cpc-edit,gcc,O0-O0: "
grep "$1.simple.lin.gcc.o0.*$2.simple.lin.gcc.o0.*$" report.$1.$2.txt | cut -d " " -f 3

printf "$1,$2,cpc-edit,gcc,O1-O1: "
grep "$1.simple.lin.gcc.o1.*$2.simple.lin.gcc.o1.*$" report.$1.$2.txt | cut -d " " -f 3

printf "$1,$2,cpc-edit,gcc,O2-O2: "
grep "$1.simple.lin.gcc.o2.*$2.simple.lin.gcc.o2.*$" report.$1.$2.txt | cut -d " " -f 3

printf "$1,$2,cpc-edit,gcc,O3-O3: "
grep "$1.simple.lin.gcc.o3.*$2.simple.lin.gcc.o3.*$" report.$1.$2.txt | cut -d " " -f 3

rm edits.$1.$2.txt report.$1.$2.txt
