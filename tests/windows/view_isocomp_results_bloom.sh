#!/bin/bash

function helptext {
	printf "view_isocomp_results [name of binary] [name of compiler] [name of feature]\n"
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

find ../../../corpora/ -wholename */$1*$2*.$3.feature.bloom -exec /cygdrive/c/Python27/python.exe ../../dev/similarity/bloom-jaccard/bloom_jaccard_ind.py {} + > report.txt

printf "isocomp, $1-$2-$3:\n" 

printf "$1,$2,$3-bloom,O0-O1: "
grep "o0.*o1.*$" report.txt | cut -d " " -f 3

printf "$1,$2,$3-bloom,O0-O2: "
grep "o0.*o2.*$" report.txt | cut -d " " -f 3

printf "$1,$2,$3-bloom,O0-O3: "
grep "o0.*o3.*$" report.txt | cut -d " " -f 3

printf "$1,$2,$3-bloom,O1-O2: "
grep "o1.*o2.*$" report.txt | cut -d " " -f 3

printf "$1,$2,$3-bloom,O1-O3: "
grep "o1.*o3.*$" report.txt | cut -d " " -f 3

printf "$1,$2,$3-bloom,O2-O3: "
grep "o2.*o3.*$" report.txt | cut -d " " -f 3
