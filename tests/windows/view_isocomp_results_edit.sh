#!/bin/bash

function helptext {
	printf "view_isocomp_results [name of binary] [name of compiler]\n"
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

find ../../../corpora/ -name *$1*$2*.cpc.chain -exec python ../../dev/similarity/editdistance/edit_distance.py {} + > report.txt

printf "isocomp, $1-$2:\n" 

printf "$1,$2,cpc-edit,O0-O1: "
grep "o0.*o1.*$" report.txt | cut -d " " -f 3

printf "$1,$2,cpc-edit,O0-O2: "
grep "o0.*o2.*$" report.txt | cut -d " " -f 3

printf "$1,$2,cpc-edit,O0-O3: "
grep "o0.*o3.*$" report.txt | cut -d " " -f 3

printf "$1,$2,cpc-edit,O1-O2: "
grep "o1.*o2.*$" report.txt | cut -d " " -f 3

printf "$1,$2,cpc-edit,O1-O3: "
grep "o1.*o3.*$" report.txt | cut -d " " -f 3

printf "$1,$2,cpc-edit,O2-O3: "
grep "o2.*o3.*$" report.txt | cut -d " " -f 3
