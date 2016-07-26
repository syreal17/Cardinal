#!/bin/bash

function helptext {
	printf "view_diffcomp_results [name of binary] \n"
}

if [ -z "$1" ]
then
	helptext
	exit 1
fi

n=$RANDOM
find ../../corpora/ -wholename "*/$1.*.cpc.chain" -exec python ../../dev/similarity/editdistance/edit_distance.py {} + > report.$1.txt

printf "diff comp, $1:\n"

printf "$1,cpc-edit,O0-O0: "
grep "clang\.o0.*gcc\.o0.*$" report.$1.txt | cut -d " " -f 3

printf "$1,cpc-edit,O1-O1: "
grep "clang\.o1.*gcc\.o1.*$" report.$1.txt | cut -d " " -f 3

printf "$1,cpc-edit,O2-O2: "
grep "clang\.o2.*gcc\.o2.*$" report.$1.txt | cut -d " " -f 3

printf "$1,cpc-edit,O3-O3: "
grep "clang\.o3.*gcc\.o3.*$" report.$1.txt | cut -d " " -f 3

rm report.$1.txt
