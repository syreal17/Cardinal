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

#one liner with no error checking
#find ../../corpora/ -wholename "*/$1.*$2*.cpc.chain" -exec python ../../dev/similarity/editdistance/edit_distance.py {} + > report.$1.$2.txt

e=0
o=""
s=`find ../../corpora/ -wholename "*/$1.*$2.o0.*.cpc.chain"`
count=`printf "%s" $s | wc -w`
if [ $count -ne 1 ]; then
	if [ $count -eq 0 ]; then
		printf "o0 not found for $1,$2\n"
		e=1
	else
		printf "Multiple o0's found for $1,$2\n"
		e=1
	fi
fi
o+=$s
o+=" "

s=`find ../../corpora/ -wholename "*/$1.*$2.o1.*.cpc.chain"`
count=`printf "%s" $s | wc -w`
if [ $count -ne 1 ]; then
	if [ $count -eq 0 ]; then
		printf "o1 not found for $1,$2\n"
		e=1
	else
		printf "Multiple o1's found for $1,$2\n"
		e=1
	fi
fi
o+=$s
o+=" "

s=`find ../../corpora/ -wholename "*/$1.*$2.o2.*.cpc.chain"`
count=`printf "%s" $s | wc -w`
if [ $count -ne 1 ]; then
	if [ $count -eq 0 ]; then
		printf "o2 not found for $1,$2\n"
		e=1
	else
		printf "Multiple o2's found for $1,$2\n"
		e=1
	fi
fi
o+=$s
o+=" "

s=`find ../../corpora/ -wholename "*/$1.*$2.o3.*.cpc.chain"`
count=`printf "%s" $s | wc -w`
if [ $count -ne 1 ]; then
	if [ $count -eq 0 ]; then
		printf "o3 not found for $1,$2\n"
		e=1
	else
		printf "Multiple o3's found for $1,$2\n"
		e=1
	fi
fi
o+=$s
o+=" "

if [ $e -eq 1 ]; then
	exit $e
fi

python ../../dev/similarity/editdistance/edit_distance.py $o > report.$1.$2.txt

printf "isocomp, $1-$2:\n" 

printf "$1,$2,cpc-edit,O0-O1: "
grep "o0.*o1.*$" report.$1.$2.txt | cut -d " " -f 3

printf "$1,$2,cpc-edit,O0-O2: "
grep "o0.*o2.*$" report.$1.$2.txt | cut -d " " -f 3

printf "$1,$2,cpc-edit,O0-O3: "
grep "o0.*o3.*$" report.$1.$2.txt | cut -d " " -f 3

printf "$1,$2,cpc-edit,O1-O2: "
grep "o1.*o2.*$" report.$1.$2.txt | cut -d " " -f 3

printf "$1,$2,cpc-edit,O1-O3: "
grep "o1.*o3.*$" report.$1.$2.txt | cut -d " " -f 3

printf "$1,$2,cpc-edit,O2-O3: "
grep "o2.*o3.*$" report.$1.$2.txt | cut -d " " -f 3

rm report.$1.$2.txt
