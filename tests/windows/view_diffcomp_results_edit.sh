#!/bin/bash

function helptext {
	printf "view_diffcomp_results [name of binary] \n"
}

if [ -z "$1" ]
then
	helptext
	exit 1
fi

#one liner with no error checking
#find ../../corpora/ -wholename "*/$1.*.cpc.chain" -exec python ../../dev/similarity/editdistance/edit_distance.py {} + > report.$1.txt
e=0
o=""
s=`find ../../corpora/ -wholename "*/$1.*.clang.o0.*.cpc.chain"`
count=`printf "%s" $s | wc -w`
if [ $count -ne 1 ]; then
	if [ $count -eq 0 ]; then
		printf "o0 not found for clang $1,$2\n"
		e=1
	else
		printf "Multiple o0's found for clang $1,$2\n"
		e=1
	fi
fi
o+=$s
o+=" "

s=`find ../../corpora/ -wholename "*/$1.*.clang.o1.*.cpc.chain"`
count=`printf "%s" $s | wc -w`
if [ $count -ne 1 ]; then
	if [ $count -eq 0 ]; then
		printf "o1 not found for clang $1,$2\n"
		e=1
	else
		printf "Multiple o1's found for clang $1,$2\n"
		e=1
	fi
fi
o+=$s
o+=" "

s=`find ../../corpora/ -wholename "*/$1.*.clang.o2.*.cpc.chain"`
count=`printf "%s" $s | wc -w`
if [ $count -ne 1 ]; then
	if [ $count -eq 0 ]; then
		printf "o2 not found for clang $1,$2\n"
		e=1
	else
		printf "Multiple o2's found for clang $1,$2\n"
		e=1
	fi
fi
o+=$s
o+=" "

s=`find ../../corpora/ -wholename "*/$1.*.clang.o3.*.cpc.chain"`
count=`printf "%s" $s | wc -w`
if [ $count -ne 1 ]; then
	if [ $count -eq 0 ]; then
		printf "o3 not found for clang $1,$2\n"
		e=1
	else
		printf "Multiple o3's found for clang $1,$2\n"
		e=1
	fi
fi
o+=$s
o+=" "

s=`find ../../corpora/ -wholename "*/$1.*.gcc.o0.*.cpc.chain"`
count=`printf "%s" $s | wc -w`
if [ $count -ne 1 ]; then
	if [ $count -eq 0 ]; then
		printf "o0 not found for gcc $1,$2\n"
		e=1
	else
		printf "Multiple o0's found for gcc $1,$2\n"
		e=1
	fi
fi
o+=$s
o+=" "

s=`find ../../corpora/ -wholename "*/$1.*.gcc.o1.*.cpc.chain"`
count=`printf "%s" $s | wc -w`
if [ $count -ne 1 ]; then
	if [ $count -eq 0 ]; then
		printf "o1 not found for gcc $1,$2\n"
		e=1
	else
		printf "Multiple o1's found for gcc $1,$2\n"
		e=1
	fi
fi
o+=$s
o+=" "

s=`find ../../corpora/ -wholename "*/$1.*.gcc.o2.*.cpc.chain"`
count=`printf "%s" $s | wc -w`
if [ $count -ne 1 ]; then
	if [ $count -eq 0 ]; then
		printf "o2 not found for gcc $1,$2\n"
		e=1
	else
		printf "Multiple o2's found for gcc $1,$2\n"
		e=1
	fi
fi
o+=$s
o+=" "

s=`find ../../corpora/ -wholename "*/$1.*.gcc.o3.*.cpc.chain"`
count=`printf "%s" $s | wc -w`
if [ $count -ne 1 ]; then
	if [ $count -eq 0 ]; then
		printf "o3 not found for gcc $1,$2\n"
		e=1
	else
		printf "Multiple o3's found for gcc $1,$2\n"
		e=1
	fi
fi
o+=$s
o+=" "

if [ $e -eq 1 ]; then
	exit $e
fi

python ../../dev/similarity/editdistance/edit_distance.py $o > report.$1.txt

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
