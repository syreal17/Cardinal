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

#brief, but no error checking
find ../../corpora/ -wholename "*/$1.*.$3.feature.bloom" > blooms.$1.$2.$3.txt
find ../../corpora/ -wholename "*/$2.*.$3.feature.bloom" >> blooms.$1.$2.$3.txt
python ../../dev/similarity/bloom-jaccard/bloom_jaccard_ind.py `cat blooms.$1.$2.$3.txt` > report.$1.$2.$3.txt

#much longer and slower, but with error checking. Redundant when used with 
#other tests (isocomp, diffcomp)
# e=0
# o=""
# s=`find ../../corpora/ -wholename "*/$1.*.clang.o0.*.$3.feature.bloom"`
# count=`printf "%s" $s | wc -w`
# if [ $count -ne 1 ]; then
	# if [ $count -eq 0 ]; then
		# printf "o0 not found for clang $1,$3\n"
		# e=1
	# else
		# printf "Multiple o0's found for clang $1,$3\n"
		# e=1
	# fi
# fi
# o+=$s
# o+=" "

# s=`find ../../corpora/ -wholename "*/$1.*.clang.o1.*.$3.feature.bloom"`
# count=`printf "%s" $s | wc -w`
# if [ $count -ne 1 ]; then
	# if [ $count -eq 0 ]; then
		# printf "o1 not found for clang $1,$3\n"
		# e=1
	# else
		# printf "Multiple o1's found for clang $1,$3\n"
		# e=1
	# fi
# fi
# o+=$s
# o+=" "

# s=`find ../../corpora/ -wholename "*/$1.*.clang.o2.*.$3.feature.bloom"`
# count=`printf "%s" $s | wc -w`
# if [ $count -ne 1 ]; then
	# if [ $count -eq 0 ]; then
		# printf "o2 not found for clang $1,$3\n"
		# e=1
	# else
		# printf "Multiple o2's found for clang $1,$3\n"
		# e=1
	# fi
# fi
# o+=$s
# o+=" "

# s=`find ../../corpora/ -wholename "*/$1.*.clang.o3.*.$3.feature.bloom"`
# count=`printf "%s" $s | wc -w`
# if [ $count -ne 1 ]; then
	# if [ $count -eq 0 ]; then
		# printf "o3 not found for clang $1,$3\n"
		# e=1
	# else
		# printf "Multiple o3's found for clang $1,$3\n"
		# e=1
	# fi
# fi
# o+=$s
# o+=" "

# s=`find ../../corpora/ -wholename "*/$1.*.gcc.o0.*.$3.feature.bloom"`
# count=`printf "%s" $s | wc -w`
# if [ $count -ne 1 ]; then
	# if [ $count -eq 0 ]; then
		# printf "o0 not found for gcc $1,$3\n"
		# e=1
	# else
		# printf "Multiple o0's found for gcc $1,$3\n"
		# e=1
	# fi
# fi
# o+=$s
# o+=" "

# s=`find ../../corpora/ -wholename "*/$1.*.gcc.o1.*.$3.feature.bloom"`
# count=`printf "%s" $s | wc -w`
# if [ $count -ne 1 ]; then
	# if [ $count -eq 0 ]; then
		# printf "o1 not found for gcc $1,$3\n"
		# e=1
	# else
		# printf "Multiple o1's found for gcc $1,$3\n"
		# e=1
	# fi
# fi
# o+=$s
# o+=" "

# s=`find ../../corpora/ -wholename "*/$1.*.gcc.o2.*.$3.feature.bloom"`
# count=`printf "%s" $s | wc -w`
# if [ $count -ne 1 ]; then
	# if [ $count -eq 0 ]; then
		# printf "o2 not found for gcc $1,$3\n"
		# e=1
	# else
		# printf "Multiple o2's found for gcc $1,$3\n"
		# e=1
	# fi
# fi
# o+=$s
# o+=" "

# s=`find ../../corpora/ -wholename "*/$1.*.gcc.o3.*.$3.feature.bloom"`
# count=`printf "%s" $s | wc -w`
# if [ $count -ne 1 ]; then
	# if [ $count -eq 0 ]; then
		# printf "o3 not found for gcc $1,$3\n"
		# e=1
	# else
		# printf "Multiple o3's found for gcc $1,$3\n"
		# e=1
	# fi
# fi
# o+=$s
# o+=" "

# s=`find ../../corpora/ -wholename "*/$2.*.clang.o0.*.$3.feature.bloom"`
# count=`printf "%s" $s | wc -w`
# if [ $count -ne 1 ]; then
	# if [ $count -eq 0 ]; then
		# printf "o0 not found for clang $2,$3\n"
		# e=1
	# else
		# printf "Multiple o0's found for clang $2,$3\n"
		# e=1
	# fi
# fi
# o+=$s
# o+=" "

# s=`find ../../corpora/ -wholename "*/$2.*.clang.o1.*.$3.feature.bloom"`
# count=`printf "%s" $s | wc -w`
# if [ $count -ne 1 ]; then
	# if [ $count -eq 0 ]; then
		# printf "o1 not found for clang $2,$3\n"
		# e=1
	# else
		# printf "Multiple o1's found for clang $2,$3\n"
		# e=1
	# fi
# fi
# o+=$s
# o+=" "

# s=`find ../../corpora/ -wholename "*/$2.*.clang.o2.*.$3.feature.bloom"`
# count=`printf "%s" $s | wc -w`
# if [ $count -ne 1 ]; then
	# if [ $count -eq 0 ]; then
		# printf "o2 not found for clang $2,$3\n"
		# e=1
	# else
		# printf "Multiple o2's found for clang $2,$3\n"
		# e=1
	# fi
# fi
# o+=$s
# o+=" "

# s=`find ../../corpora/ -wholename "*/$2.*.clang.o3.*.$3.feature.bloom"`
# count=`printf "%s" $s | wc -w`
# if [ $count -ne 1 ]; then
	# if [ $count -eq 0 ]; then
		# printf "o3 not found for clang $2,$3\n"
		# e=1
	# else
		# printf "Multiple o3's found for clang $2,$3\n"
		# e=1
	# fi
# fi
# o+=$s
# o+=" "

# s=`find ../../corpora/ -wholename "*/$2.*.gcc.o0.*.$3.feature.bloom"`
# count=`printf "%s" $s | wc -w`
# if [ $count -ne 1 ]; then
	# if [ $count -eq 0 ]; then
		# printf "o0 not found for gcc $2,$3\n"
		# e=1
	# else
		# printf "Multiple o0's found for gcc $2,$3\n"
		# e=1
	# fi
# fi
# o+=$s
# o+=" "

# s=`find ../../corpora/ -wholename "*/$2.*.gcc.o1.*.$3.feature.bloom"`
# count=`printf "%s" $s | wc -w`
# if [ $count -ne 1 ]; then
	# if [ $count -eq 0 ]; then
		# printf "o1 not found for gcc $2,$3\n"
		# e=1
	# else
		# printf "Multiple o1's found for gcc $2,$3\n"
		# e=1
	# fi
# fi
# o+=$s
# o+=" "

# s=`find ../../corpora/ -wholename "*/$2.*.gcc.o2.*.$3.feature.bloom"`
# count=`printf "%s" $s | wc -w`
# if [ $count -ne 1 ]; then
	# if [ $count -eq 0 ]; then
		# printf "o2 not found for gcc $2,$3\n"
		# e=1
	# else
		# printf "Multiple o2's found for gcc $2,$3\n"
		# e=1
	# fi
# fi
# o+=$s
# o+=" "

# s=`find ../../corpora/ -wholename "*/$2.*.gcc.o3.*.$3.feature.bloom"`
# count=`printf "%s" $s | wc -w`
# if [ $count -ne 1 ]; then
	# if [ $count -eq 0 ]; then
		# printf "o3 not found for gcc $2,$3\n"
		# e=1
	# else
		# printf "Multiple o3's found for gcc $2,$3\n"
		# e=1
	# fi
# fi
# o+=$s
# o+=" "

# if [ $e -eq 1 ]; then
	# exit $e
# fi

# python ../../dev/similarity/bloom-jaccard/bloom_jaccard_ind.py $o > report.$1.$2.$3.txt

printf "diffbin bloom, $1-$2-$3:\n" 

printf "$1,$2,$3-bloom,clang,O0-O0: "
grep "$1.simple.lin.clang.o0.*$2.simple.lin.clang.o0.*$" report.$1.$2.$3.txt | cut -d " " -f 3

printf "$1,$2,$3-bloom,clang,O1-O1: "
grep "$1.simple.lin.clang.o1.*$2.simple.lin.clang.o1.*$" report.$1.$2.$3.txt | cut -d " " -f 3

printf "$1,$2,$3-bloom,clang,O2-O2: "
grep "$1.simple.lin.clang.o2.*$2.simple.lin.clang.o2.*$" report.$1.$2.$3.txt | cut -d " " -f 3

printf "$1,$2,$3-bloom,clang,O3-O3: "
grep "$1.simple.lin.clang.o3.*$2.simple.lin.clang.o3.*$" report.$1.$2.$3.txt | cut -d " " -f 3

printf "$1,$2,$3-bloom,gcc,O0-O0: "
grep "$1.simple.lin.gcc.o0.*$2.simple.lin.gcc.o0.*$" report.$1.$2.$3.txt | cut -d " " -f 3

printf "$1,$2,$3-bloom,gcc,O1-O1: "
grep "$1.simple.lin.gcc.o1.*$2.simple.lin.gcc.o1.*$" report.$1.$2.$3.txt | cut -d " " -f 3

printf "$1,$2,$3-bloom,gcc,O2-O2: "
grep "$1.simple.lin.gcc.o2.*$2.simple.lin.gcc.o2.*$" report.$1.$2.$3.txt | cut -d " " -f 3

printf "$1,$2,$3-bloom,gcc,O3-O3: "
grep "$1.simple.lin.gcc.o3.*$2.simple.lin.gcc.o3.*$" report.$1.$2.$3.txt | cut -d " " -f 3

rm blooms.$1.$2.$3.txt report.$1.$2.$3.txt
#rm report.$1.$2.$3.txt
