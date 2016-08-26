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

#brief but no error checking
find ../../corpora/ -wholename "*/$1.*.cpc.chain" > edits.$1.$2.txt
find ../../corpora/ -wholename "*/$2.*.cpc.chain" >> edits.$1.$2.txt
python ../../dev/similarity/editdistance/edit_distance.py `cat edits.$1.$2.txt` > report.$1.$2.txt

# e=0
# o=""
# s=`find ../../corpora/ -wholename "*/$1.*.clang.o0.*.cpc.chain"`
# count=`printf "%s" $s | wc -w`
# if [ $count -ne 1 ]; then
	# if [ $count -eq 0 ]; then
		# printf "o0 not found for clang $1\n"
		# e=1
	# else
		# printf "Multiple o0's found for clang $1\n"
		# e=1
	# fi
# fi
# o+=$s
# o+=" "

# s=`find ../../corpora/ -wholename "*/$1.*.clang.o1.*.cpc.chain"`
# count=`printf "%s" $s | wc -w`
# if [ $count -ne 1 ]; then
	# if [ $count -eq 0 ]; then
		# printf "o1 not found for clang $1\n"
		# e=1
	# else
		# printf "Multiple o1's found for clang $1\n"
		# e=1
	# fi
# fi
# o+=$s
# o+=" "

# s=`find ../../corpora/ -wholename "*/$1.*.clang.o2.*.cpc.chain"`
# count=`printf "%s" $s | wc -w`
# if [ $count -ne 1 ]; then
	# if [ $count -eq 0 ]; then
		# printf "o2 not found for clang $1\n"
		# e=1
	# else
		# printf "Multiple o2's found for clang $1\n"
		# e=1
	# fi
# fi
# o+=$s
# o+=" "

# s=`find ../../corpora/ -wholename "*/$1.*.clang.o3.*.cpc.chain"`
# count=`printf "%s" $s | wc -w`
# if [ $count -ne 1 ]; then
	# if [ $count -eq 0 ]; then
		# printf "o3 not found for clang $1\n"
		# e=1
	# else
		# printf "Multiple o3's found for clang $1\n"
		# e=1
	# fi
# fi
# o+=$s
# o+=" "

# s=`find ../../corpora/ -wholename "*/$1.*.gcc.o0.*.cpc.chain"`
# count=`printf "%s" $s | wc -w`
# if [ $count -ne 1 ]; then
	# if [ $count -eq 0 ]; then
		# printf "o0 not found for gcc $1\n"
		# e=1
	# else
		# printf "Multiple o0's found for gcc $1\n"
		# e=1
	# fi
# fi
# o+=$s
# o+=" "

# s=`find ../../corpora/ -wholename "*/$1.*.gcc.o1.*.cpc.chain"`
# count=`printf "%s" $s | wc -w`
# if [ $count -ne 1 ]; then
	# if [ $count -eq 0 ]; then
		# printf "o1 not found for gcc $1\n"
		# e=1
	# else
		# printf "Multiple o1's found for gcc $1\n"
		# e=1
	# fi
# fi
# o+=$s
# o+=" "

# s=`find ../../corpora/ -wholename "*/$1.*.gcc.o2.*.cpc.chain"`
# count=`printf "%s" $s | wc -w`
# if [ $count -ne 1 ]; then
	# if [ $count -eq 0 ]; then
		# printf "o2 not found for gcc $1\n"
		# e=1
	# else
		# printf "Multiple o2's found for gcc $1\n"
		# e=1
	# fi
# fi
# o+=$s
# o+=" "

# s=`find ../../corpora/ -wholename "*/$1.*.gcc.o3.*.cpc.chain"`
# count=`printf "%s" $s | wc -w`
# if [ $count -ne 1 ]; then
	# if [ $count -eq 0 ]; then
		# printf "o3 not found for gcc $1\n"
		# e=1
	# else
		# printf "Multiple o3's found for gcc $1\n"
		# e=1
	# fi
# fi
# o+=$s
# o+=" "

# s=`find ../../corpora/ -wholename "*/$2.*.clang.o0.*.cpc.chain"`
# count=`printf "%s" $s | wc -w`
# if [ $count -ne 1 ]; then
	# if [ $count -eq 0 ]; then
		# printf "o0 not found for clang $2\n"
		# e=1
	# else
		# printf "Multiple o0's found for clang $2\n"
		# e=1
	# fi
# fi
# o+=$s
# o+=" "

# s=`find ../../corpora/ -wholename "*/$2.*.clang.o1.*.cpc.chain"`
# count=`printf "%s" $s | wc -w`
# if [ $count -ne 1 ]; then
	# if [ $count -eq 0 ]; then
		# printf "o1 not found for clang $2\n"
		# e=1
	# else
		# printf "Multiple o1's found for clang $2\n"
		# e=1
	# fi
# fi
# o+=$s
# o+=" "

# s=`find ../../corpora/ -wholename "*/$2.*.clang.o2.*.cpc.chain"`
# count=`printf "%s" $s | wc -w`
# if [ $count -ne 1 ]; then
	# if [ $count -eq 0 ]; then
		# printf "o2 not found for clang $2\n"
		# e=1
	# else
		# printf "Multiple o2's found for clang $2\n"
		# e=1
	# fi
# fi
# o+=$s
# o+=" "

# s=`find ../../corpora/ -wholename "*/$2.*.clang.o3.*.cpc.chain"`
# count=`printf "%s" $s | wc -w`
# if [ $count -ne 1 ]; then
	# if [ $count -eq 0 ]; then
		# printf "o3 not found for clang $2\n"
		# e=1
	# else
		# printf "Multiple o3's found for clang $2\n"
		# e=1
	# fi
# fi
# o+=$s
# o+=" "

# s=`find ../../corpora/ -wholename "*/$2.*.gcc.o0.*.cpc.chain"`
# count=`printf "%s" $s | wc -w`
# if [ $count -ne 1 ]; then
	# if [ $count -eq 0 ]; then
		# printf "o0 not found for gcc $2\n"
		# e=1
	# else
		# printf "Multiple o0's found for gcc $2\n"
		# e=1
	# fi
# fi
# o+=$s
# o+=" "

# s=`find ../../corpora/ -wholename "*/$2.*.gcc.o1.*.cpc.chain"`
# count=`printf "%s" $s | wc -w`
# if [ $count -ne 1 ]; then
	# if [ $count -eq 0 ]; then
		# printf "o1 not found for gcc $2\n"
		# e=1
	# else
		# printf "Multiple o1's found for gcc $2\n"
		# e=1
	# fi
# fi
# o+=$s
# o+=" "

# s=`find ../../corpora/ -wholename "*/$2.*.gcc.o2.*.cpc.chain"`
# count=`printf "%s" $s | wc -w`
# if [ $count -ne 1 ]; then
	# if [ $count -eq 0 ]; then
		# printf "o2 not found for gcc $2\n"
		# e=1
	# else
		# printf "Multiple o2's found for gcc $2\n"
		# e=1
	# fi
# fi
# o+=$s
# o+=" "

# s=`find ../../corpora/ -wholename "*/$2.*.gcc.o3.*.cpc.chain"`
# count=`printf "%s" $s | wc -w`
# if [ $count -ne 1 ]; then
	# if [ $count -eq 0 ]; then
		# printf "o3 not found for gcc $2\n"
		# e=1
	# else
		# printf "Multiple o3's found for gcc $2\n"
		# e=1
	# fi
# fi
# o+=$s
# o+=" "

# if [ $e -eq 1 ]; then
	# exit $e
# fi

# python ../../dev/similarity/editdistance/edit_distance.py $o > report.$1.$2.txt

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
#rm report.$1.$2.txt
