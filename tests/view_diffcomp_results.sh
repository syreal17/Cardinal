#!/bin/bash

function helptext {
	printf "view_diffcomp_results [name of binary] [name of feature]\n"
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

find ../corpora/ -name *$1*.$2.feature.bloom -exec python ../dev/similarity/bloom-jaccard/bloom_jaccard_ind.py {} + > report.txt

printf "diff comp, $1-$2:\n"

printf "clang O0 <-> gcc O0: "
grep "clang\.o0.*gcc\.o0.*$" report.txt | cut -d " " -f 3

printf "clang O1 <-> gcc O1: "
grep "clang\.o1.*gcc\.o1.*$" report.txt | cut -d " " -f 3

printf "clang O2 <-> gcc O2: "
grep "clang\.o2.*gcc\.o2.*$" report.txt | cut -d " " -f 3

printf "clang O3 <-> gcc O3: "
grep "clang\.o3.*gcc\.o3.*$" report.txt | cut -d " " -f 3
