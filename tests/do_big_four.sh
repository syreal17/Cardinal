#!/bin/bash
printf "Generating burg features\n"
./create_sigs.sh burg
printf "Generating treecc features\n"
./create_sigs.sh treecc
printf "Generating lua features\n"
./create_sigs.sh lua
printf "Generating sqlite3 features\n"
./create_sigs.sh sqlite3

printf "Generating report\n"

./view_isocomp_results.sh burg clang cpc > big_four.report
./view_isocomp_results.sh burg clang mc >> big_four.report
./view_isocomp_results.sh treecc clang cpc >> big_four.report
./view_isocomp_results.sh treecc clang mc >> big_four.report
./view_isocomp_results.sh lua clang cpc >> big_four.report
./view_isocomp_results.sh lua clang mc >> big_four.report
./view_isocomp_results.sh sqlite3 clang cpc >> big_four.report
./view_isocomp_results.sh sqlite3 clang mc >> big_four.report
./view_isocomp_results.sh burg gcc cpc >> big_four.report
./view_isocomp_results.sh burg gcc mc >> big_four.report
./view_isocomp_results.sh treecc gcc cpc >> big_four.report
./view_isocomp_results.sh treecc gcc mc >> big_four.report
./view_isocomp_results.sh lua gcc cpc >> big_four.report
./view_isocomp_results.sh lua gcc mc >> big_four.report
./view_isocomp_results.sh sqlite3 gcc cpc >> big_four.report
./view_isocomp_results.sh sqlite3 gcc mc >> big_four.report

./view_diffcomp_results.sh burg cpc >> big_four.report
./view_diffcomp_results.sh burg mc >> big_four.report
./view_diffcomp_results.sh treecc cpc >> big_four.report
./view_diffcomp_results.sh treecc mc >> big_four.report
./view_diffcomp_results.sh lua cpc >> big_four.report
./view_diffcomp_results.sh lua mc >> big_four.report
./view_diffcomp_results.sh sqlite3 cpc >> big_four.report
./view_diffcomp_results.sh sqlite3 mc >> big_four.report
