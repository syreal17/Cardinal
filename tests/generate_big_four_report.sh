#!/bin/bash
printf "Generating report\n"

#Bloom/Jaccard

./view_isocomp_results_bloom.sh burg clang cpc > big_four.report
./view_isocomp_results_bloom.sh burg clang mc >> big_four.report
./view_isocomp_results_bloom.sh treecc clang cpc >> big_four.report
./view_isocomp_results_bloom.sh treecc clang mc >> big_four.report
./view_isocomp_results_bloom.sh lua clang cpc >> big_four.report
./view_isocomp_results_bloom.sh lua clang mc >> big_four.report
./view_isocomp_results_bloom.sh sqlite3 clang cpc >> big_four.report
./view_isocomp_results_bloom.sh sqlite3 clang mc >> big_four.report
./view_isocomp_results_bloom.sh burg gcc cpc >> big_four.report
./view_isocomp_results_bloom.sh burg gcc mc >> big_four.report
./view_isocomp_results_bloom.sh treecc gcc cpc >> big_four.report
./view_isocomp_results_bloom.sh treecc gcc mc >> big_four.report
./view_isocomp_results_bloom.sh lua gcc cpc >> big_four.report
./view_isocomp_results_bloom.sh lua gcc mc >> big_four.report
./view_isocomp_results_bloom.sh sqlite3 gcc cpc >> big_four.report
./view_isocomp_results_bloom.sh sqlite3 gcc mc >> big_four.report

./view_diffcomp_results_bloom.sh burg cpc >> big_four.report
./view_diffcomp_results_bloom.sh burg mc >> big_four.report
./view_diffcomp_results_bloom.sh treecc cpc >> big_four.report
./view_diffcomp_results_bloom.sh treecc mc >> big_four.report
./view_diffcomp_results_bloom.sh lua cpc >> big_four.report
./view_diffcomp_results_bloom.sh lua mc >> big_four.report
./view_diffcomp_results_bloom.sh sqlite3 cpc >> big_four.report
./view_diffcomp_results_bloom.sh sqlite3 mc >> big_four.report

#Edit Distance

./view_isocomp_results_edit.sh burg clang >> big_four.report
./view_isocomp_results_edit.sh treecc clang >> big_four.report
./view_isocomp_results_edit.sh lua clang >> big_four.report
./view_isocomp_results_edit.sh sqlite3 clang >> big_four.report
./view_isocomp_results_edit.sh burg gcc >> big_four.report
./view_isocomp_results_edit.sh treecc gcc >> big_four.report
./view_isocomp_results_edit.sh lua gcc >> big_four.report
./view_isocomp_results_edit.sh sqlite3 gcc >> big_four.report

./view_diffcomp_results_edit.sh burg >> big_four.report
./view_diffcomp_results_edit.sh treecc >> big_four.report
./view_diffcomp_results_edit.sh lua >> big_four.report
./view_diffcomp_results_edit.sh sqlite3 >> big_four.report
