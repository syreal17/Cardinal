#!/bin/bash
printf "Generating burg features\n"
./create_sigs.sh burg
./create_chains.sh burg
printf "Generating treecc features\n"
./create_sigs.sh treecc
./create_chains.sh treecc
printf "Generating lua features\n"
./create_sigs.sh lua
./create_chains.sh lua
printf "Generating sqlite3 features\n"
./create_sigs.sh sqlite3
./create_chains.sh sqlite3

./generate_big_four_report.sh
