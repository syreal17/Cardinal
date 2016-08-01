#!/bin/bash

#copy passed in sample names                                                    
samples=""                                                                      
for var in "$@"                                                                 
do                                                                              
        samples="$samples $var"                                                 
done          

for sample in $samples
do
printf "Creating new dictionaries for $sample\n"
./create_dicts.sh $sample
done

printf "Calculating current accuracy\n"
printf "" > accuracy/accuracy.new.report

for sample in $samples
do
printf "Calculating $sample accuracy\n"
./view_accuracy_results.sh $sample >> accuracy/accuracy.new.report
done

#compare old and new results
#for line in old accuracy, print line compare percent to new, print correct symbol, print new

n=1
lines1=$(wc -l accuracy/accuracy.report | cut -d" " -f 1)
lines2=$(wc -l accuracy/accuracy.new.report | cut -d" " -f 1)
max_lines=$((lines1 > lines2 ? lines1 : lines2))
better_sum=0
worse_sum=0
same_sum=0
acc_sum=0
while [ $n -le $max_lines ]
do
line1="$(sed -n ${n}p accuracy/accuracy.report)"
acc1=$(printf "$line1" | cut -d" " -f 2)
line2="$(sed -n ${n}p accuracy/accuracy.new.report)"
acc2=$(printf "$line2" | cut -d" " -f 2)
acc_sum=$( bc <<< "$acc_sum+($acc2-$acc1)")
sym=""
if (( $(echo "$acc1 > $acc2" | bc -l) )); then
sym=">";
worse_sum=$((worse_sum+1));
elif (( $(echo "$acc1 == $acc2" | bc -l) )); then
sym="=";
same_sum=$((same_sum+1));
else 
sym="<";
better_sum=$((better_sum+1));
fi
printf "$line1 $sym $acc2\n"
n=$((n+1))
done

printf "$same_sum tests the same\n"
printf "$better_sum tests better\n"
printf "$worse_sum tests worse\n"
printf "$acc_sum percent change overall\n"