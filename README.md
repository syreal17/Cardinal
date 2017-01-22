# Overview
CPC Aggregation by Reversing and Dumping in Arrays Lightweight (CARDINAL) is a tool that can find similarities between binaries compiled with different optimization flags, or even completely different compilers. CARDINAL accurately finds the number of arguments at each callsite, also known as the callsite parameter cardinalities (CPC's), and creates a easily comparable signature by aggregating them per function and dumping the result into a Bloom filter. Bloom filters are compared via the Jaccard index from which a similarity score is calculated. CARDINAL is proven to tolerate differences between binaries produced using the same source but different compiler configurations, from using different optimization levels to using completely different compilers. We hope that CARDINAL paves the way for future static analyses that similarly tolerate radical code transformations like a dynamic analysis, yet still retain the benefits of static analysis. For more information, [see the paper](Cardinal-Malware2016Paper.pdf).

# Requirements
* IDA Pro
* CMake
* Python 2.7 with pip
* Cygwin (Required if running CARDINAL on Windows, which is recommended)
* LLVM (Optional: for ground truth calculation tool, cpc-tool)

# Getting Started
1. Add Python27 and IDA base folders to your system path
2. Install Python modules: `pip install capstone pyelftools pybloom editdistance`
3. Download repo `git clone https://github.com/syreal17/Cardinal.git`

# Notes
* Add your "IDA 6.9" folder to your path
* make sure you can connect to the IDA license server
* Add "Cardinal/dev/feature_extraction" to PythonPath environment variable
* make sure that "C:\Python27\python.exe" exists and is the Python install that you add the above packages to

# Usage
## Using CARDINAL directly
1. `idaw64.exe -A -S"Cardinal\dev\feature_extraction\cpc\ida_cpc_extract.py -l" name_of_test_binary1.elf` This extracts the CPC features from the binary in the form of newline delimited chains of CPC's. Each line or chain represents all the CPC's in one function.
2. `python Cardinal\dev\similarity\bloom-jaccard\to_bloom.py name_of_test_binary1.elf.cpc.feature` This enters all of the CPC chains into a Bloom filter for quick comparison.
3. `python Cardinal\dev\similarity\bloom-jaccard\bloom_jaccard_ind.py name_of_test_binary1.elf.cpc.feature.bloom name_of_test_binary2.elf.cpc.feature.bloom` This yields a number between 0 and 1 inclusive. 0 means none of the CPC chains matched in the bloom filters and 1 means all of the CPC chains matched in the bloom filters.

## Using the test harness
The test harness automates the above steps for a large number of binaries. We run the tests en masse by executing a `find` command and running the above steps on all matching files. The test harness is designed to perform the isocompiler modulation, different compiler, and different source tests, and as such, the harness only handles files that conform to the naming scheme adopted for the aforementioned tests. The scheme is as follows: `[name_of_test_binary].simple.lin.[name_of_compiler].[optimization_flag].elf` "Name of compiler" can be "clang" or "gcc" and "optimization flag" can be "o0," "o1," "o2," or "o3".

To run the isocompiler modulation, different compiler, and different source tests on a group of binaries simply do:
```
cd Cardinal/tests/windows
./test_bins.sh [name_of_test_binary1] [name_of_test_binary2] ... [name_of_test_binaryN]
```

For example `./test_bin.sh treecc vis burg` if using our corpora. This creates `multi_sample.report` with all the data from running isocompiler modulation, different compiler and different source tests. The data can be put into an R consumable form by running the following:
```
./create_isocomp_dats.sh [name_of_test_binary1] [name_of_test_binary2] ... [name_of_test_binaryN]
./create_diffcomp_dats.sh [name_of_test_binary1] [name_of_test_binary2] ... [name_of_test_binaryN]
./create_diffbin_dats.sh [name_of_test_binary1] [name_of_test_binary2] ... [name_of_test_binaryN]
```
The create dats scripts read "multi_sample.report" and put the data into a better format. The "graph" variations of these scripts put the data into two columns, test and similarity score, whereas the original create dat scripts put the data into N columns, one for each binary. More details for the testing framework are covered in Cardinal/tests/windows/README.md.
