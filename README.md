# Overview
CAC Aggrregation by Reversing and Dumping in Arrays Lightweight (Cardinal) is a tool that accurately finds callsite argument cardinalities (CAC's) and creates a easily comparable signature by aggregating them per function and dumping the result into a Bloom filter. Bloom filters are compared via the Jaccard index from which a similarity score is calculated. Cardinal is proven to tolerate differences between binaries produced using the same source but different compiler configurations, from using different optimization levels to using completely different compilers. We hope that Cardinal paves the way for future static analyses that similarly tolerate radical code transformations like a dynamic analysis, yet still retain the benefits of static analysis

# Requirements
* IDA Pro
* Python 2.7
* LLVM (Optional: for ground truth calculation tool, cpc-tool)
* CMake (Optional: for ground truth calculation tool, cpc-tool)
#### Python deps
```
pip install capstone pyelftools pybloom editdistance
```

# Usage
First we cover how to use Cardinal on a single sample. This is what the test harnass automates for many samples.
## Using Cardinal directly
## Using the test harnass

# Contact
Email: luke dotto jones dotto ctr atta usafa dotto edu
