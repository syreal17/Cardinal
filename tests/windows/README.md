# Task Tutorials
## Basic Tests
See Cardinal/README.md under "Using the test harness" for a quick rundown on how to run the basic tests and analyze the results.

## Parallelizing Different Source Tests
The amount of computations for the different sources tests balloons quickly. Therefore, we made some shell scripts that spin off background jobs to utilize multiple cores for these tests.

First, create the signatures for each of your test binaries:
```
cd Cardinal/tests/windows
./test_bins_gen.sh [names of test binaries]
```

Now, on your multicore machine, start the different sources tests:
```
./start_parallel_diffbin.sh [names of test binaries]
```

After all of the jobs have finished, the reports of the different sources tests must be merged:
```
./merge_diffbin_reports.sh [names of test binaries]
```

The isocompiler modulation and different compiler tests will have to be started separately, such as:
```
./generate_similarity_reports.sh [names of test binaries]
```

## Accuracy Tests

# Script Structure
There's a lot of shell scripts supporting the testing harness. The following highlights the scripts that each script calls, proceeding from most dependencies to least.
```
test_bins.sh
|     └────────────────────────┬────────────────────┐
V                              V                    V
generate_report.sh      create_sigs.sh      create_chains.sh
|     └─────────────────────────────────────────────┐
V                                                   V
generate_similarity_reports.sh       generate_difference_reports.sh
│                                    |
├─ > view_isocomp_results_bloom.sh   ├─ > view_diffbin_results_bloom.sh
├─ > view_isocomp_results_edit.sh    └─ > view_diffbin_results_edit.sh
├─ > view_diffcomp_results_bloom.sh
└─ > view_diffcomp_results_edit.sh
```
```
test_bins_sim.sh
|     └────────────────────────────────────┬────────────────────┐
V                                          V                    V
generate_similarity_reports.sh       create_sigs.sh      create_chains.sh
│
├─ > view_isocomp_results_bloom.sh
├─ > view_isocomp_results_edit.sh
├─ > view_diffcomp_results_bloom.sh
└─ > view_diffcomp_results_edit.sh
```
```
test_bins_gen.sh
|     └─────────────────┐
V                       V
create_sigs.sh  create_chains.sh
```
```
start_parallel_diffbin.sh
|
V
generate_difference_reports_parallel.sh
|     └─────────────────────────────────────────┐
V                                               V
view_diffbin_results_bloom.sh      view_diffbin_results_edit.sh
```
```
start_parallel_diffbin_bloom.sh
|
V
generate_difference_reports_parallel_bloom.sh
|
V
view_diffbin_results_bloom.sh
```
```
create_sigs.sh,create_chains.sh,create_dicts.sh
│
├─ > Cardinal/dev/feature_extraction/cpc/ida_cpc_extract_standalone.py
├─ > Cardinal/dev/feature_extraction/benchmarks/machine_code.py
├─ > Cardinal/dev/feature_extraction/benchmarks/ida_bbcp.py
└─ > Cardinal/dev/similarity/bloom-jaccard/to_bloom.py
```
```
view_isocomp_results_bloom.sh,view_diffcomp_results_bloom.sh,view_diffbin_results_bloom.sh
|
V
Cardinal/dev/similarity/bloom-jaccard/bloom_jaccard_ind.py
```
```
view_isocomp_results_edit.sh,view_diffcomp_results_edit.sh,view_diffbin_results_edit.sh
|
V
Cardinal/dev/similarity/editdistance/edit_distance.py
```
