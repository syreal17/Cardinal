# Task Tutorials
## Basic Tests
See the root README under "Using the test harness" for a quick rundown on how to run the basic tests and analyze the results.

# Script Structure
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

# File listing
