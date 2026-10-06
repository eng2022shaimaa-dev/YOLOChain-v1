# Signature Benchmark

This directory contains standalone C++ benchmarks for post-quantum digital signature algorithms used in the experimental evaluation.

## Included Algorithms

* Falcon
* MAYO
* SPHINCS+

## Directory Structure


Signature_Benchmark/
│
├── falcon/
│   ├── falcon_pqc_benchmark.cpp
│   └── steps_to_run.md
│
├── mayo/
│   ├── mayo_pqc_benchmark.cpp
│   └── steps_to_run.md
│
└── sphincs/
    ├── sphincs_pqc_benchmark.cpp
    └── steps_to_run.md


## Requirements

A compatible liboqs installation is required.

The compilation commands assume:


/usr/local/include
/usr/local/lib


are the locations of the liboqs headers and library.

If liboqs is installed elsewhere, adjust the compilation commands accordingly.

## Falcon

The Falcon benchmark evaluates the configured Falcon parameter sets.

See:


falcon/steps_to_run.md


## MAYO

The MAYO benchmark evaluates the configured MAYO parameter sets.

See:


mayo/steps_to_run.md


## SPHINCS+

The SPHINCS+ benchmark evaluates the configured SPHINCS+ parameter sets.

See:


sphincs/steps_to_run.md


## Output

The benchmark programs generate CSV files containing the measured and summarized results.

Generated benchmark results are not included in the repository.
