# KEM Benchmark

This directory contains standalone C++ benchmarks for post-quantum key encapsulation mechanisms (KEMs) used in the experimental evaluation.

## Included Algorithms

* Kyber
* NTRU
* BIKE

The benchmark programs use liboqs and measure the configured KEM operations using repeated executions.

## Benchmark Configuration

The benchmark programs are configured to use:

* 100 warm-up iterations
* 1000 measured iterations

The exact operations and reported metrics are defined by the corresponding C++ benchmark source code.

## Directory Structure


KEM_Benchmark/
│
├── kyber/
│   ├── kyber_pqc_benchmark.cpp
│   └── steps_to_run.md
│
├── ntru/
│   ├── ntru_pqc_benchmark.cpp
│   └── steps_to_run.md
│
└── BIKE/
    ├── bike_pqc_benchmark.cpp
    └── steps_to_run.md


## Requirements

A compatible liboqs installation is required.

The benchmark compilation commands assume:


/usr/local/include
/usr/local/lib


are the locations of the liboqs headers and library.

If liboqs is installed elsewhere, adjust the `-I` and `-L` compiler options accordingly.

## Kyber

The Kyber benchmark evaluates the configured Kyber parameter sets.

See:


kyber/steps_to_run.md


for compilation and execution commands.

## NTRU

The NTRU benchmark evaluates the configured NTRU parameter sets.

See:


ntru/steps_to_run.md


for compilation and execution commands.

## BIKE

The BIKE benchmark evaluates the configured BIKE parameter sets.

See:


BIKE/steps_to_run.md


for compilation and execution commands.

## Output Files

The benchmark programs generate CSV files containing raw measurements and/or summary statistics.

These generated files are not included in the repository and should be produced locally when reproducing the experiments.
