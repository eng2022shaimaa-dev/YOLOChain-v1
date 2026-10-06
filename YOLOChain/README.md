# YOLOChain

## Blockchain-Enabled Smart Surveillance with Post-Quantum Security

This repository contains the source code and experimental materials used to evaluate YOLOChain, a blockchain-enabled smart surveillance framework integrating YOLOv8-based object detection, MQTT communication, PBFT-style consensus, and post-quantum cryptographic primitives.

## Repository Structure


YOLOChain/
│
├── .gitignore
├── README.md
├── requirements.txt
├── package.json
│
├── Ablation Study/
│   ├── experiment_A&B/
│   │   ├── unified_experiment_AB.py
│   │   └── experiment_A&B_readme.md
│   │
│   ├── experiment_C/
│   │   ├── *.js
│   │   ├── experiment_C_E2E.py
│   │   └── experiment_C_readme.md
│   │
│   ├── experiment_D/
│   │   ├── *.js
│   │   ├── *.py
│   │   └── experiment_D_readme.md
│   │
│   └── ablation_readme.md
│
├── PQC_library/
│   ├── r1_pqc_kem_lib.cpp
│   ├── r1_sign_lib.cpp
│   └── PQC_library_readme.md
│
├── kem benchmark/
│   ├── kyber/
│   │   ├── kyber_pqc_benchmark.cpp
│   │   └── steps_to_run.md
│   ├── ntru/
│   │   ├── ntru_pqc_benchmark.cpp
│   │   └── steps_to_run.md
│   └── BIKE/
│       ├── bike_pqc_benchmark.cpp
│       └── steps_to_run.md
│
├── signature benchmark/
│   ├── falcon/
│   │   ├── falcon_pqc_benchmark.cpp
│   │   └── steps_to_run.md
│   ├── mayo/
│   │   ├── mayo_pqc_benchmark.cpp
│   │   └── steps_to_run.md
│   └── sphincs/
│       ├── sphincs_pqc_benchmark.cpp
│       └── steps_to_run.md
│
├── scalability_yolochain/
│   ├── *.js
│   ├── *.py
│   └── scalability_yolochain_readme.md
│
└── security/
    ├── *.js
    ├── *.py
    └── security_readme.md


## Experiments

The repository contains four ablation configurations:

* **Experiment A:** YOLOv8
* **Experiment B:** YOLOv8 + MQTT
* **Experiment C:** YOLOv8 + MQTT + PBFT
* **Experiment D:** YOLOv8 + MQTT + PQC + PBFT

The detailed execution procedure for each experiment is provided in the corresponding experiment directory.

## Experimental Configuration

The main YOLOChain experiments use the following configuration:

* YOLOv8n
* Input resolution: 416 × 416
* Confidence threshold: 0.25
* IoU threshold: 0.50
* Batch size: 1
* Warm-up iterations: 10
* Independent runs: 5
* CPU execution
* CUDA: False

## Datasets

The experiments use:

* COCO128
* MOT17-04-SDP

The datasets themselves are not included in this repository.

The experiment README files specify the expected dataset structure and the corresponding input arguments.

## Post-Quantum Cryptography

The YOLOChain experiments use post-quantum cryptographic primitives including:

* Falcon-512
* Kyber-512
* NTRU-HPS-2048-509
* BIKE-L1
* SPHINCS+
* MAYO

KEM primitives are used for session/key establishment, while digital signatures are used for authentication and integrity according to the corresponding experimental configuration.

The PQC wrapper implementations used by the YOLOChain experiments are provided in:


PQC_library/

The standalone cryptographic performance benchmarks are provided separately in:


KEM_Benchmark/
Signature_Benchmark/


## KEM Benchmarks

The `KEM_Benchmark/` directory contains standalone C++ benchmarks for:

* Kyber
* NTRU
* BIKE

The benchmarks measure the corresponding KEM operations using the configured liboqs installation.

Each algorithm directory contains:

* the C++ benchmark source code
* a `steps_to_run.md` file containing the compilation and execution commands

The benchmark output files are generated locally and are not included in the repository.

## Signature Benchmarks

The `Signature_Benchmark/` directory contains standalone C++ benchmarks for:

* Falcon
* MAYO
* SPHINCS+

Each algorithm directory contains:

* the C++ benchmark source code
* a `steps_to_run.md` file containing the compilation and execution commands

The benchmark output files are generated locally and are not included in the repository.

## Blockchain

The blockchain component uses PBFT-style consensus with:

* N = 4 validators
* f = 1
* quorum = 3

Validator scalability experiments are provided in:

scalability_yolochain/


## Security Evaluation

The security experiments evaluate the following scenarios:

* **S1 — Replay**
* **S2 — Modified metadata**
* **S3 — Fake camera**
* **S4 — MITM/message tampering**
* **S5 — Off-chain data tampering**

The corresponding source code and execution instructions are provided in:


security/


## Software Requirements

The repository uses both Python and Node.js components.

Python dependencies are listed in:


requirements.txt


Node.js dependencies are specified in:

package.json


The PQC components require a compatible installation of **liboqs**.

The C++ benchmarks require a C++ compiler and access to the liboqs headers and library.

## PQC Shared Libraries

The `PQC_library/` directory contains the C/C++ wrapper source files and shared libraries used by the YOLOChain implementation.

The provided wrappers expose PQC functionality to the Node.js/Python components through the generated shared libraries.

The directory contains:

* `r1_pqc_kem_lib.cpp`
* `r1_pqc_kem_lib.so`
* `r1_sign_lib.cpp`
* `r1_sign_lib.so`

Compilation instructions are provided in:


PQC_library/PQC_library_readme.md


## Reproducibility

Each experimental component contains a dedicated README file describing the commands required to reproduce the corresponding experiment or benchmark.

In particular:

* `Ablation Study/` — YOLOChain ablation experiments
* `KEM_Benchmark/` — standalone KEM benchmarks
* `Signature_Benchmark/` — standalone signature benchmarks
* `scalability_yolochain/` — validator scalability experiments
* `security/` — security evaluation experiments
* `PQC_library/` — PQC shared-library compilation

Generated results, benchmark CSV files, temporary runtime files, and dataset files are not included in the repository.


