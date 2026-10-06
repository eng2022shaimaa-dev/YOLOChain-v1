# PQC Library

This directory contains the C++ implementations and shared libraries used by the YOLOChain experiments for post-quantum cryptographic operations.

## Files


r1_pqc_kem_lib.cpp, 
r1_pqc_kem_lib.so, 
r1_sign_lib.cpp, 
r1_sign_lib.so


* `r1_pqc_kem_lib.cpp`: C++ implementation of the PQC KEM interface.
* `r1_pqc_kem_lib.so`: compiled shared library for the KEM interface.
* `r1_sign_lib.cpp`: C++ implementation of the PQC signature interface.
* `r1_sign_lib.so`: compiled shared library for the signature interface.


## KEM Algorithms as an example

The KEM wrapper provides access to the following algorithms through liboqs:

* Kyber-512
* NTRU-HPS-2048-509
* BIKE-L1

The algorithm is selected through the character parameter:

```text
1 → Kyber-512
2 → NTRU-HPS-2048-509
3 → BIKE-L1
```

## KEM Interface

The shared library exports the following functions:

pqc_kem_keypair()
pqc_kem_encaps()
pqc_kem_decaps()
pqc_kem_free()


The wrapper uses dynamic memory allocation for generated keys, ciphertexts, and shared secrets. Memory returned by the library should be released using:

pqc_kem_free()


## Requirements

The libraries require:

* GCC/G++ -- (C/C++ compiler)
* liboqs
* Linux environment
* liboqs development headers and libraries

The source includes:

<oqs/oqs.h>

The exact liboqs version used for the experiments should match the version reported in the manuscript.

## Building the KEM Shared Library

From this directory:


g++ -fPIC -shared r1_pqc_kem_lib.cpp -o r1_pqc_kem_lib.so


## Building the Signature Shared Library


g++ -fPIC -shared r1_sign_lib.cpp -o r1_sign_lib.so


## Usage

The resulting .so files are loaded by the Python/Node.js experimental
code through their respective foreign-function interfaces.


If the local liboqs installation requires explicit include or library paths, provide them according to the liboqs installation.

For example, when supported by the local installation:


g++ -fPIC -shared r1_pqc_kem_lib.cpp \
    $(pkg-config --cflags --libs liboqs) \
    -o r1_pqc_kem_lib.so


and:


g++ -fPIC -shared r1_sign_lib.cpp \
    $(pkg-config --cflags --libs liboqs) \
    -o r1_sign_lib.so


Use the compilation command that corresponds to the installed liboqs configuration.

## Checking the Shared Libraries

After compilation:

ls -lh *.so

The expected files are:

r1_pqc_kem_lib.so, 
r1_sign_lib.so

## Verify the Shared Library

Check the shared-library dependencies:

ldd r1_pqc_kem_lib.so | grep oqs

Check the exported KEM functions:

nm -D r1_pqc_kem_lib.so | grep pqc_kem

The exported functions should include:

1.	pqc_kem_keypair
2.	pqc_kem_encaps
3.	pqc_kem_decaps
4.	pqc_kem_free


## Runtime Library Path

If the system cannot locate `liboqs.so` at runtime, the library path can be temporarily specified using:

export LD_LIBRARY_PATH=/path/to/liboqs/lib:$LD_LIBRARY_PATH

The exact path depends on the local liboqs installation.

------
The shared libraries can also be inspected using:

file r1_pqc_kem_lib.so
file r1_sign_lib.so


## Usage in YOLOChain

The YOLOChain Experiment D implementation loads the required PQC shared library during execution.

For example:


--pqc-library ./r1_sign_lib.so


The shared library path must be changed if the library is located in a different directory.

## Important

The `.so` files included in this repository were compiled for the experimental Linux environment.

For reproducibility on another system, rebuilding the shared libraries from the provided `.cpp` source files is recommended.


## Rebuilding

The `.so` files included in this repository correspond to the compiled versions used by the experiments. If the source code or liboqs installation changes, rebuild the shared libraries and verify their exported symbols and dependencies before running the experiments.

## Important Note

The KEM operations are used for session/key establishment. They are not applied as a per-frame replacement for the digital-signature operation used in the YOLOChain data path.
