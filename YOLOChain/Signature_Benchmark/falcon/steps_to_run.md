# Falcon Benchmark — Steps to Run

## 1. Compile


g++ -O2 -std=c++17 falcon_pqc_benchmark.cpp \
    -I/usr/local/include \
    -L/usr/local/lib \
    -loqs \
    -Wl,-rpath,/usr/local/lib \
    -o falcon_pqc_benchmark


## 2. Run


./falcon_pqc_benchmark


## 3. Inspect the generated summaries


cat falcon512_summary.csv



cat falcon1024_summary.csv


The benchmark generates the corresponding CSV output files locally.
