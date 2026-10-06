# NTRU Benchmark — Steps to Run

## 1. Compile


g++ -O2 -std=c++17 ntru_pqc_benchmark.cpp \
    -I/usr/local/include \
    -L/usr/local/lib \
    -loqs \
    -Wl,-rpath,/usr/local/lib \
    -o ntru_pqc_benchmark


## 2. Run NTRU parameter sets

Run the benchmark with 1000 measured iterations and 100 warm-up iterations:


./ntru_pqc_benchmark L1 1000 100



./ntru_pqc_benchmark L3 1000 100


./ntru_pqc_benchmark L5 1000 100


The generated CSV files are produced locally by the benchmark program and are not included in the repository.

