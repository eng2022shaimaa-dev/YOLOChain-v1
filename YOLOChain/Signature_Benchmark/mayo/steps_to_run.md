# MAYO Benchmark — Steps to Run

## 1. Compile


g++ -O2 -std=c++17 mayo_pqc_benchmark.cpp \
    -I/usr/local/include \
    -L/usr/local/lib \
    -loqs \
    -Wl,-rpath,/usr/local/lib \
    -o mayo_pqc_benchmark


## 2. Run


./mayo_pqc_benchmark


## 3. Inspect the generated summaries


cat mayo1_summary.csv



cat mayo3_summary.csv



cat mayo5_summary.csv


The benchmark generates the corresponding CSV output files locally.



