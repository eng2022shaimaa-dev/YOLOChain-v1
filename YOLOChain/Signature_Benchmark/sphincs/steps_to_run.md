# SPHINCS+ Benchmark — Steps to Run

## 1. Compile


g++ -O2 -std=c++17 sphincs_pqc_benchmark.cpp \
    -I/usr/local/include \
    -L/usr/local/lib \
    -loqs \
    -Wl,-rpath,/usr/local/lib \
    -o sphincs_pqc_benchmark


## 2. Run


./sphincs_pqc_benchmark


## 3. Inspect the generated summaries


cat sphincs128s_summary.csv



cat sphincs192s_summary.csv



cat sphincs256s_summary.csv


The benchmark generates the corresponding CSV output files locally.
