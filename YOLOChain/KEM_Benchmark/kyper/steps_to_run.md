# Kyber Benchmark — Steps to Run

## 1. Compile

From the `kyber` directory:

g++ -O2 -std=c++17 kyber_pqc_benchmark.cpp \
    -I/usr/local/include \
    -L/usr/local/lib \
    -loqs \
    -Wl,-rpath,/usr/local/lib \
    -o kyber_pqc_benchmark


## 2. Run Kyber-512


./kyber_pqc_benchmark 512 1000 100


Rename the generated output files:


mv kyber_raw.csv kyber512_raw.csv
mv kyber_summary.csv kyber512_summary.csv


## 3. Run Kyber-768


./kyber_pqc_benchmark 768 1000 100


Rename the generated output files:


mv kyber_raw.csv kyber768_raw.csv
mv kyber_summary.csv kyber768_summary.csv


## 4. Run Kyber-1024


./kyber_pqc_benchmark 1024 1000 100


Rename the generated output files:


mv kyber_raw.csv kyber1024_raw.csv
mv kyber_summary.csv kyber1024_summary.csv


The benchmark uses 100 warm-up iterations followed by 1000 measured iterations.
