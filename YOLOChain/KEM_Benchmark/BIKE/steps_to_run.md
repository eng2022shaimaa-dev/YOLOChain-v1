# BIKE Benchmark — Steps to Run

## 1. Compile


g++ -O2 -std=c++17 bike_pqc_benchmark.cpp \
    -I/usr/local/include \
    -L/usr/local/lib \
    -loqs \
    -Wl,-rpath,/usr/local/lib \
    -o bike_pqc_benchmark


## 2. Run BIKE-L1


./bike_pqc_benchmark L1 1000 100


The benchmark generates:


bike_l1_raw.csv
bike_l1_summary.csv


## 3. Run BIKE-L3


./bike_pqc_benchmark L3 1000 100


The benchmark generates:


bike_l3_raw.csv
bike_l3_summary.csv


## 4. Run BIKE-L5


./bike_pqc_benchmark L5 1000 100


The benchmark generates:


bike_l5_raw.csv
bike_l5_summary.csv


The benchmark uses 100 warm-up iterations followed by 1000 measured iterations.
