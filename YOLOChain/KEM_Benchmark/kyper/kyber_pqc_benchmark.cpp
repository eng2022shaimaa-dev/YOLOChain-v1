#include <oqs/oqs.h>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <numeric>
#include <sstream>
#include <string>
#include <vector>

#include <time.h>


/* ============================================================
 * YOLOChain / PQC Benchmark
 *
 * Kyber512 / Kyber768 / Kyber1024
 *
 * Measures:
 *   - KeyGen
 *   - Encaps
 *   - Decaps
 *
 * Reports:
 *   Mean
 *   SD
 *   95% CI
 *   P95
 *   P99
 *   Maximum
 *
 * Also verifies:
 *   shared_secret_enc == shared_secret_dec
 *
 * Output:
 *   kyber_raw.csv
 *   kyber_summary.csv
 *
 * Usage:
 *   ./kyber_pqc_benchmark 512 1000 100
 *   ./kyber_pqc_benchmark 768 1000 100
 *   ./kyber_pqc_benchmark 1024 1000 100
 *
 * ============================================================ */


struct Statistics {
    double mean = 0.0;
    double sd = 0.0;
    double ci_low = 0.0;
    double ci_high = 0.0;
    double p95 = 0.0;
    double p99 = 0.0;
    double maximum = 0.0;
};


static double now_ms() {
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);

    return static_cast<double>(ts.tv_sec) * 1000.0 +
           static_cast<double>(ts.tv_nsec) / 1000000.0;
}


static Statistics calculate_statistics(
    const std::vector<double>& values
) {
    Statistics s;

    if (values.empty()) {
        return s;
    }

    const size_t n = values.size();

    s.mean =
        std::accumulate(values.begin(), values.end(), 0.0)
        / static_cast<double>(n);

    if (n > 1) {
        double sum_sq = 0.0;

        for (double x : values) {
            const double d = x - s.mean;
            sum_sq += d * d;
        }

        s.sd = std::sqrt(
            sum_sq / static_cast<double>(n - 1)
        );
    }

    const double se =
        s.sd / std::sqrt(static_cast<double>(n));

    const double margin = 1.96 * se;

    s.ci_low = s.mean - margin;
    s.ci_high = s.mean + margin;

    std::vector<double> sorted = values;

    std::sort(sorted.begin(), sorted.end());

    auto percentile = [&](double p) -> double {

        if (sorted.size() == 1) {
            return sorted[0];
        }

        const double pos =
            p * static_cast<double>(sorted.size() - 1);

        const size_t lower =
            static_cast<size_t>(std::floor(pos));

        const size_t upper =
            static_cast<size_t>(std::ceil(pos));

        if (lower == upper) {
            return sorted[lower];
        }

        const double fraction =
            pos - static_cast<double>(lower);

        return sorted[lower] +
               fraction *
               (sorted[upper] - sorted[lower]);
    };

    s.p95 = percentile(0.95);
    s.p99 = percentile(0.99);

    s.maximum =
        *std::max_element(sorted.begin(), sorted.end());

    return s;
}


static void print_statistics(
    const std::string& name,
    const Statistics& s
) {
    std::cout
        << std::fixed
        << std::setprecision(6);

    std::cout << "  "
              << std::left
              << std::setw(12)
              << name
              << " Mean=" << std::setw(12) << s.mean
              << " SD=" << std::setw(12) << s.sd
              << " CI95=[" << s.ci_low
              << ", " << s.ci_high << "]"
              << " P95=" << std::setw(12) << s.p95
              << " P99=" << std::setw(12) << s.p99
              << " Max=" << s.maximum
              << " ms\n";
}


struct KyberConfig {
    std::string name;
    const char* algorithm;

    size_t public_key_size;
    size_t secret_key_size;
    size_t ciphertext_size;
    size_t shared_secret_size;
};


static bool get_config(
    const std::string& level,
    KyberConfig& config
) {
    if (level == "512") {

        config.name = "Kyber512";
        config.algorithm = OQS_KEM_alg_kyber_512;

        config.public_key_size =
            OQS_KEM_kyber_512_length_public_key;

        config.secret_key_size =
            OQS_KEM_kyber_512_length_secret_key;

        config.ciphertext_size =
            OQS_KEM_kyber_512_length_ciphertext;

        config.shared_secret_size =
            OQS_KEM_kyber_512_length_shared_secret;

        return true;
    }

    if (level == "768") {

        config.name = "Kyber768";
        config.algorithm = OQS_KEM_alg_kyber_768;

        config.public_key_size =
            OQS_KEM_kyber_768_length_public_key;

        config.secret_key_size =
            OQS_KEM_kyber_768_length_secret_key;

        config.ciphertext_size =
            OQS_KEM_kyber_768_length_ciphertext;

        config.shared_secret_size =
            OQS_KEM_kyber_768_length_shared_secret;

        return true;
    }

    if (level == "1024") {

        config.name = "Kyber1024";
        config.algorithm = OQS_KEM_alg_kyber_1024;

        config.public_key_size =
            OQS_KEM_kyber_1024_length_public_key;

        config.secret_key_size =
            OQS_KEM_kyber_1024_length_secret_key;

        config.ciphertext_size =
            OQS_KEM_kyber_1024_length_ciphertext;

        config.shared_secret_size =
            OQS_KEM_kyber_1024_length_shared_secret;

        return true;
    }

    return false;
}


int main(int argc, char* argv[]) {

    if (argc < 2 || argc > 4) {

        std::cerr
            << "Usage:\n"
            << "  " << argv[0]
            << " <512|768|1024> [iterations] [warmup]\n\n"
            << "Examples:\n"
            << "  " << argv[0] << " 512 1000 100\n"
            << "  " << argv[0] << " 768 1000 100\n"
            << "  " << argv[0] << " 1024 1000 100\n";

        return EXIT_FAILURE;
    }


    const std::string level = argv[1];

    const int iterations =
        (argc >= 3)
        ? std::atoi(argv[2])
        : 1000;

    const int warmup =
        (argc >= 4)
        ? std::atoi(argv[3])
        : 100;


    if (iterations <= 0 || warmup < 0) {

        std::cerr
            << "ERROR: iterations must be > 0 "
            << "and warmup must be >= 0.\n";

        return EXIT_FAILURE;
    }


    KyberConfig config;

    if (!get_config(level, config)) {

        std::cerr
            << "ERROR: unsupported Kyber level: "
            << level << "\n";

        return EXIT_FAILURE;
    }


    std::cout
        << "\n"
        << "============================================================\n"
        << "PQC KEM BENCHMARK\n"
        << "============================================================\n"
        << "Algorithm      : " << config.name << "\n"
        << "Iterations     : " << iterations << "\n"
        << "Warm-up        : " << warmup << "\n"
        << "liboqs API     : " << config.algorithm << "\n"
        << "============================================================\n\n";


    OQS_KEM* kem =
        OQS_KEM_new(config.algorithm);


    if (kem == nullptr) {

        std::cerr
            << "ERROR: OQS_KEM_new() failed for "
            << config.name << "\n";

        return EXIT_FAILURE;
    }


    std::cout
        << "Parameter sizes:\n"
        << "  Public key     : "
        << kem->length_public_key << " bytes\n"
        << "  Secret key     : "
        << kem->length_secret_key << " bytes\n"
        << "  Ciphertext     : "
        << kem->length_ciphertext << " bytes\n"
        << "  Shared secret  : "
        << kem->length_shared_secret << " bytes\n\n";


    /*
     * Allocate buffers once.
     */

    std::vector<uint8_t> public_key(
        kem->length_public_key
    );

    std::vector<uint8_t> secret_key(
        kem->length_secret_key
    );

    std::vector<uint8_t> ciphertext(
        kem->length_ciphertext
    );

    std::vector<uint8_t> shared_secret_enc(
        kem->length_shared_secret
    );

    std::vector<uint8_t> shared_secret_dec(
        kem->length_shared_secret
    );


    /*
     * Warm-up
     */

    std::cout
        << "Running warm-up iterations...\n";


    for (int i = 0; i < warmup; ++i) {

        if (OQS_KEM_keypair(
                kem,
                public_key.data(),
                secret_key.data()
            ) != OQS_SUCCESS) {

            std::cerr
                << "ERROR: warm-up KeyGen failed.\n";

            OQS_KEM_free(kem);

            return EXIT_FAILURE;
        }


        if (OQS_KEM_encaps(
                kem,
                ciphertext.data(),
                shared_secret_enc.data(),
                public_key.data()
            ) != OQS_SUCCESS) {

            std::cerr
                << "ERROR: warm-up Encaps failed.\n";

            OQS_KEM_free(kem);

            return EXIT_FAILURE;
        }


        if (OQS_KEM_decaps(
                kem,
                shared_secret_dec.data(),
                ciphertext.data(),
                secret_key.data()
            ) != OQS_SUCCESS) {

            std::cerr
                << "ERROR: warm-up Decaps failed.\n";

            OQS_KEM_free(kem);

            return EXIT_FAILURE;
        }
    }


    /*
     * Measured samples
     */

    std::vector<double> keygen_times;
    std::vector<double> encaps_times;
    std::vector<double> decaps_times;

    std::vector<int> correctness_per_iteration;

    keygen_times.reserve(iterations);
    encaps_times.reserve(iterations);
    decaps_times.reserve(iterations);
    correctness_per_iteration.reserve(iterations);


    std::cout
        << "Running measured iterations...\n";


    for (int i = 0; i < iterations; ++i) {

        /*
         * --------------------------------------------------------
         * KeyGen
         * --------------------------------------------------------
         */

        double start = now_ms();

        OQS_STATUS status =
            OQS_KEM_keypair(
                kem,
                public_key.data(),
                secret_key.data()
            );

        double end = now_ms();

        if (status != OQS_SUCCESS) {

            std::cerr
                << "ERROR: KeyGen failed at iteration "
                << (i + 1) << ".\n";

            OQS_KEM_free(kem);

            return EXIT_FAILURE;
        }

        keygen_times.push_back(end - start);


        /*
         * --------------------------------------------------------
         * Encaps
         * --------------------------------------------------------
         */

        start = now_ms();

        status =
            OQS_KEM_encaps(
                kem,
                ciphertext.data(),
                shared_secret_enc.data(),
                public_key.data()
            );

        end = now_ms();

        if (status != OQS_SUCCESS) {

            std::cerr
                << "ERROR: Encaps failed at iteration "
                << (i + 1) << ".\n";

            OQS_KEM_free(kem);

            return EXIT_FAILURE;
        }

        encaps_times.push_back(end - start);


        /*
         * --------------------------------------------------------
         * Decaps
         * --------------------------------------------------------
         */

        start = now_ms();

        status =
            OQS_KEM_decaps(
                kem,
                shared_secret_dec.data(),
                ciphertext.data(),
                secret_key.data()
            );

        end = now_ms();

        if (status != OQS_SUCCESS) {

            std::cerr
                << "ERROR: Decaps failed at iteration "
                << (i + 1) << ".\n";

            OQS_KEM_free(kem);

            return EXIT_FAILURE;
        }

        decaps_times.push_back(end - start);


        /*
         * --------------------------------------------------------
         * Correctness
         * --------------------------------------------------------
         */

        const bool match =
            std::memcmp(
                shared_secret_enc.data(),
                shared_secret_dec.data(),
                kem->length_shared_secret
            ) == 0;

        correctness_per_iteration.push_back(
            match ? 1 : 0
        );


        if (!match) {

            std::cerr
                << "ERROR: Shared-secret mismatch at "
                << "iteration " << (i + 1) << ".\n";

            OQS_KEM_free(kem);

            return EXIT_FAILURE;
        }
    }


    /*
     * Statistics
     */

    const Statistics keygen_stats =
        calculate_statistics(keygen_times);

    const Statistics encaps_stats =
        calculate_statistics(encaps_times);

    const Statistics decaps_stats =
        calculate_statistics(decaps_times);


    const int correct =
        std::accumulate(
            correctness_per_iteration.begin(),
            correctness_per_iteration.end(),
            0
        );

    const double correctness_rate =
        100.0 *
        static_cast<double>(correct) /
        static_cast<double>(iterations);


    /*
     * Console output
     */

    std::cout
        << "\n"
        << "============================================================\n"
        << "RESULTS — " << config.name << "\n"
        << "============================================================\n";

    print_statistics(
        "KeyGen",
        keygen_stats
    );

    print_statistics(
        "Encaps",
        encaps_stats
    );

    print_statistics(
        "Decaps",
        decaps_stats
    );


    std::cout
        << "\n"
        << "Correctness     : "
        << std::fixed
        << std::setprecision(2)
        << correctness_rate
        << "%\n";

    std::cout
        << "============================================================\n";


    /*
     * ------------------------------------------------------------
     * Raw CSV
     * ------------------------------------------------------------
     */

    std::ofstream raw_csv(
        "kyber_raw.csv"
    );


    if (!raw_csv.is_open()) {

        std::cerr
            << "ERROR: Cannot open kyber_raw.csv\n";

        OQS_KEM_free(kem);

        return EXIT_FAILURE;
    }


    raw_csv
        << "algorithm,"
        << "iteration,"
        << "keygen_ms,"
        << "encaps_ms,"
        << "decaps_ms,"
        << "correctness\n";


    raw_csv
        << std::fixed
        << std::setprecision(9);


    for (int i = 0; i < iterations; ++i) {

        raw_csv
            << config.name << ","
            << (i + 1) << ","
            << keygen_times[i] << ","
            << encaps_times[i] << ","
            << decaps_times[i] << ","
            << (
                correctness_per_iteration[i]
                ? "PASS"
                : "FAIL"
            )
            << "\n";
    }


    raw_csv.close();


    /*
     * ------------------------------------------------------------
     * Summary CSV
     * ------------------------------------------------------------
     */

    std::ofstream summary_csv(
        "kyber_summary.csv"
    );


    if (!summary_csv.is_open()) {

        std::cerr
            << "ERROR: Cannot open kyber_summary.csv\n";

        OQS_KEM_free(kem);

        return EXIT_FAILURE;
    }


    summary_csv
        << "algorithm,"
        << "iterations,"
        << "warmup,"
        << "public_key_bytes,"
        << "secret_key_bytes,"
        << "ciphertext_bytes,"
        << "shared_secret_bytes,"
        << "operation,"
        << "mean_ms,"
        << "sd_ms,"
        << "ci95_low_ms,"
        << "ci95_high_ms,"
        << "p95_ms,"
        << "p99_ms,"
        << "max_ms,"
        << "correctness_rate_percent\n";


    summary_csv
        << std::fixed
        << std::setprecision(9);


    auto write_summary =
        [&](const std::string& operation,
            const Statistics& stats) {

            summary_csv
                << config.name << ","
                << iterations << ","
                << warmup << ","
                << kem->length_public_key << ","
                << kem->length_secret_key << ","
                << kem->length_ciphertext << ","
                << kem->length_shared_secret << ","
                << operation << ","
                << stats.mean << ","
                << stats.sd << ","
                << stats.ci_low << ","
                << stats.ci_high << ","
                << stats.p95 << ","
                << stats.p99 << ","
                << stats.maximum << ","
                << correctness_rate
                << "\n";
        };


    write_summary(
        "KeyGen",
        keygen_stats
    );

    write_summary(
        "Encaps",
        encaps_stats
    );

    write_summary(
        "Decaps",
        decaps_stats
    );


    summary_csv.close();


    /*
     * Cleanup
     */

    OQS_KEM_free(kem);


    std::cout
        << "\nOutput files:\n"
        << "  kyber_raw.csv\n"
        << "  kyber_summary.csv\n\n";


    return EXIT_SUCCESS;
}
