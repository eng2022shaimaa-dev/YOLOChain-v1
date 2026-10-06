#include <oqs/oqs.h>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <numeric>
#include <string>
#include <vector>
#include <time.h>

static long long time_diff_ns(const timespec& start,
                              const timespec& end) {
    return (end.tv_sec - start.tv_sec) * 1000000000LL +
           (end.tv_nsec - start.tv_nsec);
}

static double percentile(std::vector<double> values,
                         double p) {
    if (values.empty()) {
        return 0.0;
    }

    std::sort(values.begin(), values.end());

    double pos = (p / 100.0) * (values.size() - 1);
    size_t lower = static_cast<size_t>(std::floor(pos));
    size_t upper = static_cast<size_t>(std::ceil(pos));

    if (lower == upper) {
        return values[lower];
    }

    double fraction = pos - lower;

    return values[lower] +
           fraction * (values[upper] - values[lower]);
}

struct Statistics {
    double mean;
    double sd;
    double ci_low;
    double ci_high;
    double p95;
    double p99;
    double maximum;
};

static Statistics calculate_statistics(
    const std::vector<double>& values) {

    Statistics s{};

    if (values.empty()) {
        return s;
    }

    const size_t n = values.size();

    double sum =
        std::accumulate(values.begin(),
                        values.end(),
                        0.0);

    s.mean = sum / static_cast<double>(n);

    if (n > 1) {
        double sq_sum = 0.0;

        for (double x : values) {
            double d = x - s.mean;
            sq_sum += d * d;
        }

        s.sd = std::sqrt(
            sq_sum / static_cast<double>(n - 1));
    } else {
        s.sd = 0.0;
    }

    const double se =
        s.sd / std::sqrt(static_cast<double>(n));

    const double margin =
        1.96 * se;

    s.ci_low = s.mean - margin;
    s.ci_high = s.mean + margin;

    s.p95 = percentile(values, 95.0);
    s.p99 = percentile(values, 99.0);

    s.maximum =
        *std::max_element(values.begin(),
                          values.end());

    return s;
}

static const char* get_algorithm(
    const std::string& level) {

    if (level == "L1" ||
        level == "l1" ||
        level == "ntru_l1") {

        return OQS_KEM_alg_ntru_hps2048509;
    }

    if (level == "L3" ||
        level == "l3" ||
        level == "ntru_l3") {

        return OQS_KEM_alg_ntru_hps2048677;
    }

    if (level == "L5" ||
        level == "l5" ||
        level == "ntru_l5") {

        return OQS_KEM_alg_ntru_hps4096821;
    }

    return nullptr;
}

static std::string get_display_name(
    const std::string& level) {

    if (level == "L1" ||
        level == "l1" ||
        level == "ntru_l1") {

        return "NTRU-HPS2048509";
    }

    if (level == "L3" ||
        level == "l3" ||
        level == "ntru_l3") {

        return "NTRU-HPS2048677";
    }

    if (level == "L5" ||
        level == "l5" ||
        level == "ntru_l5") {

        return "NTRU-HPS4096821";
    }

    return "UNKNOWN";
}

static bool check_shared_secret(
    const uint8_t* a,
    const uint8_t* b,
    size_t length) {

    for (size_t i = 0; i < length; ++i) {
        if (a[i] != b[i]) {
            return false;
        }
    }

    return true;
}

static void write_csv_row(
    std::ofstream& file,
    const std::string& algorithm,
    int iterations,
    int warmup,
    size_t public_key_bytes,
    size_t secret_key_bytes,
    size_t ciphertext_bytes,
    size_t shared_secret_bytes,
    const std::string& operation,
    const Statistics& s,
    double correctness_rate) {

    file << algorithm << ","
         << iterations << ","
         << warmup << ","
         << public_key_bytes << ","
         << secret_key_bytes << ","
         << ciphertext_bytes << ","
         << shared_secret_bytes << ","
         << operation << ","
         << std::fixed
         << std::setprecision(9)
         << s.mean << ","
         << s.sd << ","
         << s.ci_low << ","
         << s.ci_high << ","
         << s.p95 << ","
         << s.p99 << ","
         << s.maximum << ","
         << correctness_rate
         << "\n";
}

int main(int argc, char* argv[]) {

    if (argc < 2 || argc > 4) {

        std::cerr
            << "Usage:\n"
            << "  " << argv[0]
            << " L1 [iterations] [warmup]\n"
            << "  " << argv[0]
            << " L3 [iterations] [warmup]\n"
            << "  " << argv[0]
            << " L5 [iterations] [warmup]\n";

        return EXIT_FAILURE;
    }

    std::string level = argv[1];

    int iterations = 1000;
    int warmup = 100;

    if (argc >= 3) {
        iterations = std::atoi(argv[2]);
    }

    if (argc >= 4) {
        warmup = std::atoi(argv[3]);
    }

    if (iterations <= 0 || warmup < 0) {

        std::cerr
            << "Invalid iterations/warmup values."
            << std::endl;

        return EXIT_FAILURE;
    }

    const char* alg_name =
        get_algorithm(level);

    if (alg_name == nullptr) {

        std::cerr
            << "Unknown NTRU level: "
            << level
            << std::endl;

        return EXIT_FAILURE;
    }

    const std::string display_name =
        get_display_name(level);

    std::cout
        << "\n==================================================\n"
        << "NTRU PQC Benchmark\n"
        << "==================================================\n"
        << "Algorithm : "
        << display_name
        << "\n"
        << "Iterations: "
        << iterations
        << "\n"
        << "Warm-up   : "
        << warmup
        << "\n"
        << "==================================================\n"
        << std::endl;

    if (!OQS_KEM_alg_is_enabled(alg_name)) {

        std::cerr
            << display_name
            << " is not enabled in this liboqs build."
            << std::endl;

        return EXIT_FAILURE;
    }

    OQS_KEM* kem =
        OQS_KEM_new(alg_name);

    if (kem == nullptr) {

        std::cerr
            << "Failed to create NTRU KEM object."
            << std::endl;

        return EXIT_FAILURE;
    }

    const size_t pk_len =
        kem->length_public_key;

    const size_t sk_len =
        kem->length_secret_key;

    const size_t ct_len =
        kem->length_ciphertext;

    const size_t ss_len =
        kem->length_shared_secret;

    std::vector<uint8_t> public_key(pk_len);
    std::vector<uint8_t> secret_key(sk_len);
    std::vector<uint8_t> ciphertext(ct_len);
    std::vector<uint8_t> shared_secret_enc(ss_len);
    std::vector<uint8_t> shared_secret_dec(ss_len);

    std::vector<double> keygen_times;
    std::vector<double> encaps_times;
    std::vector<double> decaps_times;

    std::vector<int> correctness;

    keygen_times.reserve(iterations);
    encaps_times.reserve(iterations);
    decaps_times.reserve(iterations);
    correctness.reserve(iterations);

    timespec start{};
    timespec end{};

    // =====================================================
    // WARM-UP
    // =====================================================

    std::cout
        << "Running warm-up..."
        << std::endl;

    for (int i = 0; i < warmup; ++i) {

        if (OQS_KEM_keypair(
                kem,
                public_key.data(),
                secret_key.data()) != OQS_SUCCESS) {

            std::cerr
                << "Warm-up KeyGen failed."
                << std::endl;

            OQS_KEM_free(kem);
            return EXIT_FAILURE;
        }

        if (OQS_KEM_encaps(
                kem,
                ciphertext.data(),
                shared_secret_enc.data(),
                public_key.data()) != OQS_SUCCESS) {

            std::cerr
                << "Warm-up Encaps failed."
                << std::endl;

            OQS_KEM_free(kem);
            return EXIT_FAILURE;
        }

        if (OQS_KEM_decaps(
                kem,
                shared_secret_dec.data(),
                ciphertext.data(),
                secret_key.data()) != OQS_SUCCESS) {

            std::cerr
                << "Warm-up Decaps failed."
                << std::endl;

            OQS_KEM_free(kem);
            return EXIT_FAILURE;
        }
    }

    // =====================================================
    // MEASURED ITERATIONS
    // =====================================================

    std::cout
        << "Running measured iterations..."
        << std::endl;

    for (int i = 0; i < iterations; ++i) {

        // -------------------------------------------------
        // KeyGen
        // -------------------------------------------------

        clock_gettime(
            CLOCK_MONOTONIC,
            &start);

        if (OQS_KEM_keypair(
                kem,
                public_key.data(),
                secret_key.data()) != OQS_SUCCESS) {

            std::cerr
                << "KeyGen failed at iteration "
                << i
                << std::endl;

            OQS_KEM_free(kem);
            return EXIT_FAILURE;
        }

        clock_gettime(
            CLOCK_MONOTONIC,
            &end);

        keygen_times.push_back(
            time_diff_ns(start, end) / 1e6);

        // -------------------------------------------------
        // Encapsulation
        // -------------------------------------------------

        clock_gettime(
            CLOCK_MONOTONIC,
            &start);

        if (OQS_KEM_encaps(
                kem,
                ciphertext.data(),
                shared_secret_enc.data(),
                public_key.data()) != OQS_SUCCESS) {

            std::cerr
                << "Encapsulation failed at iteration "
                << i
                << std::endl;

            OQS_KEM_free(kem);
            return EXIT_FAILURE;
        }

        clock_gettime(
            CLOCK_MONOTONIC,
            &end);

        encaps_times.push_back(
            time_diff_ns(start, end) / 1e6);

        // -------------------------------------------------
        // Decapsulation
        // -------------------------------------------------

        clock_gettime(
            CLOCK_MONOTONIC,
            &start);

        if (OQS_KEM_decaps(
                kem,
                shared_secret_dec.data(),
                ciphertext.data(),
                secret_key.data()) != OQS_SUCCESS) {

            std::cerr
                << "Decapsulation failed at iteration "
                << i
                << std::endl;

            OQS_KEM_free(kem);
            return EXIT_FAILURE;
        }

        clock_gettime(
            CLOCK_MONOTONIC,
            &end);

        decaps_times.push_back(
            time_diff_ns(start, end) / 1e6);

        // -------------------------------------------------
        // Correctness — every measured iteration
        // -------------------------------------------------

        bool match =
            check_shared_secret(
                shared_secret_enc.data(),
                shared_secret_dec.data(),
                ss_len);

        correctness.push_back(
            match ? 1 : 0);
    }

    // =====================================================
    // STATISTICS
    // =====================================================

    Statistics keygen_stats =
        calculate_statistics(keygen_times);

    Statistics encaps_stats =
        calculate_statistics(encaps_times);

    Statistics decaps_stats =
        calculate_statistics(decaps_times);

    int correct_count =
        std::accumulate(
            correctness.begin(),
            correctness.end(),
            0);

    double correctness_rate =
        100.0 *
        static_cast<double>(correct_count) /
        static_cast<double>(iterations);

    // =====================================================
    // CSV OUTPUT
    // =====================================================

    std::string prefix;

    if (level == "L1" ||
        level == "l1" ||
        level == "ntru_l1") {

        prefix = "ntru_l1";
    } else if (
        level == "L3" ||
        level == "l3" ||
        level == "ntru_l3") {

        prefix = "ntru_l3";
    } else {

        prefix = "ntru_l5";
    }

    std::string raw_filename =
        prefix + "_raw.csv";

    std::string summary_filename =
        prefix + "_summary.csv";

    std::ofstream raw_file(
        raw_filename);

    std::ofstream summary_file(
        summary_filename);

    if (!raw_file || !summary_file) {

        std::cerr
            << "Failed to create CSV files."
            << std::endl;

        OQS_KEM_free(kem);
        return EXIT_FAILURE;
    }

    // -----------------------------------------------------
    // RAW CSV
    // -----------------------------------------------------

    raw_file
        << "algorithm,iteration,"
        << "keygen_ms,encaps_ms,decaps_ms,"
        << "correctness\n";

    for (int i = 0; i < iterations; ++i) {

        raw_file
            << display_name << ","
            << i + 1 << ","
            << std::fixed
            << std::setprecision(9)
            << keygen_times[i] << ","
            << encaps_times[i] << ","
            << decaps_times[i] << ","
            << correctness[i]
            << "\n";
    }

    // -----------------------------------------------------
    // SUMMARY CSV
    // -----------------------------------------------------

    summary_file
        << "algorithm,iterations,warmup,"
        << "public_key_bytes,secret_key_bytes,"
        << "ciphertext_bytes,shared_secret_bytes,"
        << "operation,mean_ms,sd_ms,"
        << "ci95_low_ms,ci95_high_ms,"
        << "p95_ms,p99_ms,max_ms,"
        << "correctness_rate_percent\n";

    write_csv_row(
        summary_file,
        display_name,
        iterations,
        warmup,
        pk_len,
        sk_len,
        ct_len,
        ss_len,
        "KeyGen",
        keygen_stats,
        correctness_rate);

    write_csv_row(
        summary_file,
        display_name,
        iterations,
        warmup,
        pk_len,
        sk_len,
        ct_len,
        ss_len,
        "Encaps",
        encaps_stats,
        correctness_rate);

    write_csv_row(
        summary_file,
        display_name,
        iterations,
        warmup,
        pk_len,
        sk_len,
        ct_len,
        ss_len,
        "Decaps",
        decaps_stats,
        correctness_rate);

    raw_file.close();
    summary_file.close();

    // =====================================================
    // TERMINAL OUTPUT
    // =====================================================

    std::cout
        << "\n==================================================\n"
        << "NTRU Results\n"
        << "==================================================\n";

    std::cout
        << "Algorithm           : "
        << display_name
        << "\n";

    std::cout
        << "Iterations          : "
        << iterations
        << "\n";

    std::cout
        << "Warm-up             : "
        << warmup
        << "\n";

    std::cout
        << "Public key          : "
        << pk_len
        << " bytes\n";

    std::cout
        << "Secret key          : "
        << sk_len
        << " bytes\n";

    std::cout
        << "Ciphertext          : "
        << ct_len
        << " bytes\n";

    std::cout
        << "Shared secret       : "
        << ss_len
        << " bytes\n";

    std::cout
        << "--------------------------------------------------\n";

    std::cout
        << std::fixed
        << std::setprecision(9);

    std::cout
        << "KeyGen\n"
        << "  Mean              : "
        << keygen_stats.mean
        << " ms\n"
        << "  SD                : "
        << keygen_stats.sd
        << " ms\n"
        << "  95% CI            : ["
        << keygen_stats.ci_low
        << ", "
        << keygen_stats.ci_high
        << "] ms\n"
        << "  P95               : "
        << keygen_stats.p95
        << " ms\n"
        << "  P99               : "
        << keygen_stats.p99
        << " ms\n"
        << "  Max               : "
        << keygen_stats.maximum
        << " ms\n\n";

    std::cout
        << "Encaps\n"
        << "  Mean              : "
        << encaps_stats.mean
        << " ms\n"
        << "  SD                : "
        << encaps_stats.sd
        << " ms\n"
        << "  95% CI            : ["
        << encaps_stats.ci_low
        << ", "
        << encaps_stats.ci_high
        << "] ms\n"
        << "  P95               : "
        << encaps_stats.p95
        << " ms\n"
        << "  P99               : "
        << encaps_stats.p99
        << " ms\n"
        << "  Max               : "
        << encaps_stats.maximum
        << " ms\n\n";

    std::cout
        << "Decaps\n"
        << "  Mean              : "
        << decaps_stats.mean
        << " ms\n"
        << "  SD                : "
        << decaps_stats.sd
        << " ms\n"
        << "  95% CI            : ["
        << decaps_stats.ci_low
        << ", "
        << decaps_stats.ci_high
        << "] ms\n"
        << "  P95               : "
        << decaps_stats.p95
        << " ms\n"
        << "  P99               : "
        << decaps_stats.p99
        << " ms\n"
        << "  Max               : "
        << decaps_stats.maximum
        << " ms\n\n";

    std::cout
        << "Correctness         : "
        << correct_count
        << "/"
        << iterations
        << " ("
        << correctness_rate
        << "%)\n";

    std::cout
        << "--------------------------------------------------\n";

    double total_mean =
        keygen_stats.mean +
        encaps_stats.mean +
        decaps_stats.mean;

    std::cout
        << "Sum of mean KEM operations: "
        << total_mean
        << " ms\n";

    std::cout
        << "--------------------------------------------------\n";

    std::cout
        << "Raw CSV             : "
        << raw_filename
        << "\n";

    std::cout
        << "Summary CSV         : "
        << summary_filename
        << "\n";

    std::cout
        << "==================================================\n"
        << std::endl;

    OQS_KEM_free(kem);

    return EXIT_SUCCESS;
}
