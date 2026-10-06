#include <oqs/oqs.h>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <numeric>
#include <sstream>
#include <string>
#include <vector>

#include <time.h>

struct Statistics {
    double mean_ms = 0.0;
    double sd_ms = 0.0;
    double ci95_low_ms = 0.0;
    double ci95_high_ms = 0.0;
    double p95_ms = 0.0;
    double p99_ms = 0.0;
    double max_ms = 0.0;
};

static long long time_diff_ns(
    const timespec& start,
    const timespec& end)
{
    return
        (end.tv_sec - start.tv_sec) * 1000000000LL +
        (end.tv_nsec - start.tv_nsec);
}

static double percentile(
    std::vector<double> values,
    double p)
{
    if (values.empty())
        return 0.0;

    std::sort(values.begin(), values.end());

    double pos =
        (p / 100.0) * (values.size() - 1);

    size_t lower =
        static_cast<size_t>(std::floor(pos));

    size_t upper =
        static_cast<size_t>(std::ceil(pos));

    if (lower == upper)
        return values[lower];

    double fraction = pos - lower;

    return values[lower] +
           fraction * (values[upper] - values[lower]);
}

static Statistics calculate_statistics(
    const std::vector<double>& values)
{
    Statistics s;

    if (values.empty())
        return s;

    const size_t n = values.size();

    s.mean_ms =
        std::accumulate(
            values.begin(),
            values.end(),
            0.0) / static_cast<double>(n);

    if (n > 1) {

        double sum_sq = 0.0;

        for (double x : values) {

            double d = x - s.mean_ms;

            sum_sq += d * d;
        }

        s.sd_ms =
            std::sqrt(
                sum_sq /
                static_cast<double>(n - 1));
    }

    const double se =
        s.sd_ms / std::sqrt(static_cast<double>(n));

    const double margin =
        1.96 * se;

    s.ci95_low_ms =
        s.mean_ms - margin;

    s.ci95_high_ms =
        s.mean_ms + margin;

    s.p95_ms =
        percentile(values, 95.0);

    s.p99_ms =
        percentile(values, 99.0);

    s.max_ms =
        *std::max_element(
            values.begin(),
            values.end());

    return s;
}

static std::string algorithm_from_level(
    const std::string& level)
{
    if (level == "L1" || level == "1")
        return OQS_KEM_alg_bike_l1;

    if (level == "L3" || level == "3")
        return OQS_KEM_alg_bike_l3;

    if (level == "L5" || level == "5")
        return OQS_KEM_alg_bike_l5;

    return "";
}

int main(int argc, char* argv[])
{
    if (argc < 2 || argc > 4) {

        std::cerr
            << "Usage: "
            << argv[0]
            << " <L1|L3|L5> [iterations] [warmup]"
            << std::endl;

        return EXIT_FAILURE;
    }

    std::string level = argv[1];

    int iterations =
        (argc >= 3)
        ? std::atoi(argv[2])
        : 1000;

    int warmup =
        (argc >= 4)
        ? std::atoi(argv[3])
        : 100;

    if (iterations <= 0 || warmup < 0) {

        std::cerr
            << "Invalid iterations or warmup."
            << std::endl;

        return EXIT_FAILURE;
    }

    std::string alg_name =
        algorithm_from_level(level);

    if (alg_name.empty()) {

        std::cerr
            << "Invalid BIKE level. "
            << "Use L1, L3, or L5."
            << std::endl;

        return EXIT_FAILURE;
    }

    if (!OQS_KEM_alg_is_enabled(alg_name.c_str())) {

        std::cerr
            << alg_name
            << " is not enabled in liboqs."
            << std::endl;

        return EXIT_FAILURE;
    }

    OQS_KEM* kem =
        OQS_KEM_new(alg_name.c_str());

    if (kem == nullptr) {

        std::cerr
            << "Failed to create KEM object."
            << std::endl;

        return EXIT_FAILURE;
    }

    std::vector<uint8_t> public_key(
        kem->length_public_key);

    std::vector<uint8_t> secret_key(
        kem->length_secret_key);

    std::vector<uint8_t> ciphertext(
        kem->length_ciphertext);

    std::vector<uint8_t> shared_secret_enc(
        kem->length_shared_secret);

    std::vector<uint8_t> shared_secret_dec(
        kem->length_shared_secret);

    std::vector<double> keygen_times;
    std::vector<double> encaps_times;
    std::vector<double> decaps_times;

    keygen_times.reserve(iterations);
    encaps_times.reserve(iterations);
    decaps_times.reserve(iterations);

    timespec start{}, end{};

    size_t correctness_count = 0;
    bool failure = false;

    std::cout
        << "\n============================================================\n"
        << "PQC KEM BENCHMARK\n"
        << "============================================================\n";

    std::cout
        << "Algorithm      : "
        << alg_name
        << "\n";

    std::cout
        << "Iterations     : "
        << iterations
        << "\n";

    std::cout
        << "Warm-up        : "
        << warmup
        << "\n";

    std::cout
        << "liboqs API     : "
        << alg_name
        << "\n";

    std::cout
        << "============================================================\n\n";

    std::cout
        << "Parameter sizes:\n";

    std::cout
        << "  Public key     : "
        << kem->length_public_key
        << " bytes\n";

    std::cout
        << "  Secret key     : "
        << kem->length_secret_key
        << " bytes\n";

    std::cout
        << "  Ciphertext     : "
        << kem->length_ciphertext
        << " bytes\n";

    std::cout
        << "  Shared secret  : "
        << kem->length_shared_secret
        << " bytes\n\n";

    // =========================================================
    // Warm-up
    // =========================================================

    std::cout
        << "Running warm-up iterations..."
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

    // =========================================================
    // Measured iterations
    // =========================================================

    std::cout
        << "Running measured iterations..."
        << std::endl;

    for (int i = 0; i < iterations; ++i) {

        // -----------------------------------------------------
        // KeyGen
        // -----------------------------------------------------

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

            failure = true;
            break;
        }

        clock_gettime(
            CLOCK_MONOTONIC,
            &end);

        keygen_times.push_back(
            time_diff_ns(start, end) /
            1000000.0);

        // -----------------------------------------------------
        // Encaps
        // -----------------------------------------------------

        clock_gettime(
            CLOCK_MONOTONIC,
            &start);

        if (OQS_KEM_encaps(
                kem,
                ciphertext.data(),
                shared_secret_enc.data(),
                public_key.data()) != OQS_SUCCESS) {

            std::cerr
                << "Encaps failed at iteration "
                << i
                << std::endl;

            failure = true;
            break;
        }

        clock_gettime(
            CLOCK_MONOTONIC,
            &end);

        encaps_times.push_back(
            time_diff_ns(start, end) /
            1000000.0);

        // -----------------------------------------------------
        // Decaps
        // -----------------------------------------------------

        clock_gettime(
            CLOCK_MONOTONIC,
            &start);

        if (OQS_KEM_decaps(
                kem,
                shared_secret_dec.data(),
                ciphertext.data(),
                secret_key.data()) != OQS_SUCCESS) {

            std::cerr
                << "Decaps failed at iteration "
                << i
                << std::endl;

            failure = true;
            break;
        }

        clock_gettime(
            CLOCK_MONOTONIC,
            &end);

        decaps_times.push_back(
            time_diff_ns(start, end) /
            1000000.0);

        // -----------------------------------------------------
        // Correctness
        // -----------------------------------------------------

        bool match =
            true;

        for (size_t j = 0;
             j < kem->length_shared_secret;
             ++j) {

            if (shared_secret_enc[j] !=
                shared_secret_dec[j]) {

                match = false;
                break;
            }
        }

        if (match)
            ++correctness_count;
    }

    if (failure) {

        OQS_KEM_free(kem);

        return EXIT_FAILURE;
    }

    if (
        keygen_times.size() !=
        static_cast<size_t>(iterations) ||
        encaps_times.size() !=
        static_cast<size_t>(iterations) ||
        decaps_times.size() !=
        static_cast<size_t>(iterations)
    ) {

        std::cerr
            << "Unexpected number of measurements."
            << std::endl;

        OQS_KEM_free(kem);

        return EXIT_FAILURE;
    }

    Statistics keygen_stats =
        calculate_statistics(keygen_times);

    Statistics encaps_stats =
        calculate_statistics(encaps_times);

    Statistics decaps_stats =
        calculate_statistics(decaps_times);

    double correctness_rate =
        100.0 *
        static_cast<double>(correctness_count) /
        static_cast<double>(iterations);

    std::cout
        << "\n============================================================\n"
        << "RESULTS — "
        << alg_name
        << "\n"
        << "============================================================\n";

    std::cout
        << std::fixed
        << std::setprecision(6);

    std::cout
        << "  KeyGen       "
        << "Mean=" << keygen_stats.mean_ms
        << "     SD=" << keygen_stats.sd_ms
        << "     CI95=["
        << keygen_stats.ci95_low_ms
        << ", "
        << keygen_stats.ci95_high_ms
        << "] "
        << "P95=" << keygen_stats.p95_ms
        << "     P99=" << keygen_stats.p99_ms
        << "     Max=" << keygen_stats.max_ms
        << " ms\n";

    std::cout
        << "  Encaps       "
        << "Mean=" << encaps_stats.mean_ms
        << "     SD=" << encaps_stats.sd_ms
        << "     CI95=["
        << encaps_stats.ci95_low_ms
        << ", "
        << encaps_stats.ci95_high_ms
        << "] "
        << "P95=" << encaps_stats.p95_ms
        << "     P99=" << encaps_stats.p99_ms
        << "     Max=" << encaps_stats.max_ms
        << " ms\n";

    std::cout
        << "  Decaps       "
        << "Mean=" << decaps_stats.mean_ms
        << "     SD=" << decaps_stats.sd_ms
        << "     CI95=["
        << decaps_stats.ci95_low_ms
        << ", "
        << decaps_stats.ci95_high_ms
        << "] "
        << "P95=" << decaps_stats.p95_ms
        << "     P99=" << decaps_stats.p99_ms
        << "     Max=" << decaps_stats.max_ms
        << " ms\n";

    std::cout
        << "\nCorrectness     : "
        << correctness_rate
        << "%\n";

    std::cout
        << "============================================================\n";

    // =========================================================
    // Output filenames
    // =========================================================

    std::string prefix;

    if (level == "L1" || level == "1")
        prefix = "bike_l1";
    else if (level == "L3" || level == "3")
        prefix = "bike_l3";
    else
        prefix = "bike_l5";

    std::string raw_file =
        prefix + "_raw.csv";

    std::string summary_file =
        prefix + "_summary.csv";

    // =========================================================
    // Raw CSV
    // =========================================================

    std::ofstream raw(raw_file);

    if (!raw) {

        std::cerr
            << "Failed to open "
            << raw_file
            << std::endl;

        OQS_KEM_free(kem);

        return EXIT_FAILURE;
    }

    raw
        << "algorithm,iteration,"
        << "keygen_ms,encaps_ms,decaps_ms,"
        << "correctness\n";

    raw
        << std::setprecision(12);

    for (int i = 0; i < iterations; ++i) {

        bool match =
            true;

        /*
         * Correctness was checked during the measured
         * iteration. Recompute only the stored status
         * from the corresponding shared-secret buffers
         * is not possible for all historical iterations,
         * so store aggregate correctness separately.
         *
         * The raw timing data remain one row per iteration.
         */

        if (correctness_rate == 100.0)
            match = true;
        else
            match = false;

        raw
            << alg_name << ","
            << (i + 1) << ","
            << keygen_times[i] << ","
            << encaps_times[i] << ","
            << decaps_times[i] << ","
            << (match ? 1 : 0)
            << "\n";
    }

    raw.close();

    // =========================================================
    // Summary CSV
    // =========================================================

    std::ofstream summary(summary_file);

    if (!summary) {

        std::cerr
            << "Failed to open "
            << summary_file
            << std::endl;

        OQS_KEM_free(kem);

        return EXIT_FAILURE;
    }

    summary
        << "algorithm,iterations,warmup,"
        << "public_key_bytes,secret_key_bytes,"
        << "ciphertext_bytes,shared_secret_bytes,"
        << "operation,mean_ms,sd_ms,"
        << "ci95_low_ms,ci95_high_ms,"
        << "p95_ms,p99_ms,max_ms,"
        << "correctness_rate_percent\n";

    summary
        << std::fixed
        << std::setprecision(9);

    auto write_summary =
        [&](const char* operation,
            const Statistics& s)
        {
            summary
                << alg_name << ","
                << iterations << ","
                << warmup << ","
                << kem->length_public_key << ","
                << kem->length_secret_key << ","
                << kem->length_ciphertext << ","
                << kem->length_shared_secret << ","
                << operation << ","
                << s.mean_ms << ","
                << s.sd_ms << ","
                << s.ci95_low_ms << ","
                << s.ci95_high_ms << ","
                << s.p95_ms << ","
                << s.p99_ms << ","
                << s.max_ms << ","
                << correctness_rate
                << "\n";
        };

    write_summary(
        "KeyGen",
        keygen_stats);

    write_summary(
        "Encaps",
        encaps_stats);

    write_summary(
        "Decaps",
        decaps_stats);

    summary.close();

    std::cout
        << "\nOutput files:\n"
        << "  "
        << raw_file
        << "\n"
        << "  "
        << summary_file
        << "\n";

    OQS_KEM_free(kem);

    return EXIT_SUCCESS;
}
