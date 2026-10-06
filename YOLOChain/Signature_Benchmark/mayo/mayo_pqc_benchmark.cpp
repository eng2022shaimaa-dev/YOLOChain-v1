#include <iostream>
#include <fstream>
#include <vector>
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <iomanip>

#include <oqs/oqs.h>

/*
 * ============================================================
 * MAYO PQC SIGNATURE BENCHMARK
 * ============================================================
 *
 * Algorithms:
 *   MAYO-1
 *   MAYO-3
 *   MAYO-5
 *
 * Methodology:
 *   Warm-up iterations : 100
 *   Measured iterations: 1000
 *
 * Operations:
 *   Key Generation
 *   Signing
 *   Verification
 *
 * Metrics:
 *   Mean
 *   Sample SD
 *   95% CI
 *   P95
 *   P99
 *   Maximum
 *
 * Correctness:
 *   - Valid signature verification
 *   - Modified-message rejection
 *
 * Timing:
 *   CLOCK_MONOTONIC
 *
 * Output:
 *   mayo1_summary.csv
 *   mayo3_summary.csv
 *   mayo5_summary.csv
 *
 * ============================================================
 */

#define WARMUP_ITERATIONS   100
#define MEASURED_ITERATIONS 1000

static const double Z95 = 1.96;


/* ============================================================
 * Timing helper
 * ============================================================ */

static inline long long time_diff_ns(
    const timespec& start,
    const timespec& end)
{
    return
        (end.tv_sec - start.tv_sec) * 1000000000LL +
        (end.tv_nsec - start.tv_nsec);
}


/* ============================================================
 * Statistics structure
 * ============================================================ */

struct Statistics {

    double mean_ms;
    double sd_ms;
    double ci95_low_ms;
    double ci95_high_ms;

    double p95_ms;
    double p99_ms;
    double max_ms;
};


/* ============================================================
 * Calculate statistics
 * ============================================================ */

Statistics calculate_statistics(
    const std::vector<double>& values_ms)
{
    Statistics s{};

    if (values_ms.empty()) {
        return s;
    }

    const size_t n = values_ms.size();

    /* ----------------------------
     * Mean
     * ---------------------------- */

    double sum = 0.0;

    for (double x : values_ms) {
        sum += x;
    }

    s.mean_ms = sum / static_cast<double>(n);


    /* ----------------------------
     * Sample standard deviation
     * ---------------------------- */

    if (n > 1) {

        double sq_sum = 0.0;

        for (double x : values_ms) {

            double d = x - s.mean_ms;

            sq_sum += d * d;
        }

        s.sd_ms =
            std::sqrt(
                sq_sum /
                static_cast<double>(n - 1)
            );

    } else {

        s.sd_ms = 0.0;
    }


    /* ----------------------------
     * 95% confidence interval
     * ---------------------------- */

    double standard_error =
        s.sd_ms /
        std::sqrt(static_cast<double>(n));

    double margin =
        Z95 * standard_error;

    s.ci95_low_ms =
        s.mean_ms - margin;

    s.ci95_high_ms =
        s.mean_ms + margin;


    /* ----------------------------
     * Percentiles
     * ---------------------------- */

    std::vector<double> sorted =
        values_ms;

    std::sort(
        sorted.begin(),
        sorted.end()
    );


    auto percentile = [&sorted](double p) -> double {

        if (sorted.empty()) {
            return 0.0;
        }

        if (sorted.size() == 1) {
            return sorted[0];
        }

        double position =
            p * static_cast<double>(
                sorted.size() - 1
            );

        size_t lower =
            static_cast<size_t>(
                std::floor(position)
            );

        size_t upper =
            static_cast<size_t>(
                std::ceil(position)
            );

        if (lower == upper) {
            return sorted[lower];
        }

        double fraction =
            position -
            static_cast<double>(lower);

        return
            sorted[lower] +
            fraction *
            (sorted[upper] - sorted[lower]);
    };


    s.p95_ms = percentile(0.95);
    s.p99_ms = percentile(0.99);

    s.max_ms =
        sorted.back();

    return s;
}


/* ============================================================
 * CSV writer
 * ============================================================ */

void write_csv_header(
    std::ofstream& csv)
{
    csv
        << "algorithm,"
        << "iterations,"
        << "warmup,"
        << "public_key_bytes,"
        << "secret_key_bytes,"
        << "signature_bytes,"
        << "message_bytes,"
        << "operation,"
        << "mean_ms,"
        << "sd_ms,"
        << "ci95_low_ms,"
        << "ci95_high_ms,"
        << "p95_ms,"
        << "p99_ms,"
        << "max_ms,"
        << "correctness_rate_percent"
        << "\n";
}


/* ============================================================
 * CSV row writer
 * ============================================================ */

void write_csv_row(
    std::ofstream& csv,
    const char* algorithm,
    size_t public_key_bytes,
    size_t secret_key_bytes,
    size_t signature_bytes,
    size_t message_bytes,
    const char* operation,
    const Statistics& stats,
    double correctness_rate)
{
    csv
        << algorithm << ","
        << MEASURED_ITERATIONS << ","
        << WARMUP_ITERATIONS << ","
        << public_key_bytes << ","
        << secret_key_bytes << ","
        << signature_bytes << ","
        << message_bytes << ","
        << operation << ","

        << std::fixed
        << std::setprecision(9)

        << stats.mean_ms << ","
        << stats.sd_ms << ","
        << stats.ci95_low_ms << ","
        << stats.ci95_high_ms << ","
        << stats.p95_ms << ","
        << stats.p99_ms << ","
        << stats.max_ms << ","

        << std::setprecision(6)
        << correctness_rate

        << "\n";
}


/* ============================================================
 * Benchmark one MAYO algorithm
 * ============================================================ */

bool benchmark_mayo(
    const char* alg_name,
    const char* output_csv,
    const char* display_name)
{
    std::cout
        << "\n============================================================\n"
        << display_name
        << "\n"
        << "============================================================\n";


    /* ========================================================
     * Check whether algorithm is enabled
     * ======================================================== */

    if (!OQS_SIG_alg_is_enabled(alg_name)) {

        std::cerr
            << "ERROR: Algorithm not enabled: "
            << alg_name
            << "\n";

        return false;
    }


    /* ========================================================
     * Create OQS signature object
     * ======================================================== */

    OQS_SIG* sig =
        OQS_SIG_new(alg_name);

    if (sig == nullptr) {

        std::cerr
            << "ERROR: Failed to create OQS signature object for "
            << display_name
            << "\n";

        return false;
    }


    /* ========================================================
     * Print parameter sizes
     * ======================================================== */

    std::cout
        << "Algorithm          : "
        << sig->method_name
        << "\n";

    std::cout
        << "Public key         : "
        << sig->length_public_key
        << " bytes\n";

    std::cout
        << "Secret key         : "
        << sig->length_secret_key
        << " bytes\n";

    std::cout
        << "Signature          : "
        << sig->length_signature
        << " bytes\n";

    std::cout
        << "Warm-up iterations : "
        << WARMUP_ITERATIONS
        << "\n";

    std::cout
        << "Measured iterations: "
        << MEASURED_ITERATIONS
        << "\n";


    /* ========================================================
     * Allocate buffers
     * ======================================================== */

    uint8_t* public_key =
        static_cast<uint8_t*>(
            std::malloc(
                sig->length_public_key
            )
        );

    uint8_t* secret_key =
        static_cast<uint8_t*>(
            std::malloc(
                sig->length_secret_key
            )
        );

    uint8_t* signature =
        static_cast<uint8_t*>(
            std::malloc(
                sig->length_signature
            )
        );


    if (!public_key ||
        !secret_key ||
        !signature)
    {
        std::cerr
            << "ERROR: Memory allocation failed\n";

        std::free(public_key);
        std::free(secret_key);
        std::free(signature);

        OQS_SIG_free(sig);

        return false;
    }


    /* ========================================================
     * Message
     * ======================================================== */

    const uint8_t message[] =
        "Hello MAYO Post-Quantum Signature Benchmark!";

    const size_t msg_len =
        sizeof(message) - 1;


    /* ========================================================
     * Timing vectors
     * ======================================================== */

    std::vector<double> keygen_times;
    std::vector<double> sign_times;
    std::vector<double> verify_times;

    keygen_times.reserve(
        MEASURED_ITERATIONS
    );

    sign_times.reserve(
        MEASURED_ITERATIONS
    );

    verify_times.reserve(
        MEASURED_ITERATIONS
    );


    /* ========================================================
     * Correctness counters
     * ======================================================== */

    size_t keygen_success = 0;
    size_t sign_success = 0;
    size_t verify_success = 0;


    /* ========================================================
     * Signature length
     * ======================================================== */

    size_t sig_len = 0;


    /* ========================================================
     * Warm-up phase
     *
     * Timing is NOT recorded.
     * ======================================================== */

    std::cout
        << "\nRunning warm-up..."
        << std::endl;


    for (int i = 0;
         i < WARMUP_ITERATIONS;
         ++i)
    {
        if (OQS_SIG_keypair(
                sig,
                public_key,
                secret_key) != OQS_SUCCESS)
        {
            std::cerr
                << "ERROR: Warm-up key generation failed\n";

            std::free(public_key);
            std::free(secret_key);
            std::free(signature);
            OQS_SIG_free(sig);

            return false;
        }


        sig_len = 0;

        if (OQS_SIG_sign(
                sig,
                signature,
                &sig_len,
                message,
                msg_len,
                secret_key) != OQS_SUCCESS)
        {
            std::cerr
                << "ERROR: Warm-up signing failed\n";

            std::free(public_key);
            std::free(secret_key);
            std::free(signature);
            OQS_SIG_free(sig);

            return false;
        }


        if (OQS_SIG_verify(
                sig,
                message,
                msg_len,
                signature,
                sig_len,
                public_key) != OQS_SUCCESS)
        {
            std::cerr
                << "ERROR: Warm-up verification failed\n";

            std::free(public_key);
            std::free(secret_key);
            std::free(signature);
            OQS_SIG_free(sig);

            return false;
        }
    }


    /* ========================================================
     * Measurement phase
     * ======================================================== */

    std::cout
        << "Running measured iterations..."
        << std::endl;


    for (int i = 0;
         i < MEASURED_ITERATIONS;
         ++i)
    {
        timespec start{};
        timespec end{};


        /* ====================================================
         * Key Generation
         * ==================================================== */

        clock_gettime(
            CLOCK_MONOTONIC,
            &start
        );

        OQS_STATUS keygen_status =
            OQS_SIG_keypair(
                sig,
                public_key,
                secret_key
            );

        clock_gettime(
            CLOCK_MONOTONIC,
            &end
        );


        if (keygen_status != OQS_SUCCESS)
        {
            std::cerr
                << "ERROR: Key generation failed at iteration "
                << i
                << "\n";

            std::free(public_key);
            std::free(secret_key);
            std::free(signature);
            OQS_SIG_free(sig);

            return false;
        }


        ++keygen_success;


        double keygen_ms =
            static_cast<double>(
                time_diff_ns(start, end)
            ) / 1000000.0;

        keygen_times.push_back(
            keygen_ms
        );


        /* ====================================================
         * Signing
         * ==================================================== */

        sig_len = 0;

        clock_gettime(
            CLOCK_MONOTONIC,
            &start
        );

        OQS_STATUS sign_status =
            OQS_SIG_sign(
                sig,
                signature,
                &sig_len,
                message,
                msg_len,
                secret_key
            );

        clock_gettime(
            CLOCK_MONOTONIC,
            &end
        );


        if (sign_status != OQS_SUCCESS)
        {
            std::cerr
                << "ERROR: Signing failed at iteration "
                << i
                << "\n";

            std::free(public_key);
            std::free(secret_key);
            std::free(signature);
            OQS_SIG_free(sig);

            return false;
        }


        ++sign_success;


        double sign_ms =
            static_cast<double>(
                time_diff_ns(start, end)
            ) / 1000000.0;

        sign_times.push_back(
            sign_ms
        );


        /* ====================================================
         * Verification
         * ==================================================== */

        clock_gettime(
            CLOCK_MONOTONIC,
            &start
        );

        OQS_STATUS verify_status =
            OQS_SIG_verify(
                sig,
                message,
                msg_len,
                signature,
                sig_len,
                public_key
            );

        clock_gettime(
            CLOCK_MONOTONIC,
            &end
        );


        if (verify_status != OQS_SUCCESS)
        {
            std::cerr
                << "ERROR: Verification failed at iteration "
                << i
                << "\n";

            std::free(public_key);
            std::free(secret_key);
            std::free(signature);
            OQS_SIG_free(sig);

            return false;
        }


        ++verify_success;


        double verify_ms =
            static_cast<double>(
                time_diff_ns(start, end)
            ) / 1000000.0;

        verify_times.push_back(
            verify_ms
        );
    }


    /* ========================================================
     * Calculate statistics
     * ======================================================== */

    Statistics keygen_stats =
        calculate_statistics(
            keygen_times
        );

    Statistics sign_stats =
        calculate_statistics(
            sign_times
        );

    Statistics verify_stats =
        calculate_statistics(
            verify_times
        );


    double keygen_correctness =
        100.0 *
        static_cast<double>(keygen_success) /
        static_cast<double>(MEASURED_ITERATIONS);

    double sign_correctness =
        100.0 *
        static_cast<double>(sign_success) /
        static_cast<double>(MEASURED_ITERATIONS);

    double verify_correctness =
        100.0 *
        static_cast<double>(verify_success) /
        static_cast<double>(MEASURED_ITERATIONS);


    /* ========================================================
     * Modified-message rejection test
     *
     * This is NOT included in timing statistics.
     * ======================================================== */

    bool modified_message_rejected = false;

    uint8_t modified_message[128];

    if (msg_len > sizeof(modified_message))
    {
        std::cerr
            << "ERROR: Message buffer too small\n";

        std::free(public_key);
        std::free(secret_key);
        std::free(signature);
        OQS_SIG_free(sig);

        return false;
    }


    std::memcpy(
        modified_message,
        message,
        msg_len
    );


    modified_message[0] ^= 0x01;


    sig_len = 0;


    /*
     * Generate a fresh valid key/signature pair
     * for the rejection test.
     */

    if (OQS_SIG_keypair(
            sig,
            public_key,
            secret_key) != OQS_SUCCESS)
    {
        std::cerr
            << "ERROR: Key generation failed during rejection test\n";

        std::free(public_key);
        std::free(secret_key);
        std::free(signature);
        OQS_SIG_free(sig);

        return false;
    }


    if (OQS_SIG_sign(
            sig,
            signature,
            &sig_len,
            message,
            msg_len,
            secret_key) != OQS_SUCCESS)
    {
        std::cerr
            << "ERROR: Signing failed during rejection test\n";

        std::free(public_key);
        std::free(secret_key);
        std::free(signature);
        OQS_SIG_free(sig);

        return false;
    }


    /*
     * Verification MUST fail for modified message.
     */

    OQS_STATUS modified_status =
        OQS_SIG_verify(
            sig,
            modified_message,
            msg_len,
            signature,
            sig_len,
            public_key
        );


    if (modified_status != OQS_SUCCESS)
    {
        modified_message_rejected = true;
    }


    /* ========================================================
     * Open CSV
     * ======================================================== */

    std::ofstream csv(
        output_csv,
        std::ios::out |
        std::ios::trunc
    );


    if (!csv.is_open())
    {
        std::cerr
            << "ERROR: Cannot open output CSV: "
            << output_csv
            << "\n";

        std::free(public_key);
        std::free(secret_key);
        std::free(signature);
        OQS_SIG_free(sig);

        return false;
    }


    /* ========================================================
     * CSV header
     * ======================================================== */

    write_csv_header(csv);


    /* ========================================================
     * Write operation results
     * ======================================================== */

    write_csv_row(
        csv,
        display_name,
        sig->length_public_key,
        sig->length_secret_key,
        sig->length_signature,
        msg_len,
        "KeyGen",
        keygen_stats,
        keygen_correctness
    );


    write_csv_row(
        csv,
        display_name,
        sig->length_public_key,
        sig->length_secret_key,
        sig->length_signature,
        msg_len,
        "Sign",
        sign_stats,
        sign_correctness
    );


    write_csv_row(
        csv,
        display_name,
        sig->length_public_key,
        sig->length_secret_key,
        sig->length_signature,
        msg_len,
        "Verify",
        verify_stats,
        verify_correctness
    );


    csv.close();


    /* ========================================================
     * Console output
     * ======================================================== */

    std::cout
        << "\n------------------------------------------------------------\n"
        << display_name
        << " RESULTS\n"
        << "------------------------------------------------------------\n";


    std::cout
        << std::fixed
        << std::setprecision(9);


    std::cout
        << "\nKeyGen\n"
        << "  Mean : "
        << keygen_stats.mean_ms
        << " ms\n"
        << "  SD   : "
        << keygen_stats.sd_ms
        << " ms\n"
        << "  CI95 : ["
        << keygen_stats.ci95_low_ms
        << ", "
        << keygen_stats.ci95_high_ms
        << "] ms\n"
        << "  P95  : "
        << keygen_stats.p95_ms
        << " ms\n"
        << "  P99  : "
        << keygen_stats.p99_ms
        << " ms\n"
        << "  Max  : "
        << keygen_stats.max_ms
        << " ms\n"
        << "  Correctness : "
        << std::setprecision(6)
        << keygen_correctness
        << "%\n";


    std::cout
        << std::setprecision(9)
        << "\nSign\n"
        << "  Mean : "
        << sign_stats.mean_ms
        << " ms\n"
        << "  SD   : "
        << sign_stats.sd_ms
        << " ms\n"
        << "  CI95 : ["
        << sign_stats.ci95_low_ms
        << ", "
        << sign_stats.ci95_high_ms
        << "] ms\n"
        << "  P95  : "
        << sign_stats.p95_ms
        << " ms\n"
        << "  P99  : "
        << sign_stats.p99_ms
        << " ms\n"
        << "  Max  : "
        << sign_stats.max_ms
        << " ms\n"
        << "  Correctness : "
        << std::setprecision(6)
        << sign_correctness
        << "%\n";


    std::cout
        << std::setprecision(9)
        << "\nVerify\n"
        << "  Mean : "
        << verify_stats.mean_ms
        << " ms\n"
        << "  SD   : "
        << verify_stats.sd_ms
        << " ms\n"
        << "  CI95 : ["
        << verify_stats.ci95_low_ms
        << ", "
        << verify_stats.ci95_high_ms
        << "] ms\n"
        << "  P95  : "
        << verify_stats.p95_ms
        << " ms\n"
        << "  P99  : "
        << verify_stats.p99_ms
        << " ms\n"
        << "  Max  : "
        << verify_stats.max_ms
        << " ms\n"
        << "  Correctness : "
        << std::setprecision(6)
        << verify_correctness
        << "%\n";


    std::cout
        << "\nSignature length produced : "
        << sig_len
        << " bytes\n";


    std::cout
        << "Modified-message rejection : "
        << (
            modified_message_rejected
            ? "PASS"
            : "FAIL"
        )
        << "\n";


    std::cout
        << "\nCSV output : "
        << output_csv
        << "\n";


    /* ========================================================
     * Cleanup
     * ======================================================== */

    std::free(public_key);
    std::free(secret_key);
    std::free(signature);

    OQS_SIG_free(sig);


    return modified_message_rejected;
}


/* ============================================================
 * Main
 * ============================================================ */

int main()
{
    std::cout
        << "============================================================\n"
        << "MAYO Post-Quantum Signature Benchmark\n"
        << "============================================================\n"
        << "Warm-up iterations : "
        << WARMUP_ITERATIONS
        << "\n"
        << "Measured iterations: "
        << MEASURED_ITERATIONS
        << "\n"
        << "============================================================\n";


    bool mayo1_ok =
        benchmark_mayo(
            OQS_SIG_alg_mayo_1,
            "mayo1_summary.csv",
            "MAYO-1"
        );


    bool mayo3_ok =
        benchmark_mayo(
            OQS_SIG_alg_mayo_3,
            "mayo3_summary.csv",
            "MAYO-3"
        );


    bool mayo5_ok =
        benchmark_mayo(
            OQS_SIG_alg_mayo_5,
            "mayo5_summary.csv",
            "MAYO-5"
        );


    std::cout
        << "\n============================================================\n"
        << "FINAL STATUS\n"
        << "============================================================\n";

    std::cout
        << "MAYO-1 : "
        << (mayo1_ok ? "PASS" : "FAIL")
        << "\n";

    std::cout
        << "MAYO-3 : "
        << (mayo3_ok ? "PASS" : "FAIL")
        << "\n";

    std::cout
        << "MAYO-5 : "
        << (mayo5_ok ? "PASS" : "FAIL")
        << "\n";


    if (mayo1_ok &&
        mayo3_ok &&
        mayo5_ok)
    {
        std::cout
            << "\nAll MAYO benchmarks completed successfully.\n";

        return EXIT_SUCCESS;
    }


    std::cerr
        << "\nOne or more MAYO benchmarks failed.\n";

    return EXIT_FAILURE;
}
