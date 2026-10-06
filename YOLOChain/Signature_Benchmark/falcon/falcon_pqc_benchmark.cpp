#include <iostream>
#include <fstream>
#include <vector>
#include <algorithm>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <ctime>
#include <iomanip>
#include <string>

#include <oqs/oqs.h>

/*
 * ============================================================
 * Falcon PQC Benchmark
 * ============================================================
 *
 * Algorithms:
 *   - Falcon-512
 *   - Falcon-1024
 *
 * Experimental configuration:
 *   Warmup iterations : 100
 *   Measured iterations: 1000
 *
 * Operations:
 *   - KeyGen
 *   - Sign
 *   - Verify
 *
 * Output:
 *   falcon512_summary.csv
 *   falcon1024_summary.csv
 *
 * Statistics:
 *   Mean
 *   Standard deviation
 *   95% confidence interval
 *   P95
 *   P99
 *   Maximum
 *   Correctness rate
 *
 * Timing unit:
 *   milliseconds
 *
 * Timer:
 *   CLOCK_MONOTONIC
 * ============================================================
 */

#define ITERATIONS 1000
#define WARMUP 100

// ============================================================
// Time difference in nanoseconds
// ============================================================

long long time_diff_ns(
    const timespec& start,
    const timespec& end)
{
    return
        (end.tv_sec - start.tv_sec) * 1000000000LL +
        (end.tv_nsec - start.tv_nsec);
}

// ============================================================
// Statistics structure
// ============================================================

struct Statistics {

    double mean_ms;
    double sd_ms;

    double ci95_low_ms;
    double ci95_high_ms;

    double p95_ms;
    double p99_ms;

    double max_ms;
};

// ============================================================
// Calculate statistics
// ============================================================

Statistics calculate_statistics(
    const std::vector<double>& values)
{
    Statistics s{};

    if (values.empty()) {
        return s;
    }

    const size_t n = values.size();

    // --------------------------------------------------------
    // Mean
    // --------------------------------------------------------

    double sum = 0.0;

    for (double v : values) {
        sum += v;
    }

    s.mean_ms = sum / static_cast<double>(n);

    // --------------------------------------------------------
    // Standard deviation
    // --------------------------------------------------------

    if (n > 1) {

        double squared_sum = 0.0;

        for (double v : values) {

            double diff =
                v - s.mean_ms;

            squared_sum += diff * diff;
        }

        s.sd_ms =
            std::sqrt(
                squared_sum /
                static_cast<double>(n - 1)
            );

    } else {

        s.sd_ms = 0.0;
    }

    // --------------------------------------------------------
    // 95% Confidence Interval
    //
    // For n=1000:
    // CI = mean +/- 1.96 * SD/sqrt(n)
    // --------------------------------------------------------

    double standard_error =
        s.sd_ms /
        std::sqrt(static_cast<double>(n));

    double margin =
        1.96 * standard_error;

    s.ci95_low_ms =
        s.mean_ms - margin;

    s.ci95_high_ms =
        s.mean_ms + margin;

    // --------------------------------------------------------
    // Sorted copy for percentiles
    // --------------------------------------------------------

    std::vector<double> sorted_values =
        values;

    std::sort(
        sorted_values.begin(),
        sorted_values.end()
    );

    // --------------------------------------------------------
    // P95
    // --------------------------------------------------------

    size_t p95_index =
        static_cast<size_t>(
            std::ceil(0.95 * n)
        ) - 1;

    if (p95_index >= n) {
        p95_index = n - 1;
    }

    s.p95_ms =
        sorted_values[p95_index];

    // --------------------------------------------------------
    // P99
    // --------------------------------------------------------

    size_t p99_index =
        static_cast<size_t>(
            std::ceil(0.99 * n)
        ) - 1;

    if (p99_index >= n) {
        p99_index = n - 1;
    }

    s.p99_ms =
        sorted_values[p99_index];

    // --------------------------------------------------------
    // Maximum
    // --------------------------------------------------------

    s.max_ms =
        sorted_values.back();

    return s;
}

// ============================================================
// Convert nanoseconds to milliseconds
// ============================================================

double ns_to_ms(long long ns)
{
    return
        static_cast<double>(ns) /
        1000000.0;
}

// ============================================================
// CSV writer
// ============================================================

void write_csv_header(
    std::ofstream& file)
{
    file
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

// ============================================================
// Write one CSV result
// ============================================================

void write_csv_row(
    std::ofstream& file,
    const char* algorithm,
    const OQS_SIG* sig,
    const char* operation,
    const Statistics& stats,
    double correctness_rate,
    size_t message_bytes)
{
    file
        << algorithm << ","
        << ITERATIONS << ","
        << WARMUP << ","
        << sig->length_public_key << ","
        << sig->length_secret_key << ","
        << sig->length_signature << ","
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

        << std::setprecision(9)
        << correctness_rate

        << "\n";
}

// ============================================================
// Benchmark one Falcon algorithm
// ============================================================

bool benchmark_falcon(
    const char* algorithm,
    const char* output_file)
{
    std::cout
        << "\n============================================================\n"
        << "Benchmark: "
        << algorithm
        << "\n"
        << "============================================================\n";

    // --------------------------------------------------------
    // Check whether algorithm is enabled
    // --------------------------------------------------------

    if (!OQS_SIG_alg_is_enabled(algorithm)) {

        std::cerr
            << "ERROR: Algorithm is not enabled: "
            << algorithm
            << "\n";

        return false;
    }

    // --------------------------------------------------------
    // Create OQS signature object
    // --------------------------------------------------------

    OQS_SIG* sig =
        OQS_SIG_new(algorithm);

    if (sig == nullptr) {

        std::cerr
            << "ERROR: Failed to create OQS_SIG object for "
            << algorithm
            << "\n";

        return false;
    }

    // --------------------------------------------------------
    // Print algorithm information
    // --------------------------------------------------------

    std::cout
        << "Algorithm            : "
        << sig->method_name
        << "\n";

    std::cout
        << "Public key bytes     : "
        << sig->length_public_key
        << "\n";

    std::cout
        << "Secret key bytes     : "
        << sig->length_secret_key
        << "\n";

    std::cout
        << "Signature bytes      : "
        << sig->length_signature
        << "\n";

    // --------------------------------------------------------
    // Message
    // --------------------------------------------------------

    const uint8_t message[] =
        "Hello Falcon!";

    const size_t message_len =
        strlen(
            reinterpret_cast<const char*>(message)
        );

    std::cout
        << "Message bytes        : "
        << message_len
        << "\n";

    std::cout
        << "Warmup iterations    : "
        << WARMUP
        << "\n";

    std::cout
        << "Measured iterations  : "
        << ITERATIONS
        << "\n";

    // --------------------------------------------------------
    // Allocate buffers
    // --------------------------------------------------------

    uint8_t* public_key =
        static_cast<uint8_t*>(
            malloc(sig->length_public_key)
        );

    uint8_t* secret_key =
        static_cast<uint8_t*>(
            malloc(sig->length_secret_key)
        );

    uint8_t* signature =
        static_cast<uint8_t*>(
            malloc(sig->length_signature)
        );

    if (!public_key ||
        !secret_key ||
        !signature)
    {
        std::cerr
            << "ERROR: Memory allocation failed.\n";

        free(public_key);
        free(secret_key);
        free(signature);

        OQS_SIG_free(sig);

        return false;
    }

    // --------------------------------------------------------
    // Timing vectors
    // --------------------------------------------------------

    std::vector<double> keygen_times;
    std::vector<double> sign_times;
    std::vector<double> verify_times;

    keygen_times.reserve(ITERATIONS);
    sign_times.reserve(ITERATIONS);
    verify_times.reserve(ITERATIONS);

    // --------------------------------------------------------
    // Correctness counters
    // --------------------------------------------------------

    size_t keygen_success = 0;
    size_t sign_success = 0;
    size_t verify_success = 0;

    // ========================================================
    // WARMUP
    // ========================================================

    std::cout
        << "\nRunning warmup..."
        << std::endl;

	size_t sig_len = 0;

    for (int i = 0; i < WARMUP; i++) {

        

        // Key generation
        if (OQS_SIG_keypair(
                sig,
                public_key,
                secret_key)
            != OQS_SUCCESS)
        {
            std::cerr
                << "ERROR: Warmup key generation failed.\n";

            free(public_key);
            free(secret_key);
            free(signature);

            OQS_SIG_free(sig);

            return false;
        }

        // Signing
        if (OQS_SIG_sign(
                sig,
                signature,
                &sig_len,
                message,
                message_len,
                secret_key)
            != OQS_SUCCESS)
        {
            std::cerr
                << "ERROR: Warmup signing failed.\n";

            free(public_key);
            free(secret_key);
            free(signature);

            OQS_SIG_free(sig);

            return false;
        }

        // Verification
        if (OQS_SIG_verify(
                sig,
                message,
                message_len,
                signature,
                sig_len,
                public_key)
            != OQS_SUCCESS)
        {
            std::cerr
                << "ERROR: Warmup verification failed.\n";

            free(public_key);
            free(secret_key);
            free(signature);

            OQS_SIG_free(sig);

            return false;
        }
    }

    std::cout
        << "Warmup completed successfully."
        << std::endl;

    // ========================================================
    // MEASURED ITERATIONS
    // ========================================================

    std::cout
        << "Running "
        << ITERATIONS
        << " measured iterations..."
        << std::endl;

    for (int i = 0; i < ITERATIONS; i++) {

        timespec start{};
        timespec end{};

        size_t sig_len = 0;

        // ----------------------------------------------------
        // Key Generation
        // ----------------------------------------------------

        clock_gettime(
            CLOCK_MONOTONIC,
            &start
        );

        int keygen_result =
            OQS_SIG_keypair(
                sig,
                public_key,
                secret_key
            );

        clock_gettime(
            CLOCK_MONOTONIC,
            &end
        );

        if (keygen_result != OQS_SUCCESS) {

            std::cerr
                << "ERROR: Key generation failed at iteration "
                << i
                << "\n";

            free(public_key);
            free(secret_key);
            free(signature);

            OQS_SIG_free(sig);

            return false;
        }

        keygen_success++;

        keygen_times.push_back(
            ns_to_ms(
                time_diff_ns(
                    start,
                    end
                )
            )
        );

        // ----------------------------------------------------
        // Signing
        // ----------------------------------------------------

        clock_gettime(
            CLOCK_MONOTONIC,
            &start
        );

        int sign_result =
            OQS_SIG_sign(
                sig,
                signature,
                &sig_len,
                message,
                message_len,
                secret_key
            );

        clock_gettime(
            CLOCK_MONOTONIC,
            &end
        );

        if (sign_result != OQS_SUCCESS) {

            std::cerr
                << "ERROR: Signing failed at iteration "
                << i
                << "\n";

            free(public_key);
            free(secret_key);
            free(signature);

            OQS_SIG_free(sig);

            return false;
        }

        sign_success++;

        sign_times.push_back(
            ns_to_ms(
                time_diff_ns(
                    start,
                    end
                )
            )
        );

        // ----------------------------------------------------
        // Verification
        // ----------------------------------------------------

        clock_gettime(
            CLOCK_MONOTONIC,
            &start
        );

        int verify_result =
            OQS_SIG_verify(
                sig,
                message,
                message_len,
                signature,
                sig_len,
                public_key
            );

        clock_gettime(
            CLOCK_MONOTONIC,
            &end
        );

        if (verify_result != OQS_SUCCESS) {

            std::cerr
                << "ERROR: Verification failed at iteration "
                << i
                << "\n";

            free(public_key);
            free(secret_key);
            free(signature);

            OQS_SIG_free(sig);

            return false;
        }

        verify_success++;

        verify_times.push_back(
            ns_to_ms(
                time_diff_ns(
                    start,
                    end
                )
            )
        );
    }

    // ========================================================
    // Calculate statistics
    // ========================================================

    Statistics keygen_stats =
        calculate_statistics(keygen_times);

    Statistics sign_stats =
        calculate_statistics(sign_times);

    Statistics verify_stats =
        calculate_statistics(verify_times);

    // --------------------------------------------------------
    // Correctness rates
    // --------------------------------------------------------

    double keygen_correctness =
        100.0 *
        static_cast<double>(keygen_success) /
        static_cast<double>(ITERATIONS);

    double sign_correctness =
        100.0 *
        static_cast<double>(sign_success) /
        static_cast<double>(ITERATIONS);

    double verify_correctness =
        100.0 *
        static_cast<double>(verify_success) /
        static_cast<double>(ITERATIONS);

    // ========================================================
    // Display results
    // ========================================================

    std::cout
        << "\n---------------- Results ----------------\n";

    std::cout
        << std::fixed
        << std::setprecision(9);

    std::cout
        << "KeyGen\n"
        << "  Mean       : "
        << keygen_stats.mean_ms
        << " ms\n"
        << "  SD         : "
        << keygen_stats.sd_ms
        << " ms\n"
        << "  CI95       : ["
        << keygen_stats.ci95_low_ms
        << ", "
        << keygen_stats.ci95_high_ms
        << "] ms\n"
        << "  P95        : "
        << keygen_stats.p95_ms
        << " ms\n"
        << "  P99        : "
        << keygen_stats.p99_ms
        << " ms\n"
        << "  Max        : "
        << keygen_stats.max_ms
        << " ms\n"
        << "  Correctness: "
        << keygen_correctness
        << "%\n";

    std::cout
        << "\nSign\n"
        << "  Mean       : "
        << sign_stats.mean_ms
        << " ms\n"
        << "  SD         : "
        << sign_stats.sd_ms
        << " ms\n"
        << "  CI95       : ["
        << sign_stats.ci95_low_ms
        << ", "
        << sign_stats.ci95_high_ms
        << "] ms\n"
        << "  P95        : "
        << sign_stats.p95_ms
        << " ms\n"
        << "  P99        : "
        << sign_stats.p99_ms
        << " ms\n"
        << "  Max        : "
        << sign_stats.max_ms
        << " ms\n"
        << "  Correctness: "
        << sign_correctness
        << "%\n";

    std::cout
        << "\nVerify\n"
        << "  Mean       : "
        << verify_stats.mean_ms
        << " ms\n"
        << "  SD         : "
        << verify_stats.sd_ms
        << " ms\n"
        << "  CI95       : ["
        << verify_stats.ci95_low_ms
        << ", "
        << verify_stats.ci95_high_ms
        << "] ms\n"
        << "  P95        : "
        << verify_stats.p95_ms
        << " ms\n"
        << "  P99        : "
        << verify_stats.p99_ms
        << " ms\n"
        << "  Max        : "
        << verify_stats.max_ms
        << " ms\n"
        << "  Correctness: "
        << verify_correctness
        << "%\n";

    // ========================================================
    // Write CSV
    // ========================================================

    std::ofstream csv(
        output_file,
        std::ios::out |
        std::ios::trunc
    );

    if (!csv.is_open()) {

        std::cerr
            << "\nERROR: Cannot open output file: "
            << output_file
            << "\n";

        free(public_key);
        free(secret_key);
        free(signature);

        OQS_SIG_free(sig);

        return false;
    }

    write_csv_header(csv);

    write_csv_row(
        csv,
        algorithm,
        sig,
        "KeyGen",
        keygen_stats,
        keygen_correctness,
        message_len
    );

    write_csv_row(
        csv,
        algorithm,
        sig,
        "Sign",
        sign_stats,
        sign_correctness,
        message_len
    );

    write_csv_row(
        csv,
        algorithm,
        sig,
        "Verify",
        verify_stats,
        verify_correctness,
        message_len
    );

    csv.close();

    // ========================================================
    // Final correctness check
    // ========================================================

    bool final_correctness =
        OQS_SIG_verify(
            sig,
            message,
            message_len,
            signature,
            sig_len,
            public_key
        ) == OQS_SUCCESS;

    std::cout
        << "\nFinal signature verification: "
        << (final_correctness ? "PASS" : "FAIL")
        << "\n";

    std::cout
        << "CSV written to: "
        << output_file
        << "\n";

    // ========================================================
    // Cleanup
    // ========================================================

    free(public_key);
    free(secret_key);
    free(signature);

    OQS_SIG_free(sig);

    return true;
}

// ============================================================
// MAIN
// ============================================================

int main()
{
    std::cout
        << "============================================================\n"
        << "          Falcon PQC Benchmark Suite\n"
        << "============================================================\n"
        << "Warmup iterations   : "
        << WARMUP
        << "\n"
        << "Measured iterations : "
        << ITERATIONS
        << "\n"
        << "============================================================\n";

    // --------------------------------------------------------
    // Falcon-512
    // --------------------------------------------------------

    bool falcon512_ok =
        benchmark_falcon(
            "Falcon-512",
            "falcon512_summary.csv"
        );

    // --------------------------------------------------------
    // Falcon-1024
    // --------------------------------------------------------

    bool falcon1024_ok =
        benchmark_falcon(
            "Falcon-1024",
            "falcon1024_summary.csv"
        );

    // --------------------------------------------------------
    // Final status
    // --------------------------------------------------------

    std::cout
        << "\n============================================================\n"
        << "Benchmark completed.\n"
        << "============================================================\n";

    std::cout
        << "Falcon-512  : "
        << (falcon512_ok ? "SUCCESS" : "FAILED")
        << "\n";

    std::cout
        << "Falcon-1024 : "
        << (falcon1024_ok ? "SUCCESS" : "FAILED")
        << "\n";

    std::cout
        << "============================================================\n";

    if (falcon512_ok && falcon1024_ok) {
        return EXIT_SUCCESS;
    }

    return EXIT_FAILURE;
}
