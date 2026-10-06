#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <iomanip>

#include <oqs/oqs.h>

#define WARMUP_ITERATIONS 100
#define MEASURED_ITERATIONS 1000

struct TimingStats {
    double mean_ms = 0.0;
    double sd_ms = 0.0;
    double ci95_low_ms = 0.0;
    double ci95_high_ms = 0.0;
    double p95_ms = 0.0;
    double p99_ms = 0.0;
    double max_ms = 0.0;
};

long long time_diff_ns(
    const timespec& start,
    const timespec& end)
{
    return
        (end.tv_sec - start.tv_sec) * 1000000000LL +
        (end.tv_nsec - start.tv_nsec);
}

TimingStats calculate_stats(
    std::vector<double> values)
{
    TimingStats stats;

    const size_t n = values.size();

    if (n == 0)
        return stats;

    double sum = 0.0;

    for (double v : values)
        sum += v;

    stats.mean_ms =
        sum / static_cast<double>(n);

    double squared_sum = 0.0;

    for (double v : values) {

        double diff =
            v - stats.mean_ms;

        squared_sum +=
            diff * diff;
    }

    if (n > 1) {

        stats.sd_ms =
            std::sqrt(
                squared_sum /
                static_cast<double>(n - 1));
    }

    const double margin =
        1.96 *
        stats.sd_ms /
        std::sqrt(
            static_cast<double>(n));

    stats.ci95_low_ms =
        stats.mean_ms - margin;

    stats.ci95_high_ms =
        stats.mean_ms + margin;

    std::sort(
        values.begin(),
        values.end());

    auto percentile =
        [&](double p) -> double {

            if (values.empty())
                return 0.0;

            double index =
                p *
                static_cast<double>(
                    values.size() - 1);

            size_t lower =
                static_cast<size_t>(
                    std::floor(index));

            size_t upper =
                static_cast<size_t>(
                    std::ceil(index));

            if (lower == upper)
                return values[lower];

            double fraction =
                index -
                static_cast<double>(lower);

            return
                values[lower] +
                fraction *
                (values[upper] -
                 values[lower]);
        };

    stats.p95_ms =
        percentile(0.95);

    stats.p99_ms =
        percentile(0.99);

    stats.max_ms =
        values.back();

    return stats;
}

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

void write_csv_row(
    std::ofstream& csv,
    const std::string& algorithm,
    size_t public_key_bytes,
    size_t secret_key_bytes,
    size_t signature_bytes,
    size_t message_bytes,
    const std::string& operation,
    const TimingStats& stats,
    double correctness)
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
        << std::setprecision(2)
        << correctness
        << "\n";
}

void print_stats(
    const char* operation,
    const TimingStats& stats,
    double correctness)
{
    std::cout
        << "\n"
        << operation
        << "\n";

    std::cout
        << "  Mean ms          : "
        << std::fixed
        << std::setprecision(9)
        << stats.mean_ms
        << "\n";

    std::cout
        << "  SD ms            : "
        << stats.sd_ms
        << "\n";

    std::cout
        << "  95% CI ms        : "
        << stats.ci95_low_ms
        << " - "
        << stats.ci95_high_ms
        << "\n";

    std::cout
        << "  P95 ms           : "
        << stats.p95_ms
        << "\n";

    std::cout
        << "  P99 ms           : "
        << stats.p99_ms
        << "\n";

    std::cout
        << "  Maximum ms       : "
        << stats.max_ms
        << "\n";

    std::cout
        << "  Correctness (%)  : "
        << std::setprecision(2)
        << correctness
        << "\n";
}

bool run_benchmark(
    const char* alg_name,
    const char* message_text,
    const char* csv_filename)
{
    std::cout
        << "\n============================================================\n"
        << "SPHINCS+ BENCHMARK\n"
        << "============================================================\n";

    std::cout
        << "Algorithm: "
        << alg_name
        << "\n";

    if (!OQS_SIG_alg_is_enabled(alg_name)) {

        std::cerr
            << "Algorithm not enabled: "
            << alg_name
            << "\n";

        return false;
    }

    OQS_SIG* sig =
        OQS_SIG_new(alg_name);

    if (sig == nullptr) {

        std::cerr
            << "Failed to create OQS signature object.\n";

        return false;
    }

    const size_t public_key_bytes =
        sig->length_public_key;

    const size_t secret_key_bytes =
        sig->length_secret_key;

    const size_t signature_bytes =
        sig->length_signature;

    const uint8_t* message =
        reinterpret_cast<const uint8_t*>(
            message_text);

    const size_t message_bytes =
        std::strlen(message_text);

    uint8_t* public_key =
        static_cast<uint8_t*>(
            std::malloc(public_key_bytes));

    uint8_t* secret_key =
        static_cast<uint8_t*>(
            std::malloc(secret_key_bytes));

    uint8_t* signature =
        static_cast<uint8_t*>(
            std::malloc(signature_bytes));

    if (!public_key ||
        !secret_key ||
        !signature)
    {
        std::cerr
            << "Memory allocation failed.\n";

        std::free(public_key);
        std::free(secret_key);
        std::free(signature);

        OQS_SIG_free(sig);

        return false;
    }

    std::vector<double> keygen_times;
    std::vector<double> sign_times;
    std::vector<double> verify_times;

    keygen_times.reserve(
        MEASURED_ITERATIONS);

    sign_times.reserve(
        MEASURED_ITERATIONS);

    verify_times.reserve(
        MEASURED_ITERATIONS);

    timespec start{};
    timespec end{};

    size_t sig_len = 0;

    bool benchmark_ok = true;

    /*
     * ========================================================
     * WARM-UP
     * ========================================================
     */

    for (int i = 0;
         i < WARMUP_ITERATIONS;
         ++i)
    {
        if (OQS_SIG_keypair(
                sig,
                public_key,
                secret_key)
            != OQS_SUCCESS)
        {
            std::cerr
                << "Warm-up key generation failed.\n";

            benchmark_ok = false;
            break;
        }

        if (OQS_SIG_sign(
                sig,
                signature,
                &sig_len,
                message,
                message_bytes,
                secret_key)
            != OQS_SUCCESS)
        {
            std::cerr
                << "Warm-up signing failed.\n";

            benchmark_ok = false;
            break;
        }

        if (OQS_SIG_verify(
                sig,
                message,
                message_bytes,
                signature,
                sig_len,
                public_key)
            != OQS_SUCCESS)
        {
            std::cerr
                << "Warm-up verification failed.\n";

            benchmark_ok = false;
            break;
        }
    }

    /*
     * ========================================================
     * MEASURED ITERATIONS
     * ========================================================
     */

    if (benchmark_ok) {

        for (int i = 0;
             i < MEASURED_ITERATIONS;
             ++i)
        {
            /*
             * ------------------------------------------------
             * KEY GENERATION
             * ------------------------------------------------
             */

            clock_gettime(
                CLOCK_MONOTONIC,
                &start);

            int keygen_result =
                OQS_SIG_keypair(
                    sig,
                    public_key,
                    secret_key);

            clock_gettime(
                CLOCK_MONOTONIC,
                &end);

            if (keygen_result != OQS_SUCCESS) {

                std::cerr
                    << "Key generation failed at iteration "
                    << i
                    << "\n";

                benchmark_ok = false;
                break;
            }

            keygen_times.push_back(
                static_cast<double>(
                    time_diff_ns(
                        start,
                        end))
                / 1.0e6);

            /*
             * ------------------------------------------------
             * SIGNING
             * ------------------------------------------------
             */

            sig_len = 0;

            clock_gettime(
                CLOCK_MONOTONIC,
                &start);

            int sign_result =
                OQS_SIG_sign(
                    sig,
                    signature,
                    &sig_len,
                    message,
                    message_bytes,
                    secret_key);

            clock_gettime(
                CLOCK_MONOTONIC,
                &end);

            if (sign_result != OQS_SUCCESS) {

                std::cerr
                    << "Signing failed at iteration "
                    << i
                    << "\n";

                benchmark_ok = false;
                break;
            }

            sign_times.push_back(
                static_cast<double>(
                    time_diff_ns(
                        start,
                        end))
                / 1.0e6);

            /*
             * ------------------------------------------------
             * VERIFICATION
             * ------------------------------------------------
             */

            clock_gettime(
                CLOCK_MONOTONIC,
                &start);

            int verify_result =
                OQS_SIG_verify(
                    sig,
                    message,
                    message_bytes,
                    signature,
                    sig_len,
                    public_key);

            clock_gettime(
                CLOCK_MONOTONIC,
                &end);

            verify_times.push_back(
                static_cast<double>(
                    time_diff_ns(
                        start,
                        end))
                / 1.0e6);

            if (verify_result != OQS_SUCCESS) {

                std::cerr
                    << "Verification failed at iteration "
                    << i
                    << "\n";

                benchmark_ok = false;
                break;
            }
        }
    }

    /*
     * ========================================================
     * CHECK THAT ALL MEASUREMENTS EXIST
     * ========================================================
     */

    if (!benchmark_ok ||
        keygen_times.size() !=
            MEASURED_ITERATIONS ||
        sign_times.size() !=
            MEASURED_ITERATIONS ||
        verify_times.size() !=
            MEASURED_ITERATIONS)
    {
        std::free(public_key);
        std::free(secret_key);
        std::free(signature);

        OQS_SIG_free(sig);

        return false;
    }

    /*
     * ========================================================
     * STATISTICS
     * ========================================================
     */

    TimingStats keygen_stats =
        calculate_stats(keygen_times);

    TimingStats sign_stats =
        calculate_stats(sign_times);

    TimingStats verify_stats =
        calculate_stats(verify_times);

    /*
     * Every measured iteration successfully reached
     * the corresponding operation.
     */

    const double keygen_correctness = 100.0;
    const double sign_correctness = 100.0;
    const double verify_correctness = 100.0;

    /*
     * ========================================================
     * NEGATIVE TEST
     *
     * Modify one byte of the message and make sure that the
     * original signature is rejected.
     * ========================================================
     */

    bool modified_message_rejected = false;

    if (message_bytes > 0) {

        std::vector<uint8_t> modified_message(
            message,
            message + message_bytes);

        modified_message[0] ^= 0x01;

        int negative_result =
            OQS_SIG_verify(
                sig,
                modified_message.data(),
                modified_message.size(),
                signature,
                sig_len,
                public_key);

        modified_message_rejected =
            (negative_result != OQS_SUCCESS);
    }

    /*
     * ========================================================
     * CSV
     * ========================================================
     */

    std::ofstream csv(
        csv_filename,
        std::ios::out |
        std::ios::trunc);

    if (!csv.is_open()) {

        std::cerr
            << "Cannot open CSV file: "
            << csv_filename
            << "\n";

        std::free(public_key);
        std::free(secret_key);
        std::free(signature);

        OQS_SIG_free(sig);

        return false;
    }

    write_csv_header(csv);

    write_csv_row(
        csv,
        alg_name,
        public_key_bytes,
        secret_key_bytes,
        signature_bytes,
        message_bytes,
        "KeyGen",
        keygen_stats,
        keygen_correctness);

    write_csv_row(
        csv,
        alg_name,
        public_key_bytes,
        secret_key_bytes,
        signature_bytes,
        message_bytes,
        "Sign",
        sign_stats,
        sign_correctness);

    write_csv_row(
        csv,
        alg_name,
        public_key_bytes,
        secret_key_bytes,
        signature_bytes,
        message_bytes,
        "Verify",
        verify_stats,
        verify_correctness);

    csv.close();

    /*
     * ========================================================
     * CONSOLE OUTPUT
     * ========================================================
     */

    std::cout
        << "\nAlgorithm              : "
        << alg_name
        << "\n";

    std::cout
        << "Warm-up iterations     : "
        << WARMUP_ITERATIONS
        << "\n";

    std::cout
        << "Measured iterations    : "
        << MEASURED_ITERATIONS
        << "\n";

    std::cout
        << "Public key bytes       : "
        << public_key_bytes
        << "\n";

    std::cout
        << "Secret key bytes       : "
        << secret_key_bytes
        << "\n";

    std::cout
        << "Signature bytes        : "
        << signature_bytes
        << "\n";

    std::cout
        << "Message bytes          : "
        << message_bytes
        << "\n";

    print_stats(
        "KeyGen",
        keygen_stats,
        keygen_correctness);

    print_stats(
        "Sign",
        sign_stats,
        sign_correctness);

    print_stats(
        "Verify",
        verify_stats,
        verify_correctness);

    std::cout
        << "\nModified-message rejection : "
        << (modified_message_rejected
            ? "PASS"
            : "FAIL")
        << "\n";

    std::cout
        << "CSV file                   : "
        << csv_filename
        << "\n";

    /*
     * ========================================================
     * CLEANUP
     * ========================================================
     */

    std::free(public_key);
    std::free(secret_key);
    std::free(signature);

    OQS_SIG_free(sig);

    return modified_message_rejected;
}

int main()
{
    bool all_ok = true;

    bool result128 =
        run_benchmark(
            "SPHINCS+-SHAKE-128s-simple",
            "Hello SPHINCS+ with SHAKE128!",
            "sphincs128s_summary.csv");

    bool result192 =
        run_benchmark(
            "SPHINCS+-SHAKE-192s-simple",
            "Hello SPHINCS+ with SHAKE192!",
            "sphincs192s_summary.csv");

    bool result256 =
        run_benchmark(
            "SPHINCS+-SHAKE-256s-simple",
            "Hello SPHINCS+ with SHAKE256!",
            "sphincs256s_summary.csv");

    all_ok =
        result128 &&
        result192 &&
        result256;

    std::cout
        << "\n============================================================\n"
        << "SPHINCS+ BENCHMARK COMPLETE\n"
        << "============================================================\n";

    std::cout
        << "128s : "
        << (result128 ? "PASS" : "FAIL")
        << "\n";

    std::cout
        << "192s : "
        << (result192 ? "PASS" : "FAIL")
        << "\n";

    std::cout
        << "256s : "
        << (result256 ? "PASS" : "FAIL")
        << "\n";

    return all_ok
        ? EXIT_SUCCESS
        : EXIT_FAILURE;
}
