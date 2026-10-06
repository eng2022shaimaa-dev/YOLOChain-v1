#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oqs/oqs.h>

#ifdef __cplusplus
extern "C" {
#endif

// اختيار الخوارزمية
static const char *get_alg(char type) {
    switch (type) {
        case '1': return OQS_SIG_alg_mayo_1;
        case '2': return OQS_SIG_alg_falcon_512;
        case '3': return OQS_SIG_alg_sphincs_shake_256s_simple;
        default:  return NULL;
    }
}

// التوقيع
int pqc_sign(
    const uint8_t *message,
    size_t message_len,
    char type,
    uint8_t **signature,
    size_t *signature_len,
    uint8_t **public_key,
    size_t *public_key_len
) {
    const char *alg = get_alg(type);
    if (!alg || !OQS_SIG_alg_is_enabled(alg))
        return -1;

    OQS_SIG *sig = OQS_SIG_new(alg);
    if (!sig)
        return -2;

    uint8_t *pk = (uint8_t *)malloc(sig->length_public_key);
    uint8_t *sk = (uint8_t *)malloc(sig->length_secret_key);
    uint8_t *sig_buf = (uint8_t *)malloc(sig->length_signature);

    if (!pk || !sk || !sig_buf)
        return -3;

    if (OQS_SIG_keypair(sig, pk, sk) != OQS_SUCCESS)
        return -4;

    if (OQS_SIG_sign(sig, sig_buf, signature_len,
                     message, message_len, sk) != OQS_SUCCESS)
        return -5;

    *signature = sig_buf;
    *public_key = pk;
    *public_key_len = sig->length_public_key;

    free(sk);
    OQS_SIG_free(sig);
    return 0;
}

// التحقق
int pqc_verify(
    const uint8_t *message,
    size_t message_len,
    const uint8_t *signature,
    size_t signature_len,
    const uint8_t *public_key,
    char type
) {
    const char *alg = get_alg(type);
    if (!alg || !OQS_SIG_alg_is_enabled(alg))
        return -1;

    OQS_SIG *sig = OQS_SIG_new(alg);
    if (!sig)
        return -2;

    int ret = OQS_SIG_verify(
        sig,
        message,
        message_len,
        signature,
        signature_len,
        public_key
    );

    OQS_SIG_free(sig);
    return (ret == OQS_SUCCESS) ? 0 : -3;
}

// تحرير الذاكرة
void pqc_free(uint8_t *buf) {
    free(buf);
}

#ifdef __cplusplus
}
#endif

