#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oqs/oqs.h>

#ifdef __cplusplus
extern "C" {
#endif

/* اختيار الخوارزمية */
static const char *get_kem_alg(char type) {
    switch (type) {
        case '1': return OQS_KEM_alg_kyber_512;
        case '2': return OQS_KEM_alg_ntru_hps2048509;
        case '3': return OQS_KEM_alg_bike_l1;
        default:  return NULL;
    }
}

/* توليد المفاتيح */
int pqc_kem_keypair(
    char type,
    uint8_t **public_key,
    size_t *public_key_len,
    uint8_t **secret_key,
    size_t *secret_key_len
) {
    const char *alg = get_kem_alg(type);
    if (!alg || !OQS_KEM_alg_is_enabled(alg))
        return -1;

    OQS_KEM *kem = OQS_KEM_new(alg);
    if (!kem)
        return -2;

    uint8_t *pk = (uint8_t *)malloc(kem->length_public_key);
    uint8_t *sk = (uint8_t *)malloc(kem->length_secret_key);

    if (!pk || !sk)
        return -3;

    if (OQS_KEM_keypair(kem, pk, sk) != OQS_SUCCESS)
        return -4;

    *public_key = pk;
    *secret_key = sk;
    *public_key_len = kem->length_public_key;
    *secret_key_len = kem->length_secret_key;

    OQS_KEM_free(kem);
    return 0;
}

/* Encapsulation */
int pqc_kem_encaps(
    char type,
    const uint8_t *public_key,
    uint8_t **ciphertext,
    size_t *ciphertext_len,
    uint8_t **shared_secret,
    size_t *shared_secret_len
) {
    const char *alg = get_kem_alg(type);
    if (!alg || !OQS_KEM_alg_is_enabled(alg))
        return -1;

    OQS_KEM *kem = OQS_KEM_new(alg);
    if (!kem)
        return -2;

    uint8_t *ct = (uint8_t *)malloc(kem->length_ciphertext);
    uint8_t *ss = (uint8_t *)malloc(kem->length_shared_secret);

    if (!ct || !ss)
        return -3;

    if (OQS_KEM_encaps(kem, ct, ss, public_key) != OQS_SUCCESS)
        return -4;

    *ciphertext = ct;
    *shared_secret = ss;
    *ciphertext_len = kem->length_ciphertext;
    *shared_secret_len = kem->length_shared_secret;

    OQS_KEM_free(kem);
    return 0;
}

/* Decapsulation */
int pqc_kem_decaps(
    char type,
    const uint8_t *ciphertext,
    const uint8_t *secret_key,
    uint8_t **shared_secret,
    size_t *shared_secret_len
) {
    const char *alg = get_kem_alg(type);
    if (!alg || !OQS_KEM_alg_is_enabled(alg))
        return -1;

    OQS_KEM *kem = OQS_KEM_new(alg);
    if (!kem)
        return -2;

    uint8_t *ss = (uint8_t *)malloc(kem->length_shared_secret);
    if (!ss)
        return -3;

    if (OQS_KEM_decaps(kem, ss, ciphertext, secret_key) != OQS_SUCCESS)
        return -4;

    *shared_secret = ss;
    *shared_secret_len = kem->length_shared_secret;

    OQS_KEM_free(kem);
    return 0;
}

/* تحرير الذاكرة */
void pqc_kem_free(uint8_t *buf) {
    free(buf);
}

#ifdef __cplusplus
}
#endif

