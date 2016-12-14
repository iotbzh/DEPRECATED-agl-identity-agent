#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>

#include <openssl/ec.h>
#include <openssl/ecdsa.h>









 int        ret;
 ECDSA_SIG *sig;
 EC_KEY    *eckey;
 eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
 if (eckey == NULL) {
    /* error */
 }
 if (EC_KEY_generate_key(eckey) == 0) {
    /* error */
 }
sig = ECDSA_do_sign(digest, 32, eckey);
 if (sig == NULL) {
    /* error */
 }
 unsigned char *buffer, *pp;
 int            buf_len;
 buf_len = ECDSA_size(eckey);
 buffer  = OPENSSL_malloc(buf_len);
 pp = buffer;
 if (ECDSA_sign(0, dgst, dgstlen, pp, &buf_len, eckey) == 0) {
    /* error */
 }
 ret = ECDSA_do_verify(digest, 32, sig, eckey);
 ret = ECDSA_verify(0, digest, 32, buffer, buf_len, eckey);
if (ret == 1) {
    /* signature ok */
 } else if (ret == 0) {
    /* incorrect signature */
 } else {
    /* error */
 }
 int EC_KEY_set_public_key(EC_KEY *key, const EC_POINT *pub);

