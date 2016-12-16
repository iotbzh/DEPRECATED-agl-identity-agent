#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>
#include <stdint.h>

#include "u2f-crypto.h"
#include "u2f-protocol.h"

#include <openssl/objects.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>



int u2f_crypto_verify(struct u2f_proto *proto)
{
	int rc;
	const uint8_t *key, *signature, *digest;
	size_t key_size, signature_size, digest_size;

	EC_KEY    *eckey;
	EC_POINT  *point;
	const EC_GROUP *group;
	BN_CTX *ctx;

	/* retrieves the data */
	rc = u2f_protocol_get_publickey(proto, &key, &key_size);
	if (rc < 0)
		goto invalid;
	rc = u2f_protocol_get_signature(proto, &signature, &signature_size);
	if (rc < 0)
		goto invalid;
	rc = u2f_protocol_get_signedpart(proto, &digest, &digest_size);
	if (rc < 0)
		goto invalid;

	eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	if (eckey == NULL)
		goto crypto_error;

	ctx = BN_CTX_new();
	if (ctx == NULL)
		goto crypto_error;

	group = EC_KEY_get0_group(eckey);
	if (group == NULL)
		goto crypto_error;

	point = EC_POINT_new(group);
	if (point == NULL)
		goto crypto_error;

	rc = EC_POINT_oct2point(group, point, key, key_size, ctx);
	if (rc != 1)
		goto crypto_error;

	rc = EC_KEY_set_public_key(eckey, point);
	if (rc != 1)
		goto crypto_error;

	rc = ECDSA_verify(0, digest, (int)digest_size, signature, (int)signature_size, eckey);
printf("HERE!!! %d\n",rc);
	if (rc != 1 && rc != 0)
		goto crypto_error;
	goto end;

crypto_error:
	rc = -ENOMEM; /* TODO */
	goto end;
invalid:
	rc = -EINVAL;
	goto end;
oom:
	rc = -ENOMEM;
	goto end;
end:
	return rc;
}


