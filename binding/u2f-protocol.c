#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>

#include "u2f.h"
#include "u2f-protocol.h"

#define ERROR_INS_NOT_SUPPORTED                 0x6D00
#define ERROR_CLASS_NOT_SUPPORTED               0x6E00
#define ERROR_WRONG_DATA                        0x6A80
#define ERROR_WRONG_LENGTH                      0x6700
#define ERROR_SUCCESS                           0x9000

/**********************************************************************************/

struct frame {
	size_t size;
	uint8_t *data;
};

struct u2f_proto {
	struct frame challenge;
	struct frame appid;
	struct frame keyhandle;
	struct frame version;
	struct frame publickey;
	struct frame certificate;
	struct frame signature;
	struct frame signedpart;
	struct frame short_req;
	struct frame exted_req;
	unsigned refcount;
	uint32_t counter;
	uint16_t status;
	uint8_t ins;
	uint8_t p1;
	uint8_t p2;
	uint8_t userpresence;
};

/**********************************************************************************/

static uint8_t *frame_alloc(struct frame *fr, size_t size)
{
	uint8_t *p = realloc(fr->data, size);
	if (p) {
		fr->data = p;
		fr->size = size;
	}
	return p;
}

static int frame_set(struct frame *fr, const uint8_t *buffer, size_t size)
{
	uint8_t *p = frame_alloc(fr, size);
	if (!p)
		return -ENOMEM;
	memcpy(p, buffer, size);
	return 0;
}

static void frame_free(struct frame *fr)
{
	free(fr->data);
	fr->data = NULL;
	fr->size = 0;
}

/**********************************************************************************/

static int makereq(struct u2f_proto *proto, int extended)
{
	size_t lresp, lreq, size;
	struct frame *challenge, *appid, *keyhandle;
	uint8_t *d;

	switch(proto->ins) {
	case U2F_REGISTER:
		challenge = &proto->challenge;
		appid = &proto->appid;
		keyhandle = NULL;
		lreq = challenge->size + appid->size;
		lresp = sizeof(U2F_REGISTER_RESP);
		break;

	case U2F_AUTHENTICATE:
		challenge = &proto->challenge;
		appid = &proto->appid;
		keyhandle = &proto->keyhandle;
		lreq = challenge->size + appid->size + keyhandle->size + 1;
		lresp = sizeof(U2F_AUTHENTICATE_RESP);
		break;

	case U2F_VERSION:
		challenge = appid = keyhandle = NULL;
		lreq = 0;
		lresp = 65536;
		break;

	default:
		return -EINVAL;
	}

	if (challenge && challenge->size != U2F_CHAL_SIZE)
		return -EINVAL;
	if (appid && appid->size != U2F_APPID_SIZE)
		return -EINVAL;

	if (extended) {
		if (lreq > 65535 || lresp > 65536)
			return -EINVAL;
		size = 4 + lreq + (size_t)(3*(lreq || lresp) + 2*(lreq && lresp));
	} else {
		if (lreq > 255 || lresp > 256)
			return -EINVAL;
		size = 4 + lreq + !!lreq + !!lresp;
	}

	d = frame_alloc(extended ? &proto->exted_req : &proto->short_req, size);
	if (!d)
		return -ENOMEM;

	*d++ = 0;
	*d++ = proto->ins;
	*d++ = proto->p1;
	*d++ = proto->p2;
	if (lreq) {
		if (extended) {
			*d++ = 0;
			*d++ = (uint8_t)(lreq >> 8);
		}
		*d++ = (uint8_t)lreq;
		d = mempcpy(d, challenge->data, challenge->size);
		d = mempcpy(d, appid->data, appid->size);
		if (keyhandle) {
			*d++ = (uint8_t)keyhandle->size;
			d = mempcpy(d, keyhandle->data, keyhandle->size);
		}
	}
	if (lresp) {
		if (extended) {
			if (!lreq)
				*d++ = 0;
			*d++ = (uint8_t)(lresp >> 8);
		}
		*d = (uint8_t)lresp;
	}

	return 0;
}

static void cancelreq(struct u2f_proto *proto)
{
	frame_free(&proto->short_req);
	frame_free(&proto->exted_req);
}

static int set_oper(struct u2f_proto *proto, uint8_t ins, uint8_t p1, uint8_t p2)
{
	proto->ins = ins;
	proto->p1 = p1;
	proto->p2 = p2;
	cancelreq(proto);
	return 0;
}

static size_t get_DER_length(const uint8_t *buffer, size_t size)
{
	size_t index = 0, x;
	uint8_t i;

	if (index < size && (buffer[index++] & 31) == 31) {
		while(index < size && (buffer[index++] & 128) != 0);
	}
	if (index < size) {
		i = buffer[index++];
		if (i <= 127) {
			index += i;
		} else if (i == 128) {
			while (index + 1 < size && (buffer[index] || buffer[index + 1]))
				index++;
			if (index + 1 < size)
				index += 2;
			else
				index = size;
		} else {
			i &= 127;
			x = buffer[index++];
			while(--i)
				x = (x << 8) | buffer[index++];
			index += x;
		}
	}
	return index;
}

static int putreply(struct u2f_proto *proto, const uint8_t *buffer, size_t size)
{
	int rc;
	size_t len, index;
	uint8_t *b;

	/* At least 2 status bytes are expected */
	if (size < 2) {
		proto->status = 1;
		return -EINVAL;
	}

	/* get the status */
	size -= 2;
	proto->status = (uint16_t)((((uint16_t)buffer[size]) << 8) | ((uint16_t)buffer[size + 1]));

	switch(proto->ins) {
	case U2F_REGISTER:
		index = 0;
		if (size < 1 || buffer[index] != 5) {
			rc = -EINVAL;
			break;
		}
		index++;
		if (size < index + sizeof(U2F_EC_POINT)) {
			rc = -EINVAL;
			break;
		}
		rc = frame_set(&proto->publickey, &buffer[1], sizeof(U2F_EC_POINT));
		if (rc < 0)
			break;
		index += sizeof(U2F_EC_POINT);
		len = buffer[index];
		if (size < index + len) {
			rc = -EINVAL;
			break;
		}
		index++;
		rc = frame_set(&proto->keyhandle, &buffer[index], len);
		if (rc < 0)
			break;
		index += len;
		len = get_DER_length(&buffer[index], size - index);
		if (size < index + len) {
			rc = -EINVAL;
			break;
		}
		rc = frame_set(&proto->certificate, &buffer[index], len);
		if (rc < 0)
			break;
		index += len;
		rc = frame_set(&proto->signature, &buffer[index], size - index);
		if (rc < 0)
			break;

		b = frame_alloc(&proto->signedpart, 1 + proto->appid.size + proto->challenge.size + proto->keyhandle.size + proto->publickey.size);
		if (!b) {
			rc = -ENOMEM;
			break;
		}
		*b++ = 0;
		b = mempcpy(b, proto->appid.data, proto->appid.size);
		b = mempcpy(b, proto->challenge.data, proto->challenge.size);
		b = mempcpy(b, proto->keyhandle.data, proto->keyhandle.size);
		b = mempcpy(b, proto->publickey.data, proto->publickey.size);
		break;

	case U2F_AUTHENTICATE:
		index = 0;
		if (size < 1) {
			rc = -EINVAL;
			break;
		}
		proto->userpresence = buffer[index++];
		if (size < index + 4) {
			rc = -EINVAL;
			break;
		}
		proto->counter = (((uint32_t)buffer[index]) << 24)
		               | (((uint32_t)buffer[index + 1]) << 16)
		               | (((uint32_t)buffer[index + 2]) << 8)
		               |  ((uint32_t)buffer[index + 3]);
		index += 4;
		rc = frame_set(&proto->signature, &buffer[index], size - index);
		if (rc < 0)
			break;

		b = frame_alloc(&proto->signedpart, proto->appid.size + 1 + 4 + proto->challenge.size);
		if (!b) {
			rc = -ENOMEM;
			break;
		}
		b = mempcpy(b, proto->appid.data, proto->appid.size);
		*b++ = proto->userpresence;
		*b++ = (uint8_t)((proto->counter >> 24) & 255);
		*b++ = (uint8_t)((proto->counter >> 16) & 255);
		*b++ = (uint8_t)((proto->counter >> 8) & 255);
		*b++ = (uint8_t)(proto->counter & 255);
		b = mempcpy(b, proto->challenge.data, proto->challenge.size);
		break;

	case U2F_VERSION:
		rc = frame_set(&proto->version, buffer, size);
		break;

	default:
		return -EINVAL;
	}

	return rc;
}

static int get(struct frame *fr, const uint8_t **buffer, size_t *size)
{
	if (buffer)
		*buffer = fr->data;
	if (size)
		*size = fr->size;
	return !!fr->size;
}

/**********************************************************************************/

int u2f_protocol_new(struct u2f_proto **proto)
{
	struct u2f_proto *t = calloc(1, sizeof *t);
	if (!t)
		return -ENOMEM;
	t->refcount = 1;
	*proto = t;
	return 0;
}

struct u2f_proto *u2f_protocol_addref(struct u2f_proto *proto)
{
	if (proto)
		proto->refcount++;
	return proto;
}

void u2f_protocol_unref(struct u2f_proto *proto)
{
	if (proto && !--proto->refcount) {
		frame_free(&proto->challenge);
		frame_free(&proto->appid);
		frame_free(&proto->keyhandle);
		frame_free(&proto->version);
		frame_free(&proto->publickey);
		frame_free(&proto->certificate);
		frame_free(&proto->signature);
		frame_free(&proto->signedpart);
		frame_free(&proto->short_req);
		frame_free(&proto->exted_req);
		free(proto);
	}
}

size_t u2f_protocol_get_challenge_size()
{
	return U2F_CHAL_SIZE;
}

size_t u2f_protocol_get_appid_size()
{
	return U2F_APPID_SIZE;
}

size_t u2f_protocol_get_publickey_size()
{
	return U2F_EC_POINT_SIZE;
}

size_t u2f_protocol_get_keyhandle_max_size()
{
	return U2F_MAX_KH_SIZE;
}

int u2f_protocol_set_challenge(struct u2f_proto *proto, uint8_t *challenge, size_t size)
{
	if (size != U2F_CHAL_SIZE)
		return -EINVAL;
	cancelreq(proto);
	return frame_set(&proto->challenge, challenge, size);
}

int u2f_protocol_set_appid(struct u2f_proto *proto, uint8_t *appid, size_t size)
{
	if (size != U2F_APPID_SIZE)
		return -EINVAL;
	return frame_set(&proto->appid, appid, size);
}

int u2f_protocol_set_publickey(struct u2f_proto *proto, uint8_t *publickey, size_t size)
{
	if (size > U2F_EC_POINT_SIZE)
		return -EINVAL;
	return frame_set(&proto->publickey, publickey, size);
}

int u2f_protocol_set_keyhandle(struct u2f_proto *proto, uint8_t *keyhandle, size_t size)
{
	if (size > U2F_MAX_KH_SIZE)
		return -EINVAL;
	cancelreq(proto);
	return frame_set(&proto->keyhandle, keyhandle, size);
}

int u2f_protocol_set_register(struct u2f_proto *proto)
{
	return set_oper(proto, U2F_REGISTER, 0, 0);
}

int u2f_protocol_set_authenticate(struct u2f_proto *proto, int presence)
{
	return set_oper(proto, U2F_AUTHENTICATE, presence ? U2F_AUTH_ENFORCE : U2F_AUTH_CHECK_ONLY, 0);
}

int u2f_protocol_set_authenticate_check(struct u2f_proto *proto)
{
	return set_oper(proto, U2F_AUTHENTICATE, U2F_AUTH_CHECK_ONLY, 0);
}

int u2f_protocol_set_authenticate_sign(struct u2f_proto *proto)
{
	return set_oper(proto, U2F_AUTHENTICATE, U2F_AUTH_ENFORCE, 0);
}

int u2f_protocol_set_get_version(struct u2f_proto *proto)
{
	return set_oper(proto, U2F_VERSION, 0, 0);
}

int u2f_protocol_get_extended_request(struct u2f_proto *proto, const uint8_t **buffer, size_t *size)
{
	int rc;

	if (!proto->exted_req.data) {
		rc = makereq(proto, 1);
		if (rc < 0)
			return rc;
	}

	get(&proto->exted_req, buffer, size);
	return 0;
}

int u2f_protocol_put_extended_reply(struct u2f_proto *proto, const uint8_t *buffer, size_t size)
{
	return putreply(proto, buffer, size);
}

int u2f_protocol_put_error_status(struct u2f_proto *proto, uint16_t status)
{
	if (!status)
		return -EINVAL;
	
	proto->status = status;
	return 0;
}

int u2f_protocol_get_challenge(struct u2f_proto *proto, const uint8_t **buffer, size_t *size)
{
	return get(&proto->challenge, buffer, size);
}

int u2f_protocol_get_appid(struct u2f_proto *proto, const uint8_t **buffer, size_t *size)
{
	return get(&proto->appid, buffer, size);
}

int u2f_protocol_get_keyhandle(struct u2f_proto *proto, const uint8_t **buffer, size_t *size)
{
	return get(&proto->keyhandle, buffer, size);
}

int u2f_protocol_get_version(struct u2f_proto *proto, const uint8_t **buffer, size_t *size)
{
	return get(&proto->version, buffer, size);
}

int u2f_protocol_get_publickey(struct u2f_proto *proto, const uint8_t **buffer, size_t *size)
{
	return get(&proto->publickey, buffer, size);
}

int u2f_protocol_get_certificate(struct u2f_proto *proto, const uint8_t **buffer, size_t *size)
{
	return get(&proto->certificate, buffer, size);
}

int u2f_protocol_get_signature(struct u2f_proto *proto, const uint8_t **buffer, size_t *size)
{
	return get(&proto->signature, buffer, size);
}

int u2f_protocol_get_signedpart(struct u2f_proto *proto, const uint8_t **buffer, size_t *size)
{
	return get(&proto->signedpart, buffer, size);
}

uint16_t u2f_protocol_get_status(struct u2f_proto *proto)
{
	return proto->status;
}

int u2f_protocol_get_userpresence(struct u2f_proto *proto)
{
	return proto->userpresence & 1;
}

uint32_t u2f_protocol_get_counter(struct u2f_proto *proto)
{
	return proto->counter;
}

