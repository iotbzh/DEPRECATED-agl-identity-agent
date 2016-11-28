#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>

#include "u2f.h"
#include "u2f-protocol.h"

/**********************************************************************************/

enum kind {
	None,
	Challenge,
	Appid,
	Keyhandle,
	Raw
};

struct frame {
	struct frame *next;
	size_t size;
	enum kind kind;
	uint8_t data[1];
};

enum state {
	Idle
};

struct u2f_proto {
	unsigned refcount;
	uint8_t ins;
	uint8_t p1;
	uint8_t p2;
	struct frame *arguments;
	struct frame *short_req;
	struct frame *exted_req;
	struct frame *results;
	void (*callback)(void *closure, struct u2f_proto *proto);
	void *closure;
};

/**********************************************************************************/

static struct frame *frame_alloc(size_t size, enum kind kind)
{
	struct frame *p;

	p = malloc(sizeof(*p) + size - 1);
	if (!p)
		errno = ENOMEM;
	else {
		p->next = 0;
		p->size = size;
		p->kind = kind;
	}
	return p;
}

static void frame_free(struct frame *p)
{
	struct frame *np;

	while (p) {
		np = p->next;
		free(p);
		p = np;
	}
}

static struct frame *frame_find(struct frame *p, enum kind kind)
{
	while (p && p->kind != kind)
		p = p->next;
	return p;
}

static int frame_set(struct frame **pp, enum kind kind, uint8_t *data, size_t size)
{
	struct frame *p;

	while ((p = *pp) && p->kind != kind)
		pp = &p->next;

	if (p && p->size != size) {
		*pp = p->next;
		free(p);
		p = 0;
	}
	if (!p) {
		p = frame_alloc(size, kind);
		if (!p)
			return -ENOMEM;
		p->next = *pp;
		*pp = p;
	}
	memcpy(p->data, data, size);
	return 0;
}

/**********************************************************************************/

static int makereq(struct u2f_proto *proto, int extended)
{
	size_t lresp, lreq, size;
	struct frame *challenge, *appid, *keyhandle, *raw;
	uint8_t *d;

	switch(proto->ins) {
	case U2F_REGISTER:
		challenge = frame_find(proto->arguments, Challenge);
		appid = frame_find(proto->arguments, Appid);
		if (!challenge || !appid)
			return -EINVAL;
		keyhandle = NULL;
		lreq = challenge->size + appid->size;
		lresp = sizeof(U2F_REGISTER_RESP);
		break;

	case U2F_AUTHENTICATE:
		challenge = frame_find(proto->arguments, Challenge);
		appid = frame_find(proto->arguments, Appid);
		keyhandle = frame_find(proto->arguments, Appid);
		if (!challenge || !appid || !keyhandle)
			return -EINVAL;
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

	if (extended) {
		if (lreq > 65535 || lresp > 65536)
			return -EINVAL;
		size = 4 + lreq + 3*(!!lreq + !!lresp);
	} else {
		if (lreq > 255 || lresp > 256)
			return -EINVAL;
		size = 4 + lreq + !!lreq + !!lresp;
	}

	raw = frame_alloc(size, Raw);
	if (!raw)
		return -ENOMEM;

	d = raw->data;
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
			*d++ = 0;
			*d++ = (uint8_t)(lresp >> 8);
		}
		*d = (uint8_t)lresp;
	}

	if (extended)
		proto->exted_req = raw;
	else
		proto->short_req = raw;

	return 0;
}

static void cancelreq(struct u2f_proto *proto)
{
	frame_free(proto->short_req);
	frame_free(proto->exted_req);
	proto->short_req = 0;
	proto->exted_req = 0;
}

static int set_oper(struct u2f_proto *proto, uint8_t ins, uint8_t p1, uint8_t p2)
{
	proto->ins = ins;
	proto->p1 = p1;
	proto->p2 = p2;
	cancelreq(proto);
	return 0;
}

static int putreply(struct u2f_proto *proto, const uint8_t *buffer, size_t size, int extended)
{
/*
	size_t lresp, lreq, size;
	struct frame *challenge, *appid, *keyhandle, *raw;
	uint8_t *d;

	switch(proto->ins) {
	case U2F_REGISTER:
		challenge = frame_find(proto->arguments, Challenge);
		appid = frame_find(proto->arguments, Appid);
		if (!challenge || !appid)
			return -EINVAL;
		keyhandle = NULL;
		lreq = challenge->size + appid->size;
		lresp = sizeof(U2F_REGISTER_RESP);
		break;

	case U2F_AUTHENTICATE:
		challenge = frame_find(proto->arguments, Challenge);
		appid = frame_find(proto->arguments, Appid);
		keyhandle = frame_find(proto->arguments, Appid);
		if (!challenge || !appid || !keyhandle)
			return -EINVAL;
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

	if (extended) {
		if (lreq > 65535 || lresp > 65536)
			return -EINVAL;
		size = 4 + lreq + 3*(!!lreq + !!lresp);
	} else {
		if (lreq > 255 || lresp > 256)
			return -EINVAL;
		size = 4 + lreq + !!lreq + !!lresp;
	}

	raw = frame_alloc(size, Raw);
	if (!raw)
		return -ENOMEM;

	d = raw->data;
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
			*d++ = 0;
			*d++ = (uint8_t)(lresp >> 8);
		}
		*d = (uint8_t)lresp;
	}

	if (extended)
		proto->exted_req = raw;
	else
		proto->short_req = raw;
*/
	return 0;
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
		frame_free(proto->arguments);
		frame_free(proto->short_req);
		frame_free(proto->exted_req);
		frame_free(proto->results);
		free(proto);
	}
}

void u2f_protocol_set_callback(struct u2f_proto *proto, void (*callback)(void *closure, struct u2f_proto *proto), void *closure)
{
	proto->callback = callback;
	proto->closure = closure;
}

size_t u2f_protocol_get_challenge_size()
{
	return U2F_CHAL_SIZE;
}

size_t u2f_protocol_get_appid_size()
{
	return U2F_APPID_SIZE;
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
	return frame_set(&proto->arguments, Challenge, challenge, size);
}

int u2f_protocol_set_appid(struct u2f_proto *proto, uint8_t *appid, size_t size)
{
	if (size != U2F_APPID_SIZE)
		return -EINVAL;
	return frame_set(&proto->arguments, Appid, appid, size);
}

int u2f_protocol_set_keyhandle(struct u2f_proto *proto, uint8_t *keyhandle, size_t size)
{
	if (size > U2F_MAX_KH_SIZE)
		return -EINVAL;
	cancelreq(proto);
	return frame_set(&proto->arguments, Keyhandle, keyhandle, size);
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

	if (!proto->exted_req) {
		rc = makereq(proto, 1);
		if (rc < 0)
			return rc;
	}

	if (buffer)
		*buffer = proto->exted_req->data;
	if (size)
		*size = proto->exted_req->size;
	return 0;
}

int u2f_protocol_put_extended_reply(struct u2f_proto *proto, const uint8_t *buffer, size_t size)
{
	return putreply(proto, buffer, size, 1);

}

