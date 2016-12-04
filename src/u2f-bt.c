#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

#include <time.h>

#include "u2f-protocol.h"
#include "u2f-bluez.h"
#include "u2f-bt.h"

#ifndef ERROR
#define ERROR(...)  (fprintf(stderr,"ERROR: "),fprintf(stderr,__VA_ARGS__),fprintf(stderr," (%s:%d)\n",__FILE__,__LINE__),1)
#endif

#define U2F_BT_PING      0x81
#define U2F_BT_KEEPALIVE 0x82
#define U2F_BT_MSG       0x83
#define U2F_BT_ERROR     0xbf

/********************************************************************************************************/

struct buffer
{
	uint8_t *data;
	size_t size;
	size_t offset;
	uint8_t counter;
	uint8_t head;
};


enum u2f_bt_state
{
	Idle,
	Connecting,
	Dialing,
	Disconnecting
};


struct u2f_bt
{
	unsigned refcount;
	struct u2f_bluez *device;
	enum u2f_bt_state state;
	size_t mtu;
	size_t sent;
	struct buffer write;
	struct buffer read;
	const char *errmsg;
	void (*callback)(void *closure, int status, const uint8_t *buffer, size_t size);
	void *closure;
};

/********************************************************************************************************/

static int buffer_make(struct buffer *buffer, const uint8_t *data, size_t size, uint8_t head)
{
	uint8_t *p = realloc(buffer->data, size);
	if (!p)
		return -ENOMEM;
	buffer->data = p;
	buffer->size = size;
	buffer->head = head;
	buffer->offset = 0;
	buffer->counter = 0;
	if (data)
		memcpy(p, data, size);
	return 0;
}

/********************************************************************************************************/

static void try_send(struct u2f_bt *bt)
{
	uint8_t *frame;
	size_t offset, size, remain, mtu, head, len;

	offset = bt->write.offset;
	size = bt->write.size;
	remain = size - offset;
	if (remain) {
		mtu = bt->mtu;
		frame = alloca(bt->mtu);
		if (offset) {
			frame[0] = (bt->write.counter++) & 0x7f;
			head = 1;
		} else {
			frame[0] = bt->write.head;
			frame[1] = (uint8_t)(size >> 8);
			frame[2] = (uint8_t)(size);
			head = 3;
		}
		len = mtu - head;
		if (len > remain)
			len = remain;
		memcpy(&frame[head], &bt->write.data[offset], len);
		bt->sent = len;
		u2f_bluez_send(bt->device, frame, len + head);
	}
}

static void set_error(struct u2f_bt *bt, int error, const char *message)
{
printf("got error: %d, %s\n", error, message);

	if (bt->state != Idle) {
		bt->errmsg = message;
		bt->state = Idle;
		bt->callback(bt->closure, error, message, message ? strlen(message) : 0);
	}
}

static void on_connected(void *closure, size_t mtu)
{
	struct u2f_bt *bt = closure;

printf("on_connected\n");
	bt->mtu = mtu;
	if (bt->state == Connecting) {
		bt->state = Dialing;
		try_send(bt);
	}
}

static void on_disconnected(void *closure)
{
	struct u2f_bt *bt = closure;

printf("on_disconnected\n");
	bt->state = Idle;
}

static void on_received(void *closure, const uint8_t *frame, size_t framesize)
{
	int rc;
	size_t size, offset;
	struct u2f_bt *bt = closure;

printf("on_received\n");
	offset = bt->read.offset;
	if (offset == 0) {
		if (framesize < 3) {
			set_error(bt, -EINVAL, "first frame should be of at least 3 bytes");
			return;
		}

		size = (((size_t)frame[1]) << 8) | (size_t)frame[2];

		rc = buffer_make(&bt->read, NULL, size, frame[0]);
		if (rc < 0) {
			set_error(bt, rc, "allocation failed for received bytes");
			return;
		}

		frame += 3;
		framesize -= 3;
	} else {
		if (framesize < 2) {
			set_error(bt, -EINVAL, "next frames should be of at least 2 bytes");
			return;
		}

		if (frame[0] != bt->read.counter) {
			set_error(bt, -EINVAL, "invalid frame sequence detected");
			return;
		}

		bt->read.counter = (bt->read.counter + 1) & 0x7f;
		size = bt->read.size;
		frame += 1;
		framesize -= 1;
	}

	/* check remaining size */
	if (offset + framesize > size) {
		set_error(bt, -EINVAL, "received size mismatch (overflow)");
		return;
	}

	memcpy(&bt->read.data[offset], frame, framesize);
	offset += framesize;
	bt->read.offset = offset;

	if (offset == size) {
		bt->state = Idle;
		bt->callback(bt->closure, bt->read.head, bt->read.data, bt->read.size);
	}
}

static void on_sent(void *closure)
{
	struct u2f_bt *bt = closure;

printf("on_sent\n");
	bt->write.offset += bt->sent;
	bt->sent = 0;
	try_send(bt);
}

static void on_error(void *closure, int error, const char *message)
{
	struct u2f_bt *bt = closure;
printf("on_error\n");
	set_error(bt, error, message);
}

/********************************************************************************************************/

static struct u2f_bluez_observer bt_callbacks =
{
	.connected = on_connected,
	.disconnected = on_disconnected,
	.received = on_received,
	.sent = on_sent,
	.error = on_error
};

static int set_observe_on(struct u2f_bt *bt)
{
	return u2f_bluez_observer_add(bt->device, &bt_callbacks, bt);
}

static void set_observe_off(struct u2f_bt *bt)
{
	u2f_bluez_observer_delete(bt->device, &bt_callbacks, bt);
}

/********************************************************************************************************/

int u2f_bt_create(struct u2f_bt **p, struct u2f_bluez *device)
{
	int rc;
	struct u2f_bt *bt;

	bt = calloc(1, sizeof *bt);
	if (!bt) {
		u2f_bluez_unref(device);
		return -ENOMEM;
	}

	bt->device = device;
	bt->refcount = 1;
	bt->state = Idle;
	rc = u2f_bluez_observer_add(bt->device, &bt_callbacks, bt);
	if (rc == 0)
		*p = bt;
	else {
		free(bt);
		u2f_bluez_unref(device);
	}
	return rc;
}

int u2f_bt_create_address(struct u2f_bt **p, const char *address)
{
	int rc;
	struct u2f_bluez *device;
	struct u2f_bt *bt;

	rc = u2f_bluez_get(&device, address);
	if (rc == 0)
		rc = u2f_bt_create(p, device);
	return rc;
}

struct u2f_bt *u2f_bt_addref(struct u2f_bt *bt)
{
	if (bt)
		bt->refcount++;
	return bt;
}

void u2f_bt_unref(struct u2f_bt *bt)
{
	if (bt && !--bt->refcount) {
		u2f_bluez_unref(bt->device);
		free(bt->write.data);
		free(bt->read.data);
	}
}

void u2f_bt_set_callback(struct u2f_bt *bt, void (*callback)(void *closure, int status, const uint8_t *buffer, size_t size), void *closure)
{
	bt->callback = callback;
	bt->closure = closure;
}

int u2f_bt_send(struct u2f_bt *bt, uint8_t cmd, const uint8_t *data, size_t size)
{
	int rc;

	if (bt->state != Idle)
		return -EINVAL;

	rc = buffer_make(&bt->write, data, size, cmd);
	if (rc < 0)
		return rc;

	bt->state = Connecting;
	u2f_bluez_connect(bt->device);
	return 0;
}

/********************************************************************************************************/

struct message {
	struct u2f_proto *message;
	struct u2f_bt *bt;
	void (*callback)(void *closure, int status, struct u2f_proto *msg);
	void *closure;
};

static void message_complete(void *closure, int status, const uint8_t *buffer, size_t size)
{
	int rc;
	struct message *sending = closure;
	if (status == U2F_BT_MSG) {
		rc = u2f_protocol_put_extended_reply(sending->message, buffer, size);
	} else {
		rc = u2f_protocol_put_error_status(sending->message, 0x1234);
		rc = status < 0 ? status : -EACCES;
	}
	sending->callback(sending->closure, rc, sending->message);
	u2f_protocol_unref(sending->message);
	free(sending);
}

int u2f_bt_message(struct u2f_bluez *device, struct u2f_proto *msg, void (*callback)(void *closure, int status, struct u2f_proto *msg), void *closure)
{
	int rc;
	struct message *sending = 0;
	const uint8_t *buffer;
	size_t size;

	sending = calloc(1, sizeof *sending);
	if (!sending)
		return -ENOMEM;

	sending->message = u2f_protocol_addref(msg);
	sending->callback = callback;
	sending->closure = closure;

	rc = u2f_bt_create(&sending->bt, device);
	if (rc < 0)
		goto error;

	u2f_bt_set_callback(sending->bt, message_complete, sending);

	rc = u2f_protocol_get_extended_request(msg, &buffer, &size);
	if (rc < 0)
		goto error;

	rc = u2f_bt_send(sending->bt, U2F_BT_MSG, buffer, size);
	if (rc < 0)
		goto error;

	return 0;

error:
	if (sending) {
		u2f_bt_unref(sending->bt);
		u2f_protocol_unref(sending->message);
		free(sending);
	}
	return rc;
}



