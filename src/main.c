#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>

#include <systemd/sd-bus.h>
#include <systemd/sd-event.h>


#include "u2f-protocol.h"
#include "u2f-bluez.h"
#include "u2f-bt.h"

#ifndef ERROR
#define ERROR(...)  (fprintf(stderr,"ERROR: ")|fprintf(stderr,__VA_ARGS__)|fprintf(stderr," (%s:%d)\n",__FILE__,__LINE__))
#endif

#define CIF(expr)   if((expr) ? (ERROR("%s",#expr), 1) : 0)
#define CRC(end)    do{CIF(rc<0)goto end;}while(0)


/* sha 256 of u2f.h */
static const char ex1[] = "e28b1383f0019effef8334e7f4c85d286bd2a93ab3165171ffe37cab274bee56";

/* sha 256 of u2f_hid.h */
static const char ex2[] = "48ff29eaba82f6e6a7b84fff1df83a8550b62d339fe5d0f143be24d8299bd79f";

int a2b(const char *a, uint8_t **b, size_t *l)
{
	char c;
	uint8_t *p, x;
	size_t n = strlen(a);

	if (n & 1)
		return -EINVAL;
	*b = p = malloc(*l = (n >> 1));
	if (!p)
		return -ENOMEM;
	while ((c = *a++)) {
		if (c >= '0' && c <= '9')
			x = (uint8_t)(c - '0');
		else if (c >= 'A' && c <= 'F')
			x = (uint8_t)(10 + c - 'A');
		else if (c >= 'a' && c <= 'f')
			x = (uint8_t)(10 + c - 'a');
		else
			return -EINVAL;
		x <<= 4;
		c = *a++;
		if (c >= '0' && c <= '9')
			x |= (uint8_t)(c - '0');
		else if (c >= 'A' && c <= 'F')
			x |= (uint8_t)(10 + c - 'A');
		else if (c >= 'a' && c <= 'f')
			x |= (uint8_t)(10 + c - 'a');
		else
			return -EINVAL;
		*p++ = x;
	}
	return 0;
}

int b2a(const uint8_t *b, size_t l, char **a)
{
	char c, *p;
	uint8_t x;

	if (l & 1)
		return -EINVAL;
	*a = p = malloc(1 + (l << 1));
	if (!p)
		return -ENOMEM;

	while(l) {
		x = *b++;
		c = '0' + (x >> 4);
		if (c > '9')
			c += 'a' - '0' - 10;
		*p++ = c;
		c = '0' + (x & 15);
		if (c > '9')
			c += 'a' - '0' - 10;
		*p++ = c;
		--l;
	}
	return 0;
}


static void on_found_u2f_bluez_device(struct u2f_bluez *device);

static void pbuf(const char *name, struct u2f_proto *proto, int (*gbuf)(struct u2f_proto*,const uint8_t**,size_t*))
{
	const uint8_t *b;
	size_t i, j, s;

	printf("buffer %s:", name);
	if (!gbuf(proto, &b, &s))
		printf("    <NOTHING>\n");
	else {
		for (i = 0 ; i < s ; i += 16) {
			printf("\n   %04x:", i);
			for (j = 0 ; j < 16 && i + j < s ; j++)
				printf(" %02x", b[i+j]);
			for (; j < 16 ; j++)
				printf("   ");
			printf("  ");
			for (j = 0 ; j < 16 && i + j < s ; j++)
				printf("%c", b[i+j]<32 || b[i+j]>126 ? '.' : b[i+j]);
		}
		printf("\n");
	}
}

static void dumpproto(const char *message, struct u2f_proto *proto)
{
	printf("\n========={ %s }============\n", message);
	printf("Status: %d  %x\n", (int)u2f_protocol_get_status(proto), (int)u2f_protocol_get_status(proto));
	printf("Presence: %d\n", (int)u2f_protocol_get_userpresence(proto));
	printf("Counter: %u\n", (unsigned)u2f_protocol_get_counter(proto));
	pbuf("challenge", proto, u2f_protocol_get_challenge);
	pbuf("appid", proto, u2f_protocol_get_appid);
	pbuf("keyhandle", proto, u2f_protocol_get_keyhandle);
	pbuf("version", proto, u2f_protocol_get_version);
	pbuf("publickey", proto, u2f_protocol_get_publickey);
	pbuf("certificate", proto, u2f_protocol_get_certificate);
	pbuf("signature", proto, u2f_protocol_get_signature);
	pbuf("signedpart", proto, u2f_protocol_get_signedpart);
}

static void test_authorize_cb(void *closure, int status, struct u2f_proto *proto)
{
	struct u2f_bluez *device = closure;

	dumpproto("AFTER AUTHORIZE", proto);

}

static void test_register_cb(void *closure, int status, struct u2f_proto *proto)
{
	struct u2f_bluez *device = closure;

	dumpproto("AFTER REGISTER", proto);

	u2f_protocol_addref(proto);
	u2f_protocol_set_authenticate_check(proto);
	u2f_bt_message(device, proto, test_authorize_cb, (void*)device);
}

int test_register(struct u2f_bluez *device, const char *challenge, const char *appid)
{
	int rc;
	struct u2f_proto *proto = 0;
	size_t chasz;
	size_t appsz;
	uint8_t *cha = 0;
	uint8_t *app = 0;

	rc = u2f_protocol_new(&proto);
	CRC(end);

	rc = a2b(challenge, &cha, &chasz);
	CRC(end);

	rc = u2f_protocol_set_challenge(proto, cha, chasz);
	CRC(end);

	rc = a2b(appid, &app, &appsz);
	CRC(end);

	rc = u2f_protocol_set_appid(proto, app, appsz);
	CRC(end);

	rc = u2f_protocol_set_register(proto);
	CRC(end);

	if (!u2f_bluez_is_paired(device))
		printf("THE DEVICE %s MUST BE PAIRED\n", u2f_bluez_address(device));

	rc = u2f_bt_message(device, proto, test_register_cb, (void*)device);
	CRC(end);
	
end:
	u2f_protocol_unref(proto);
	free(app);
	free(cha);
	return rc;
}	

static void on_found_u2f_bluez_device(struct u2f_bluez *device)
{
	printf("\n       signaling %s\n", u2f_bluez_address(device));

	test_register(device, ex1, ex2);
}

int main(int ac, char **av)
{
	int rc;
	sd_event *e;
	sd_bus *bus;

	/* make the event loop */
	sd_event_default(&e);

	/* connect to the bus */
	rc = sd_bus_default_system(&bus);
	if (rc < 0) {
		ERROR("can't get system bus: %s", strerror(-rc));
		return 1;
	}
	sd_bus_attach_event(bus, e, 0);

	/* initialize the bluez backend */
	rc = u2f_bluez_init(bus);
	sd_bus_unref(bus);
	if (rc < 0) {
		ERROR("initialisation of bluez failed: %s", strerror(-rc));
		return 1;
	}

	rc = u2f_bluez_scan(on_found_u2f_bluez_device);
	if (rc < 0) {
		ERROR("scanning of bluez devices failed: %s", strerror(-rc));
		return 1;
	}

	/* wait forever */
	sd_event_loop(e);
	return 0;
}

/*
      83 00 49 00 01 00 00 00 00 40 e2 8b 13 83 f0 01 9e ff ef 83
      00 34 e7 f4 c8 5d 28 6b d2 a9 3a b3 16 51 71 ff e3 7c ab 27
      01 4b ee 56 48 ff 29 ea ba 82 f6 e6 a7 b8 4f ff 1d f8 3a 85
      02 50 b6 2d 33 9f e5 d0 f1 43 be 24 d8 29 9b d7 9f 09 0b
*/
