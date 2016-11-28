#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>

#include <systemd/sd-bus.h>
#include <systemd/sd-event.h>


#include "u2f-protocol.h"
#include "u2f-bluez.h"

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


static void on_found_u2f_bluez_device(const char *address);

static void test_register_cb(void *closure, int status, struct u2f_proto *proto)
{
	u2f_bluez_scan_stop();
	u2f_bluez_scan_start(on_found_u2f_bluez_device);
}

int test_register(const char *buezaddr, const char *challenge, const char *appid)
{
	int rc;
	struct u2f_proto *t = 0;
	size_t chasz;
	size_t appsz;
	uint8_t *cha = 0;
	uint8_t *app = 0;

	rc = u2f_protocol_new(&t);
	CRC(end);

	rc = a2b(challenge, &cha, &chasz);
	CRC(end);

	rc = u2f_protocol_set_challenge(t, cha, chasz);
	CRC(end);

	rc = a2b(appid, &app, &appsz);
	CRC(end);

	rc = u2f_protocol_set_appid(t, app, appsz);
	CRC(end);

	rc = u2f_protocol_set_register(t);
	CRC(end);

	rc = u2f_bluez_is_paired(buezaddr);
	CRC(end);

	if (!rc)
		printf("THE DEVICE %s MUST BE PAIRED\n", buezaddr);

	rc = u2f_bluez_send_message(buezaddr, t, test_register_cb, (void*)buezaddr);
	CRC(end);
	
end:
	u2f_protocol_unref(t);
	free(app);
	free(cha);
	return rc;
}	

static void on_found_u2f_bluez_device(const char *address)
{
	printf("\n       signaling %s\n", address);

	test_register(address, ex1, ex2);

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

	rc = u2f_bluez_scan_start(on_found_u2f_bluez_device);
	if (rc < 0) {
		ERROR("scanning of bluez devices failed: %s", strerror(-rc));
		return 1;
	}

	/* wait forever */
	sd_event_loop(e);
	return 0;
}

