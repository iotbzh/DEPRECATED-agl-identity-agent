#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>

#include <systemd/sd-bus.h>
#include <systemd/sd-event.h>


#include "u2f.h"
#include "u2f-protocol.h"
#include "u2f-bluez.h"
#include "u2f-bt.h"
#include "u2f-crypto.h"

#ifndef ERROR
#define ERROR(...)  (fprintf(stderr,"ERROR: ")|fprintf(stderr,__VA_ARGS__)|fprintf(stderr," (%s:%d)\n",__FILE__,__LINE__))
#endif

#define CIF(expr)   if((expr) ? (ERROR("%s",#expr), 1) : 0)
#define CRC(end)    do{CIF(rc<0)goto end;}while(0)


/* sha 256 of u2f.h */
static const char ex_challenge[] = "e28b1383f0019effef8334e7f4c85d286bd2a93ab3165171ffe37cab274bee56";

/* sha 256 of u2f_hid.h */
static const char ex_appid[] = "48ff29eaba82f6e6a7b84fff1df83a8550b62d339fe5d0f143be24d8299bd79f";

struct keydesc
{
	const char *name;
	const char *address;
	const char *keyhandle;
	const char *publickey;
	const char *certificate;
};

enum { WHITE = 0, BLUE = 1, GREEN = 2 };

static const struct keydesc keys[] =
{
 {
  .name = "WHITE",
  .address = "EA:00:44:68:CF:35",
  .keyhandle =
     "7a5edece43a2f926e1ae8c8160e41f44"
     "e88f1b73e35b8dd43f94e84ed1d3022c"
     "a7494b4aee7f4e1a0b55d6e8ba50a8cf"
     "a607e8f9a474c3303db75bf22eff1812"
     "3a8b36506134d4807a467374da2438d1",
  .publickey =
     "045ecafd15595e5558b276af38dc3492"
     "fd0a6b76f9813bb75c1d48e330d4fd60"
     "1ee285667b13dd68211ff266545d1673"
     "e8e44eb7bdd0543553f6fed7486b6137"
     "47",
  .certificate =
     "308201ac30820153a003020102020478"
     "2a0eb9300a06082a8648ce3d04030230"
     "46311c301a060355040a131356415343"
     "4f204461746120536563757269747931"
     "2630240603550403131d564153434f20"
     "44494749504153532053656375726543"
     "6c69636b204341301e170d3136303232"
     "323038333930305a170d343130323232"
     "3038333930305a3053311c301a060355"
     "040a1313564153434f20446174612053"
     "65637572697479313330310603550403"
     "132a564153434f204449474950415353"
     "20536563757265436c69636b20417474"
     "6573746174696f6e204b657930593013"
     "06072a8648ce3d020106082a8648ce3d"
     "030107034200044612a220e578b34f6a"
     "891e23d65a9e896498011ea9be3029bc"
     "cf1a8fca465b176697af67e0d912386d"
     "4844df233c01e014bad9de9b3932614e"
     "65d94c21bfcc83a32230203009060355"
     "1d13040230003013060b2b0601040182"
     "e51c020101040403020560300a06082a"
     "8648ce3d04030203470030440220395e"
     "8b68c043a77c8fdc4c6ef9b1194d393b"
     "694ce5bf616ae944b0cb1c7bcc600220"
     "11ccd27a799710e4fe5b0a64c0cff32f"
     "eff505f79dc43d4753087937c317b105"
 },
 {
  .name = "BLUE",
  .address = "EB:7C:23:C6:21:BF",
  .keyhandle =
     "1b68af979b088cf0aedaf9d0484cc0cb"
     "f973a3c3ce3b0298820069a19ac62c1f"
     "f890e7ec5680526795488a098b30fd53"
     "3383b2e62c9d8553a608d2ec1570ee46"
     "40732b034c5abbad3ebda45877c3e497",
  .publickey =
     "04de27afe835c6fb029ca204c0e1311d"
     "6dac539cc5ce4dd763b6ad1b3f0e0700"
     "e548758916fe135f641d8a26ca3e6d76"
     "5f129519fcd9a2bc8f1bb7314944c327"
     "ee",
  .certificate =
     "308201ac30820153a003020102020478"
     "2a0eb9300a06082a8648ce3d04030230"
     "46311c301a060355040a131356415343"
     "4f204461746120536563757269747931"
     "2630240603550403131d564153434f20"
     "44494749504153532053656375726543"
     "6c69636b204341301e170d3136303232"
     "323038333930305a170d343130323232"
     "3038333930305a3053311c301a060355"
     "040a1313564153434f20446174612053"
     "65637572697479313330310603550403"
     "132a564153434f204449474950415353"
     "20536563757265436c69636b20417474"
     "6573746174696f6e204b657930593013"
     "06072a8648ce3d020106082a8648ce3d"
     "030107034200044612a220e578b34f6a"
     "891e23d65a9e896498011ea9be3029bc"
     "cf1a8fca465b176697af67e0d912386d"
     "4844df233c01e014bad9de9b3932614e"
     "65d94c21bfcc83a32230203009060355"
     "1d13040230003013060b2b0601040182"
     "e51c020101040403020560300a06082a"
     "8648ce3d04030203470030440220395e"
     "8b68c043a77c8fdc4c6ef9b1194d393b"
     "694ce5bf616ae944b0cb1c7bcc600220"
     "11ccd27a799710e4fe5b0a64c0cff32f"
     "eff505f79dc43d4753087937c317b105"
 },
 {
  .name = "GREEN",
  .address = "D2:D4:71:0D:B5:F1",
  .keyhandle =
     "f0be3781d4275ab50e6e3f192d169087"
     "7ba12ae6b2bc7305bc8c8cef3d200df2"
     "9910123ce72e4da6705c59866687e425"
     "00d491ee1a8d6cd4eac7c914222e2f7e"
     "b3df3d793ddd871cf4f822b2a256af7c",
  .publickey =
     "04721daea333609281306329878f46ee"
     "191970fd286d872dfa8c370395da8d24"
     "f1ed421363b536a84b36fada8a3619df"
     "3290ef9cc7eeec80fd5e990d2a5db172"
     "7b",
  .certificate =
     "308201ac30820153a003020102020478"
     "2a0eb9300a06082a8648ce3d04030230"
     "46311c301a060355040a131356415343"
     "4f204461746120536563757269747931"
     "2630240603550403131d564153434f20"
     "44494749504153532053656375726543"
     "6c69636b204341301e170d3136303232"
     "323038333930305a170d343130323232"
     "3038333930305a3053311c301a060355"
     "040a1313564153434f20446174612053"
     "65637572697479313330310603550403"
     "132a564153434f204449474950415353"
     "20536563757265436c69636b20417474"
     "6573746174696f6e204b657930593013"
     "06072a8648ce3d020106082a8648ce3d"
     "030107034200044612a220e578b34f6a"
     "891e23d65a9e896498011ea9be3029bc"
     "cf1a8fca465b176697af67e0d912386d"
     "4844df233c01e014bad9de9b3932614e"
     "65d94c21bfcc83a32230203009060355"
     "1d13040230003013060b2b0601040182"
     "e51c020101040403020560300a06082a"
     "8648ce3d04030203470030440220395e"
     "8b68c043a77c8fdc4c6ef9b1194d393b"
     "694ce5bf616ae944b0cb1c7bcc600220"
     "11ccd27a799710e4fe5b0a64c0cff32f"
     "eff505f79dc43d4753087937c317b105"
 }
};


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
	printf("\n=========\n\n");
}

static void test_authenticate_cb(void *closure, int status, struct u2f_proto *proto)
{
	struct u2f_bluez *device = closure;
	int rc;

	dumpproto("AFTER AUTHORIZE", proto);

	if (u2f_protocol_get_status(proto) == U2F_SW_NO_ERROR) {
		rc = u2f_crypto_verify(proto);
		printf("!!!!! crypto resolution: %d   !!!!!\n\n\n", rc);
	}
}

int test_authenticate(struct u2f_bluez *device, const char *challenge, const char *appid, const char *keyhandle, const char *point)
{
	int rc;
	struct u2f_proto *proto = 0;
	size_t chasz;
	size_t appsz;
	size_t khsz;
	size_t ptsz;
	uint8_t *cha = 0;
	uint8_t *app = 0;
	uint8_t *kh = 0;
	uint8_t *pt = 0;

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

	rc = a2b(keyhandle, &kh, &khsz);
	CRC(end);

	rc = u2f_protocol_set_keyhandle(proto, kh, khsz);
	CRC(end);

	rc = a2b(point, &pt, &ptsz);
	CRC(end);

	rc = u2f_protocol_set_publickey(proto, pt, ptsz);
	CRC(end);

	rc = u2f_protocol_set_authenticate(proto, 1);
	CRC(end);

	if (!u2f_bluez_is_paired(device))
		printf("THE DEVICE %s MUST BE PAIRED\n", u2f_bluez_address(device));

	rc = u2f_bt_message(device, proto, test_authenticate_cb, (void*)device);
	CRC(end);

end:
	u2f_protocol_unref(proto);
	free(app);
	free(cha);
	free(kh);
	free(pt);
	return rc;
}	

static void test_register_cb(void *closure, int status, struct u2f_proto *proto)
{
	struct u2f_bluez *device = closure;
	int rc;

	dumpproto("AFTER REGISTER", proto);

	if (u2f_protocol_get_status(proto) == U2F_SW_NO_ERROR) {
		rc = u2f_crypto_verify(proto);
		printf("!!!!! crypto resolution: %d   !!!!!\n\n\n", rc);
	}
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
	int i;

	printf("\n       signaling %s\n", u2f_bluez_address(device));

#if 0
	test_register(device, ex_challenge, ex_appid);
#else
	i = (int)(sizeof keys / sizeof *keys) - 1;
	while(i && strcasecmp(keys[i].address, u2f_bluez_address(device)))
		i--;
	test_authenticate(device, ex_challenge, ex_appid, keys[i].keyhandle, keys[WHITE].publickey);
#endif
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

	u2f_bluez_scan(on_found_u2f_bluez_device);

	/* wait forever */
	sd_event_loop(e);
	return 0;
}

