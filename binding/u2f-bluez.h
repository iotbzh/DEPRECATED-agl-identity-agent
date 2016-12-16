
#pragma once

#include <systemd/sd-bus.h>

struct u2f_bluez;

extern int u2f_bluez_init(sd_bus *bus);
extern int u2f_bluez_scan(void (*callback)(struct u2f_bluez *device));

extern void u2f_bluez_unref(struct u2f_bluez *device);
extern struct u2f_bluez *u2f_bluez_addref(struct u2f_bluez *device);

extern int u2f_bluez_get(struct u2f_bluez **device, const char *address);
extern const char *u2f_bluez_address(struct u2f_bluez *device);
extern int u2f_bluez_is_paired(struct u2f_bluez *device);
extern int u2f_bluez_is_connected(struct u2f_bluez *device);

struct u2f_bluez_observer
{
	void (*connected)(void *closure);
	void (*started)(void *closure, size_t mtu);
	void (*received)(void *closure, const uint8_t *buffer, size_t size);
	void (*sent)(void *closure);
	void (*stopped)(void *closure);
	void (*disconnected)(void *closure);
	void (*error)(void *closure, int error, const char *message);
};

extern int u2f_bluez_observer_add(struct u2f_bluez *device, struct u2f_bluez_observer *observer, void *closure);
extern int u2f_bluez_observer_delete(struct u2f_bluez *device, struct u2f_bluez_observer *observer, void *closure);

extern void u2f_bluez_connect(struct u2f_bluez *device);
extern void u2f_bluez_start(struct u2f_bluez *device);
extern void u2f_bluez_stop(struct u2f_bluez *device);
extern void u2f_bluez_disconnect(struct u2f_bluez *device);
extern void u2f_bluez_send(struct u2f_bluez *device, const uint8_t *buffer, size_t size);

