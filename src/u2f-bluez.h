
#pragma once

#include <systemd/sd-bus.h>

struct u2f_proto;

extern int u2f_bluez_init(sd_bus *bus);

extern int u2f_bluez_scan_start(void (*callback)(const char *address));
extern int u2f_bluez_scan_stop();

extern int u2f_bluez_is_paired(const char *address);
extern int u2f_bluez_send_message(const char *address, struct u2f_proto *msg, void (*callback)(void *closure, int status, struct u2f_proto *msg), void *closure);
