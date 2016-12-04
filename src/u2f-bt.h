
#pragma once

struct u2f_bluez;
struct u2f_protocol;
struct u2f_bt;

extern int u2f_bt_create(struct u2f_bt **p, struct u2f_bluez *device);
extern int u2f_bt_create_address(struct u2f_bt **p, const char *address);
extern struct u2f_bt *u2f_bt_addref(struct u2f_bt *bt);
extern void u2f_bt_unref(struct u2f_bt *bt);
extern void u2f_bt_set_callback(struct u2f_bt *bt, void (*callback)(void *closure, int status, const uint8_t *buffer, size_t size), void *closure);
extern int u2f_bt_send(struct u2f_bt *bt, uint8_t cmd, const uint8_t *data, size_t size);

extern int u2f_bt_message(struct u2f_bluez *device, struct u2f_proto *msg, void (*callback)(void *closure, int status, struct u2f_proto *msg), void *closure);
