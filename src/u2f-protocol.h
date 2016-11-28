
#pragma once

struct u2f_proto;

extern int u2f_protocol_new(struct u2f_proto **proto);
extern struct u2f_proto *u2f_protocol_addref(struct u2f_proto *proto);
extern void u2f_protocol_unref(struct u2f_proto *proto);

extern void u2f_protocol_set_callback(struct u2f_proto *proto, void (*callback)(void *closure, struct u2f_proto *proto), void *closure);
extern size_t u2f_protocol_get_challenge_size();
extern size_t u2f_protocol_get_appid_size();
extern size_t u2f_protocol_get_keyhandle_max_size();

extern int u2f_protocol_set_challenge(struct u2f_proto *proto, uint8_t *challenge, size_t size);
extern int u2f_protocol_set_appid(struct u2f_proto *proto, uint8_t *appid, size_t size);
extern int u2f_protocol_set_keyhandle(struct u2f_proto *proto, uint8_t *keyhandle, size_t size);
extern int u2f_protocol_set_register(struct u2f_proto *proto);
extern int u2f_protocol_set_authenticate(struct u2f_proto *proto, int presence);
extern int u2f_protocol_set_authenticate_check(struct u2f_proto *proto);
extern int u2f_protocol_set_authenticate_sign(struct u2f_proto *proto);
extern int u2f_protocol_set_get_version(struct u2f_proto *proto);

extern int u2f_protocol_get_extended_request(struct u2f_proto *proto, const uint8_t **buffer, size_t *size);
extern int u2f_protocol_put_extended_reply(struct u2f_proto *proto, const uint8_t *buffer, size_t size);

