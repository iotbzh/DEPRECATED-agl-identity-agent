/*
 * Copyright (C) 2015, 2016 "IoT.bzh"
 * Author: José Bollo <jose.bollo@iot.bzh>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
extern int u2f_protocol_set_publickey(struct u2f_proto *proto, uint8_t *publickey, size_t size);
extern int u2f_protocol_set_register(struct u2f_proto *proto);
extern int u2f_protocol_set_authenticate(struct u2f_proto *proto, int presence);
extern int u2f_protocol_set_authenticate_check(struct u2f_proto *proto);
extern int u2f_protocol_set_authenticate_sign(struct u2f_proto *proto);
extern int u2f_protocol_set_get_version(struct u2f_proto *proto);

extern int u2f_protocol_get_extended_request(struct u2f_proto *proto, const uint8_t **buffer, size_t *size);
extern int u2f_protocol_put_extended_reply(struct u2f_proto *proto, const uint8_t *buffer, size_t size);
extern int u2f_protocol_put_error_status(struct u2f_proto *proto, uint16_t status);

extern int u2f_protocol_get_challenge(struct u2f_proto *proto, const uint8_t **buffer, size_t *size);
extern int u2f_protocol_get_appid(struct u2f_proto *proto, const uint8_t **buffer, size_t *size);
extern int u2f_protocol_get_keyhandle(struct u2f_proto *proto, const uint8_t **buffer, size_t *size);
extern int u2f_protocol_get_version(struct u2f_proto *proto, const uint8_t **buffer, size_t *size);
extern int u2f_protocol_get_publickey(struct u2f_proto *proto, const uint8_t **buffer, size_t *size);
extern int u2f_protocol_get_certificate(struct u2f_proto *proto, const uint8_t **buffer, size_t *size);
extern int u2f_protocol_get_signature(struct u2f_proto *proto, const uint8_t **buffer, size_t *size);
extern int u2f_protocol_get_signedpart(struct u2f_proto *proto, const uint8_t **buffer, size_t *size);
extern uint16_t u2f_protocol_get_status(struct u2f_proto *proto);
extern int u2f_protocol_get_userpresence(struct u2f_proto *proto);
extern uint32_t u2f_protocol_get_counter(struct u2f_proto *proto);

