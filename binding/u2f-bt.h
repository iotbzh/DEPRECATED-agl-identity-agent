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

struct u2f_bluez;
struct u2f_proto;
struct u2f_bt;

extern int u2f_bt_create(struct u2f_bt **p, struct u2f_bluez *device);
extern int u2f_bt_create_address(struct u2f_bt **p, const char *address);
extern struct u2f_bt *u2f_bt_addref(struct u2f_bt *bt);
extern void u2f_bt_unref(struct u2f_bt *bt);
extern void u2f_bt_set_callback(struct u2f_bt *bt, void (*callback)(void *closure, int status, const uint8_t *buffer, size_t size), void *closure);
extern int u2f_bt_send(struct u2f_bt *bt, uint8_t cmd, const uint8_t *data, size_t size);

extern int u2f_bt_message(struct u2f_bluez *device, struct u2f_proto *msg, void (*callback)(void *closure, int status, struct u2f_proto *msg), void *closure);
