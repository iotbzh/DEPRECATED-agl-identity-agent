/*
 * Copyright (C) 2017 "IoT.bzh"
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

#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>

#include "base64.h"

char *authorization_basic_make(const char *user, const char *password)
{
	const char *array[3] = { user, ":", password };
	return base64_encode_array(array, 3);
}

char *authorization_basic_make_header(const char *user, const char *password)
{
	char *key, *result;

	key = authorization_basic_make(user, password);
	if (!key || asprintf(&result, "Authorization: Basic %s", key) < 0)
		result = NULL;
	free(key);
	return result;
}

/* vim: set colorcolumn=80: */

