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

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

const char base64_variant_standard[] = "+/=";
const char base64_variant_url[] = "-_=";
const char base64_variant_trunc[] = "+/";
const char base64_variant_url_trunc[] = "-_";

static char eb64(int x, const char *variant)
{
	if (x < 52)
		return (char)(x + (x < 26 ? 'A' : 'a'-26));
	else
		return x < 62 ? (char)(x + '0' - 52) : variant[x - 62];
}

char *base64_encode_array_variant(const char * const *args, size_t count, const char *variant)
{
	const char *v, *s;
	char *buffer, c;
	size_t i, j, n;
	uint16_t x;

	/* compute size and allocate */
	i = n = 0;
	while (n < count)
		i += strlen(args[n++]);
	buffer = malloc(5 + ((i / 3) << 2));
	if (!buffer)
		return NULL;

	/* encode */
	v = variant ? : base64_variant_standard;
	n = 0;
	j = 0;
	x = 0;
	while (n < count) {
		s = args[n++];
		c = s[i = 0];
		while (c) {
			x = (uint16_t)((uint16_t)(x << 8) | (uint16_t)(uint8_t)c);
			switch (j & 3) {
			case 0:
				buffer[j++] = eb64((x >> 2) & 63, v);
				break;
			case 1:
				buffer[j++] = eb64((x >> 4) & 63, v);
				break;
			case 2:
				buffer[j++] = eb64((x >> 6) & 63, v);
				buffer[j++] = eb64(x & 63, v);
				break;
			}
			c = s[++i];
		}
	}

	/* pad */
	if (v[2]) {
		switch (j & 3) {
		case 1:
			buffer[j++] = eb64((x << 4) & 63, v);
			buffer[j++] = v[2];
			buffer[j++] = v[2];
			break;
		case 2:
			buffer[j++] = eb64((x << 2) & 63, v);
			buffer[j++] = v[2];
			break;
		}
	}

	/* done */
	buffer[j] = 0;
	return buffer;
}

char *base64_encode_multi_variant(const char * const *args, const char *variant)
{
	size_t count;

	for (count = 0 ; args[count] ; count++);
	return base64_encode_array_variant(args, count, variant);
}

char *base64_encode_variant(const char *arg, const char *variant)
{
	return base64_encode_array_variant(&arg, !!arg, variant);
}

