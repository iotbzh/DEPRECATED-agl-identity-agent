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

#pragma once

extern const char base64_variant_standard[];
extern const char base64_variant_trunc[];

extern const char base64_variant_url[];
extern const char base64_variant_url_trunc[];

extern char *base64_encode_array_variant(const char * const *args, size_t count, const char *variant);
extern char *base64_encode_multi_variant(const char * const *args, const char *variant);
extern char *base64_encode_variant(const char *arg, const char *variant);

#define base64_encode_array(args,count)           base64_encode_array_variant(args,count,base64_variant_standard)
#define base64_encode_multi(args)                 base64_encode_multi_variant(args,base64_variant_standard)
#define base64_encode(arg)                        base64_encode_variant(arg,base64_variant_standard)

#define base64_encode_array_standard(args,count)  base64_encode_array_variant(args,count,base64_variant_standard)
#define base64_encode_multi_standard(args)        base64_encode_multi_variant(args,base64_variant_standard)
#define base64_encode_standard(arg)               base64_encode_variant(arg,base64_variant_standard)

#define base64_encode_array_url(args,count)       base64_encode_array_variant(args,count,base64_variant_url)
#define base64_encode_multi_url(args)             base64_encode_multi_variant(args,base64_variant_url)
#define base64_encode_url(arg)                    base64_encode_variant(arg,base64_variant_url)

#define base64_encode_array_trunc(args,count)     base64_encode_array_variant(args,count,base64_variant_trunc)
#define base64_encode_multi_trunc(args)           base64_encode_multi_variant(args,base64_variant_trunc)
#define base64_encode_trunc(arg)                  base64_encode_variant(arg,base64_variant_trunc)

#define base64_encode_array_url_trunc(args,count) base64_encode_array_variant(args,count,base64_variant_url_trunc)
#define base64_encode_multi_url_trunc(args)       base64_encode_multi_variant(args,base64_variant_url_trunc)
#define base64_encode_url_trunc(arg)              base64_encode_variant(arg,base64_variant_url_trunc)



