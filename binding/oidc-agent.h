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

struct json_object;
#include <curl/curl.h>

/***************** IDP **************************/

extern int oidc_idp_set(
		const char *name,
		struct json_object *desc
	);

extern int oidc_idp_exists(
		const char *name
	);

extern void oidc_idp_delete(
		const char *name
	);


/***************** APPLI **************************/

extern int oidc_appli_set(
		const char *name,
		const char *idp,
		struct json_object *desc,
		int make_default
	);

extern int oidc_appli_exists(
		const char *name
	);

extern int oidc_appli_has_idp(
		const char *name,
		const char *idp
	);

extern int oidc_appli_set_default_idp(
		const char *name,
		const char *idp
	);

extern void oidc_appli_delete(
		const char *name
	);

/***************** APPLI **************************/

struct oidc_grant_cb
{
	void *closure;
	void (*success)(void *closure, struct json_object *result);
	void (*error)(void *closure, const char *message, const char *indice);
};

enum oidc_grant_flow
{
	Flow_Invalid,
	Flow_Authorization_Code_Grant,
	Flow_Implicit_Grant,
	Flow_Resource_Owner_Password_Credentials_Grant,
	Flow_Client_Credentials_Grant,
	Flow_Extension_Grant
};


extern void oidc_grant(
		const char *appli,
		const char *idp,
		struct json_object *args,
		const struct oidc_grant_cb *cb,
		enum oidc_grant_flow flow
	);

extern void oidc_grant_owner_password(
		const char *appli,
		const char *idp,
		struct json_object *args,
		const struct oidc_grant_cb *cb
	);

extern void oidc_grant_client_credentials(
		const char *appli,
		const char *idp,
		struct json_object *args,
		const struct oidc_grant_cb *cb
	);

extern void oidc_token_refresh(
		const char *appli,
		const char *idp,
		struct json_object *token,
		const struct oidc_grant_cb *cb
	);

extern int oidc_add_bearer(
		CURL *curl,
		struct json_object *token
	);

