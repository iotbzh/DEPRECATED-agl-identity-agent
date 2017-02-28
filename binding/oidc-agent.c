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
#include <stdint.h>
#include <string.h>
#include <pthread.h>

#include <json-c/json.h>

#include "oidc-agent.h"
#include "escape.h"
#include "curl-wrap.h"

/***************** utilities *************************/

static const char string_empty[] = "";
static const char string_authorization_endpoint[] = "authorization_endpoint";
static const char string_token_endpoint[] = "token_endpoint";
#if 0
static const char string_issuer[] = "issuer";
static const char string_userinfo_endpoint[] = "userinfo_endpoint";
static const char string_revocation_endpoint[] = "revocation_endpoint";
static const char string_jwks_uri[] = "jwks_uri";
#endif

#define MAX_IDP_COUNT     20
#define MAX_APPLI_COUNT   100

static struct json_object *idps;
static struct json_object *applis;

static pthread_rwlock_t rwlock = PTHREAD_RWLOCK_INITIALIZER;

/***************** utilities *************************/

/*
 * Get the object of 'name' in the 'container' and return it.
 * Creates the result if needed and add it to the container.
 * When 'maxcount' isn't zero the final count will not exceed 'maxcount'.
 */
static struct json_object *j_container_item(struct json_object *container, const char *name, int maxcount)
{
	struct json_object *result;

	/* ensure object of 'name' exists */
	if (!json_object_object_get_ex(container, name, &result)) {
		if (maxcount && json_object_object_length(container) >= maxcount)
			return NULL;
		result = json_object_new_object();
		if (!result)
			return NULL;
		json_object_object_add (container, name, result);
	}
	return result;
}

/*
 * Like 'j_container_item' but also creates the 'container' if needed.
 */
static struct json_object *j_container_item_make(struct json_object **container, const char *name, int maxcount)
{
	struct json_object *cont;

	/* ensure container exists */
	cont = *container;
	if (!cont) {
		cont = json_object_new_object();
		if (!cont)
			return NULL;
		*container = cont;
	}
	return j_container_item(cont, name, maxcount);
}

/*
 * Adds in 'dest' the fields of 'src'
 * Also when the value of a field of 'src' is null, delete the field of 'dst'
 */
static void j_merge(struct json_object *dest, struct json_object *src)
{
	struct json_object_iter i;
	json_object_object_foreachC(src, i) {
		if (json_object_is_type(i.val, json_type_null))
			json_object_object_del(dest, i.key);	
		else
			json_object_object_add(dest, i.key, json_object_get(i.val));
	}
}

/***************** IDP **************************/

/*
 * Set the values of 'desc' for the idp of 'name'.
 * Return 0 on error or 1 on success.
 */
int oidc_idp_set(const char *name, struct json_object *desc)
{
	struct json_object *idp;
	int result = 0;

	pthread_rwlock_wrlock(&rwlock);
	idp = j_container_item_make(&idps, name, MAX_IDP_COUNT);
	if (idp) {
		j_merge(idp, desc);
		result = 1;
	}
	pthread_rwlock_unlock(&rwlock);
	return result;
}

/*
 * Return 1 if idp of 'name' exists or 0 otherwise.
 */
int oidc_idp_exists(const char *name)
{
	int result;

	pthread_rwlock_rdlock(&rwlock);
	result = json_object_object_get_ex(idps, name, NULL);
	pthread_rwlock_unlock(&rwlock);

	return result;
}

/*
 * Deletes the idp of 'name'.
 */
void oidc_idp_delete(const char *name)
{
	pthread_rwlock_wrlock(&rwlock);
	json_object_object_del(idps, name);
	pthread_rwlock_unlock(&rwlock);
}

/***************** APPLI **************************/

/*
 * Returns the name of the idp of the 'appli'.
 * Returns NULL when appli isn't set or default idp isn't set.
 */
static const char *get_default_idp(const char *appli)
{
	struct json_object *a, *i;

	if (!json_object_object_get_ex(applis, appli, &a))
		return NULL;
	if (!json_object_object_get_ex(a, string_empty, &i))
		return NULL;
	return json_object_get_string(i);
}

/*
 * Returns the application data related to the 'appli' for the 'idp'.
 * If 'ja' isn't null, returns in it the object for the application 'appli'.
 * Returns NULL in case of error.
 */
static struct json_object *get_appli_idp(const char *appli, const char *idp, struct json_object **ja)
{
	struct json_object *a, *i;

	if (!json_object_object_get_ex(applis, appli, &a) || !json_object_object_get_ex(a, idp, &i))
		return NULL;
	if (ja)
		*ja = a;
	return i;
}

/*
 * Set the description 'desc' for the application of 'name' and
 * the 'idp'. When 'make_default' is set it, make it the default idp
 * for the application.
 * Return 0 on error or 1 on success.
 */
int oidc_appli_set(const char *name, const char *idp, struct json_object *desc, int make_default)
{
	struct json_object *a, *ai;
	int result = 0;

	pthread_rwlock_wrlock(&rwlock);
	a = j_container_item_make(&applis, name, MAX_APPLI_COUNT);
	if (a) {
		ai = j_container_item(a, idp, 0);
		if (ai) {
			j_merge(ai, desc);
			if (make_default || !json_object_object_get_ex(a, string_empty, NULL))
				json_object_object_add(a, string_empty, json_object_new_string(idp));
			result = 1;
		}
	}
	pthread_rwlock_unlock(&rwlock);
	return result;
}

/*
 * Is the appli of 'name' defined?
 * Return 1 if answer is yes or 0 for no.
 */
int oidc_appli_exists(const char *name)
{
	int result;

	pthread_rwlock_rdlock(&rwlock);
	result = json_object_object_get_ex(applis, name, NULL);
	pthread_rwlock_unlock(&rwlock);

	return result;
}

/*
 * Does the appli of 'name' has the 'idp' defined?
 * Return 1 if answer is yes or 0 for no.
 */
int oidc_appli_has_idp(const char *name, const char *idp)
{
	int result;

	pthread_rwlock_rdlock(&rwlock);
	result = !!get_appli_idp(name, idp, NULL);
	pthread_rwlock_unlock(&rwlock);

	return result;
}

/*
 * Set 'idp' as default for the application of 'name'.
 * Returns 0 on error (appli or idp for appli not existing)
 * or 1 in case of success.
 */
int oidc_appli_set_default_idp(const char *name, const char *idp)
{
	struct json_object *a, *i;

	pthread_rwlock_wrlock(&rwlock);
	i = get_appli_idp(name, idp, &a);
	if (i)
		json_object_object_add(a, string_empty, json_object_new_string(idp));
	pthread_rwlock_unlock(&rwlock);

	return !!i;
}

/*
 * Deletes the application of 'name'
 */
void oidc_appli_delete(const char *name)
{
	pthread_rwlock_wrlock(&rwlock);
	json_object_object_del(applis, name);
	pthread_rwlock_unlock(&rwlock);
}

/***************** AUTHORISATION **************************/

/* parameters */
enum param
{
	Param_Access_Token,
	Param_Acr_Values,
	Param_Authorization,
	Param_Client_Id,
	Param_Client_Secret,
	Param_Code,
	Param_Display,
	Param_Error,
	Param_Error_Description,
	Param_Error_Uri,
	Param_Expires_In,
	Param_Grant_Type,
	Param_Id_Token,
	Param_Id_Token_Hint,
	Param_Login_Hint,
	Param_Max_Age,
	Param_Nonce,
	Param_Password,
	Param_Prompt,
	Param_Redirect_Uri,
	Param_Refresh_Token,
	Param_Response_Type,
	Param_Scope,
	Param_State,
	Param_Token_Type,
	Param_Ui_Locales,
	Param_Username,
	PARAM_COUNT
};

#if PARAM_COUNT > 30
# error "Too much parameters"
#endif
#define PARAM(p)	((uint32_t)((uint32_t)1 << (Param_##p)))

/* args of authorization requests */
struct args
{
	struct json_object *appli;
	struct json_object *idp;
	struct json_object *args;
	struct oidc_grant_cb cb;
	int locked;
	int refresh;
	uint32_t mandatory;
	uint32_t all;
	struct json_object *header;
	struct json_object *query;
};

/* Release the lock if needed */
static void args_unlock(struct args *args)
{
	if (!args->locked) {
		pthread_rwlock_unlock(&rwlock);
		args->locked = 0;
	}
}

/* Release the memory needed by args */
static void args_destroy(struct args *args)
{
	json_object_put(args->appli);
	json_object_put(args->idp);
	json_object_put(args->header);
	json_object_put(args->query);
	free(args);
}

/* Send the success event with the gained tokens */
static void args_send_success(struct args *args, struct json_object *result)
{
	args_unlock(args);
	args->cb.success(args->cb.closure, result);
	args_destroy(args);
}

/* Sends the error event with the indice to the client of args */
static void args_send_error(struct args *args, const char *message, const char *indice)
{
	args_unlock(args);
	args->cb.error(args->cb.closure, message, indice);
	args_destroy(args);
}

/* Send the error and also return NULL */
static inline struct args *args_send_error_null(struct args *args, const char *message, const char *indice)
{
	args_send_error(args, message, indice);
	return NULL;
}

/* creates a struct args from the arguments, returns NULL on error */
struct args *mkargs(const char *appli, const char *idp, struct json_object *args, const struct oidc_grant_cb *cb)
{
	struct args *result;
	struct json_object *obj;

	/* allocates the args */
	result = calloc(1, sizeof *result);
	if (!result) {
		cb->error(cb->closure, "Out of memory", NULL);
		return NULL;
	}

	/* init of the structure */
	result->cb = *cb;
	result->args = args;
	result->header = json_object_new_object();
	result->query = json_object_new_object();

	/* lock in read */
	pthread_rwlock_rdlock(&rwlock);
	result->locked = 1;

	/* check previous allocations */
	if (!result->query || !result->header) {
		return args_send_error_null(result, "Out of memory", NULL);
	}

	/* check whether default idp */
	if (!idp) {
		idp = get_default_idp(appli);
		if (!idp)
			return args_send_error_null(result, "No default IDP", NULL);
	}

	/* get the IDP */
	if (!json_object_object_get_ex(idps, idp, &obj))
		return args_send_error_null(result, "Unknown IDP", idp);
	result->idp = json_object_get(obj);

	/* get the appli */
	obj = get_appli_idp(appli, idp, NULL);
	if (!obj)
		return args_send_error_null(result, "Unknown APPLI for IDP", appli);
	result->appli = json_object_get(obj);

	return result;
}

/* get a value for a struct args */
static struct json_object *args_object(struct args *args, const char *name)
{
	struct json_object *result;

	if (!json_object_object_get_ex(args->appli, name, &result)
		&& !json_object_object_get_ex(args->idp, name, &result)
		&& !json_object_object_get_ex(args->args, name, &result))
			result = NULL;
	return result;
}

/* get a string value for a struct args */
static const char *args_string(struct args *args, const char *name)
{
	struct json_object *object = args_object(args, name);
	return object ? json_object_get_string(object) : NULL;
}

/* add a data */
static int args_add(struct args *args, uint32_t val, const char *name, int query)
{
	struct json_object *obj, *dest;

	if (val & args->all) {
		obj = args_object(args, name);
		if (obj) {
			dest = query ? args->query : args->header;
			json_object_object_add(dest, name, json_object_get(obj));
		}
		else if (val & args->mandatory) {
			args_send_error(args, "Mandatory field missing", name);
			return 0;
		}	
	}

	return 1;
}

/*
 * Makes the CURL object for the given 'url' for either GET or POST depending
 * on 'post' with the added 'header' fields and the given query parameters.
 * Returns NULL on error.
 * Ex:
 *
 *   curl_json("http://iot.bzh/api", 0, {"X-Index": "no"}, {"fast":true,"item":"2345-hellfest"})
 * 
 * produces the query:
 *
 *   GET /api?fast=true&item=2345-hellfest HTTP/1.1
 *   Host: iot.bzh
 *   X-Index: no
 *
 * while the same but with post not null produces:
 *
 *   POST /api HTTP/1.1
 *   Host: iot.bzh
 *   X-Index: no
 *   Content-Type: application/x-www-form-urlencoded
 *
 *   fast=true&item=2345-hellfest
 *
 */
static CURL *curl_json(const char *url, int post, struct json_object *header, struct json_object *query)
{
	const char **args, *str;
	struct json_object_iter i;
	int idx;
	CURL *result;

	/* create args array */
	idx = 1 + (json_object_object_length(query) << 1);
	args = malloc((unsigned)idx * sizeof *args);
	if (!args)
		return NULL;

	/* fill the args array */
	args[--idx] = NULL;
	json_object_object_foreachC(query, i) {
		str = json_object_get_string(i.val);
		args[--idx] = str;
		args[--idx] = i.key;
	}

	/* prepare the query */
 	if (post)
		result = curl_wrap_prepare_post(url, NULL, args);
	else
		result = curl_wrap_prepare_get(url, NULL, args);
	free(args);
	if(!result)
		return NULL;

	/* add headers */
	if (header) {
		json_object_object_foreachC(header, i) {
			str = json_object_get_string(i.val);
			if (!curl_wrap_add_header_value(result, i.key, str)) {
				curl_easy_cleanup(result);	
				return NULL;
			}
		}
	}
	return result;
}

/*
 * Extract from the answer of 'curl' whose 'content' has 'size' bytes the
 * embeded JSON object (if any).
 * Returns it or returns NULL if the answer can't be interpreted.
 */
static struct json_object *decode_perform_result(CURL *curl, const char *content, size_t size)
{
	int i;
	const char **args;
	struct json_object *result;

	/* is it an url encoded answer? */
	if (curl_wrap_content_type_is(curl, "application/x-www-form-urlencoded")) {
		/* yes, unescape as an array of strings */
		args = unescape_args(content);
		if (!args)
			result = NULL;
		else {
			/* wrap the key=value pairs in an object  */
			result = json_object_new_object();
			if (result) {
				for (i = 0 ; args[i] ; i += 2)
					json_object_object_add(result, args[i],
						json_object_new_string(args[i+1]));
			}
			free(args);
		}
	} else if (curl_wrap_content_type_is(curl, "application/json")) {
		/* interpret the json */
		result = json_tokener_parse (content);
	} else {
		/* by default, still try to interpret the answer as if json */
		result = json_tokener_parse (content);
	}
	return result;
}

/*
 * Treats the result of the query 'curl' of 'content' of 'size' bytes for the 'args'
 */
static void perform_result(struct args *args, CURL *curl, const char *content, size_t size)
{
	struct json_object *obj, *at, *tt;
	char *txt;

	/* get answer */
	obj = decode_perform_result(curl, content, size);
	if (!obj)
		return args_send_error(args, "unable to extract answer", content);

	/* process the answer */
	if (json_object_object_get_ex(obj, "access_token", &at) && json_object_object_get_ex(obj, "token_type", &tt)) {
		if (!strcmp(json_object_get_string(tt), "bearer")) {
			if (asprintf(&txt, "Bearer %s", json_object_get_string(at)) > 0) {
				json_object_object_add(obj, "authorization", json_object_new_string(txt));
				free(txt);
			}
		}
	}

	/* merge the answer to the token args in case of refresh */
	if (args->refresh)
		j_merge(args->args, obj);

	/* send the answer */
	args_send_success(args, obj);
}

/*
 * Treats the redirect answer of the query 'curl' of 'content' of 'size' bytes for the 'args'
 */
static void perform_redirect(struct args *args, CURL *curl, const char *content, size_t size)
{
	/* TODO: handle redirection for the normal flow */
	return args_send_error(args, "unhandled redirection", content);
}

/*
 * Handle the result of the query 'curl' of 'status'. If a data is returned, it is available in
 * 'content' of 'size' bytes.
 * When 'status' is 0, an error occured. Otherwise, 'statu' isn't zero.
 */
static void perform_callback(void *closure, int status, CURL *curl, const char *content, size_t size)
{
	long code;
	struct args *args = closure;

	/* query error ? */
	if (!status
	 || curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code) != CURLE_OK)
		return args_send_error(args, "query error", NULL); /* TODO: IMPROVE? */

	/* get the returned code */
	switch (code) {
	case 200:
		return perform_result(args, curl, content, size);
	case 302:
		return perform_redirect(args, curl, content, size);
	case 400:
	case 401:
		return args_send_error(args, content ? : "returned code error", content ? "returned code error" : content);
	default:
		return args_send_error(args, content ? : "unexpected code error", content ? "unexpected code error" : content);
	}
}

/*
 * Main function for performing OAuth2/OpenId Connect transactions.
 * The structure 'args' is filled with the needed values:
 *   Application data as json object, IDP data as json object
 *   Contextual arguments for the transaction.
 * 'endpoint' must be the name of an endpoint in the context of 'args'.
 * 'operation' is the value that will get either response_type or grant_type,
 * depending on the nature of the required parameters 'mandatory'.
 * 'mandatory' designates the mandatory parameters.
 * 'optional' designate the optional parameters.
 */
static void perform(struct args *args, const char *endpoint, const char *operation, uint32_t mandatory, uint32_t optional)
{
	int post;
	const char *url, *type;
	CURL *curl;

	/* set the flags */
	args->mandatory = mandatory;
	args->all = mandatory | optional;

	/* get the endpoint */
	url = args_string(args, endpoint);
	if (!url)
		return args_send_error(args, "No endpoint", endpoint);

	/* get the operation type */
	if ((mandatory & PARAM(Response_Type)) == PARAM(Response_Type)) {
		type = "response_type";
		post = 0; /* can be 1 sometimes so not risk here */
	} else if ((mandatory & PARAM(Grant_Type)) == PARAM(Grant_Type)) {
		type = "grant_type";
		post = 1; /* must be 1 */
	} else
		return args_send_error(args, "Unexpected operation Type", NULL);
		
	json_object_object_add(args->query, type, json_object_new_string(operation));

	/* get the arguments */
	if (1
	 && args_add(args, PARAM(Access_Token), "access_token", 1)
	 && args_add(args, PARAM(Acr_Values), "acr_values", 1)
	 && args_add(args, PARAM(Authorization), "authorization", 0)
	 && args_add(args, PARAM(Client_Id), "client_id", 1)
	 && args_add(args, PARAM(Client_Secret), "client_secret", 1)
	 && args_add(args, PARAM(Code), "code", 1)
	 && args_add(args, PARAM(Display), "display", 1)
	 && args_add(args, PARAM(Expires_In), "expires_in", 1)
	 && args_add(args, PARAM(Id_Token_Hint), "id_token_hint", 1)
	 && args_add(args, PARAM(Login_Hint), "login_hint", 1)
	 && args_add(args, PARAM(Max_Age), "max_age", 1)
	 && args_add(args, PARAM(Nonce), "nonce", 1)
	 && args_add(args, PARAM(Password), "password", 1)
	 && args_add(args, PARAM(Prompt), "prompt", 1)
	 && args_add(args, PARAM(Redirect_Uri), "redirect_uri", 1)
	 && args_add(args, PARAM(Refresh_Token), "refresh_token", 1)
	 && args_add(args, PARAM(Scope), "scope", 1)
	 && args_add(args, PARAM(State), "state", 1)
	 && args_add(args, PARAM(Token_Type), "token_type", 1)
	 && args_add(args, PARAM(Ui_Locales), "ui_locales", 1)
	 && args_add(args, PARAM(Username), "username", 1)
	) {
		/* creates the curl query */
		curl = curl_json(url, post, args->header, args->query);
		if (!curl)
			return args_send_error(args, "out of memory", NULL);

		/* release data */
		args_unlock(args);

		/* perform the request to the server */
		curl_wrap_do(curl, perform_callback, args);
	}
}

/* perform a grant of flow Flow_Resource_Owner_Password_Credentials_Grant */
static void grant_owner_password(struct args *args)
{
	perform(args, string_token_endpoint, "password",
			PARAM(Grant_Type) | PARAM(Username) | PARAM(Password),
			PARAM(Scope) | PARAM(Authorization)
		);
}

/* perform a grant of flow Flow_Client_Credentials_Grant */
static void grant_client_credentials(struct args *args)
{
	perform(args, string_token_endpoint, "client_credentials",
			PARAM(Grant_Type),
			PARAM(Scope) | PARAM(Authorization)
		);
}

/* switches the requests depending on 'flow' */
static void grant(struct args *args, enum oidc_grant_flow flow)
{
	/* ensure args is valid */
	if (!args)
		return;

	/* process for flow */
	switch(flow) {

	case Flow_Resource_Owner_Password_Credentials_Grant:
		grant_owner_password(args);
		break;

	case Flow_Client_Credentials_Grant:
		grant_client_credentials(args);
		break;

	case Flow_Authorization_Code_Grant:
	case Flow_Implicit_Grant:
	case Flow_Extension_Grant:
		args_send_error(args, "Unsupported flow", NULL);
		break;
		
	case Flow_Invalid:
	default:
		args_send_error(args, "Invalid flow", NULL);
		break;
	}
}

/*
 * Initiates a grant with the given 'flow'.
 * 'appli' and 'idp' designates the appli and the idp that have been recorded.
 * when idp == NULL or idp == "", the default idp of 'appli' is used.
 * 'args' contains parameters expected in plus for the grant transaction.
 * 'cb' describes the callback actions that are called before
 * the function returns.
 */
void oidc_grant(const char *appli, const char *idp, struct json_object *args, const struct oidc_grant_cb *cb, enum oidc_grant_flow flow)
{
	grant(mkargs(appli, idp, args, cb), flow);
}

/*
 * Like oidc_grant for flow Flow_Resource_Owner_Password_Credentials_Grant
 */
void oidc_grant_owner_password(const char *appli, const char *idp, struct json_object *args, const struct oidc_grant_cb *cb)
{
	grant(mkargs(appli, idp, args, cb), Flow_Resource_Owner_Password_Credentials_Grant);
}

/*
 * Like oidc_grant for flow Flow_Client_Credentials_Grant
 */
void oidc_grant_client_credentials(const char *appli, const char *idp, struct json_object *args, const struct oidc_grant_cb *cb)
{
	grant(mkargs(appli, idp, args, cb), Flow_Client_Credentials_Grant);
}

/*
 * Refreshes the 'token' for the 'appli' and the  'idp'.
 * 'cb' describes the callback actions that are called before
 * the function returns.
 */
void oidc_token_refresh(const char *appli, const char *idp, struct json_object *token, const struct oidc_grant_cb *cb)
{
	struct args *args;

	args = mkargs(appli, idp, token, cb);
	if (!args)
		return;
	args->refresh = 1;
	perform(args, string_token_endpoint, "refresh_token",
			PARAM(Grant_Type) | PARAM(Refresh_Token),
			PARAM(Scope) | PARAM(Authorization)
		);
}

/*
 * Adds the header "authorisation" with the bearer access_token of 'token'.
 * Return 1 on case of success or 0 otherwise.
 */
int oidc_add_bearer(CURL *curl, struct json_object *token)
{
	struct json_object *bearer;

	return json_object_object_get_ex(token, "authorization", &bearer)
		&& curl_wrap_add_header_value(curl, "authorization", json_object_get_string(bearer));
}


