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
#define _GNU_SOURCE

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

#include <json-c/json.h>
#include <curl/curl.h>

#include "curl-wrap.h"
#include "oidc-agent.h"

/*
#include <errno.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <json-c/json.h>

#include <afb/afb-binding.h>
#include <afb/afb-req-itf.h>
#include <afb/afb-event-itf.h>
#include <afb/afb-service-itf.h>


#include "u2f-bluez.h"
*/


struct keyrequest {
	struct keyrequest *next;
	int dead;
	time_t expiration;
	const char *url;
	const char *appli;
	const char *idp;
	void (*callback)(void *closure, int status, const void *buffer, size_t size);
	void *closure;
	json_object *token;
	pthread_t tid;
};

static struct keyrequest *keyrequests = 0;

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

static int curl_initialized = 0;








static void perform_query_callback(void *closure, int status, CURL *curl, const char *result, size_t size)
{
	struct keyrequest *kr = closure;
	kr->callback(kr->closure, status, result, size);
}

static void perform_query(struct keyrequest *kr)
{
	CURL *curl;

	curl = curl_wrap_prepare_get_url(kr->url);
	if (!curl)
		kr->callback(kr->closure, 0, "out of memory", 0);
	else {
		oidc_add_bearer(curl, kr->token);
		curl_wrap_do(curl, perform_query_callback, kr);
	}
}

static void token_success(void *closure, struct json_object *token)
{
	struct keyrequest *kr = closure;
	kr->token = token;
	perform_query(kr);
}

static void token_error(void *closure, const char *message, const char *indice)
{
	struct keyrequest *kr = closure;
	kr->callback(kr->closure, 0, message, 0);
}

static void *kr_get_thread(void *closure)
{
	struct oidc_grant_cb cb;
	struct keyrequest *kr = closure;

	if (!kr->appli)
		perform_query(kr);
	else {
		cb.closure = kr;
		cb.success = token_success;
		cb.error = token_error;
		oidc_grant_owner_password(kr->appli, kr->idp, NULL, &cb);
	}
	kr->dead = 1;
	return NULL;
}

static void kr_free(struct keyrequest *kr)
{
	json_object_put(kr->token);
	free(kr);
}

static struct keyrequest *kr_alloc(
	const char *url,
	time_t expiration,
	const char *appli,
	const char *idp,
	void (*callback)(void *closure, int status, const void *buffer, size_t size),
	void *closure
)
{
	struct keyrequest *result;
	char *buf;
	size_t surl, sappli, sidp;

	surl = 1 + strlen(url);
	sappli = appli ? 1 + strlen(appli) : 0;
	sidp = idp ? 1 + strlen(idp) : 0;

	result = calloc(1, surl + sappli + sidp + sizeof *result);
	if (result) {
		result->next = NULL;
		result->dead = 0;
		result->expiration = expiration;
		result->callback = callback;
		result->closure = closure;
		result->token = NULL;
		result->tid = 0;

		buf = (char*)(&result[1]);
		result->url = buf;
		buf = mempcpy(buf, url, surl);
		if (!appli)
			result->appli = NULL;
		else {
			result->appli = buf;
			buf = mempcpy(buf, appli, sappli);
		}
		if (!idp)
			result->idp = NULL;
		else {
			result->idp = buf;
			buf = mempcpy(buf, idp, sidp);
		}
	}
	return result;
}

void aia_get(
	const char *url,
	int delay,
	const char *appli,
	const char *idp,
	void (*callback)(void *closure, int status, const void *buffer, size_t size),
	void *closure
)
{
	int rc;
	time_t now;
	struct keyrequest **pkr, *kr, *found_kr;

	/* initialize CURL component */
	pthread_mutex_lock(&mutex);
	if (!curl_initialized) {
		curl_initialized = 1;
		curl_global_init(CURL_GLOBAL_DEFAULT);
	}

	/* search for the same request and also cleanup deads */
	now = time(NULL);
	found_kr = 0;
	pkr = &keyrequests;
	kr = *pkr;
	while (kr) {
		if (now > kr->expiration) {
			if (kr->dead) {
				*pkr = kr->next;
				kr_free(kr);
			} else {
				pkr = &kr->next;
			}
		} else {
			if (!strcmp(url, kr->url))
				found_kr = kr;
			pkr = &kr->next;
		}
		kr = *pkr;
	}

	/* check if found and pending */
	if (found_kr) {
		/* found -> cancel */
		pthread_mutex_unlock(&mutex);
		callback(closure, 0, NULL, 0);
		return;
	}

	/* allocates the keyrequest */
	kr = kr_alloc(url, now + delay, appli, idp, callback, closure);
	if (!kr) {
		pthread_mutex_unlock(&mutex);
		callback(closure, 0, "Out of memory", 0);
		return;
	}

	/* link the request */
	kr->next = keyrequests;
	keyrequests = kr;

	/* makes the request in a new thread */
	rc = pthread_create(&kr->tid, 0, kr_get_thread, kr);
	if (rc != 0) {
		/* error, unlink */
		keyrequests = kr->next;
		pthread_mutex_unlock(&mutex);
		kr_free(kr);
		callback(closure, 0, "Can't create a new thread", 0);
		return;
	}
	pthread_mutex_unlock(&mutex);
}

/* vim: set colorcolumn=80: */

