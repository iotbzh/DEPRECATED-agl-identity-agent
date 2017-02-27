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

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
 
#include <curl/curl.h>

#include <afb/afb-binding.h>

/* synchronisation */
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

/* data */
struct request {
	struct request *next;
	size_t size;
	uint8_t *response;
	void (*callback)(void *closure, int status, void *buffer, size_t size);
	void *closure;
	char url[1];
};

extern const struct afb_binding_interface *interface;

static int init_done;
static struct request *requests;

static struct request *request_create(const char *url, void (*callback)(void *closure, int status, void *buffer, size_t size), void *closure)
{
	size_t length;
	struct request *request;

	length = strlen(url);
	request = malloc(sizeof *request + length);
	if (request) {
		request->next = 0;
		request->size = 0;
		request->response = 0;
		request->callback = callback;
		request->closure = closure;
		memcpy(request->url, url, length + 1);
	}
	return request;
}

static void request_destroy(struct request *request)
{
	free(request->response);
	free(request);
}

static size_t write_callback(char *ptr, size_t size, size_t nmemb, void *userdata)
{
	struct request *request = userdata;
	size_t sz = size * nmemb;
	size_t old_size = request->size;
	size_t new_size = old_size + sz;
	uint8_t *response = realloc(request->response, new_size + 1);
	if (!response)
		return 0;
	memcpy(&response[old_size], ptr, sz);
	response[new_size] = 0;
	request->size = new_size;
	request->response = response;
	return sz;
}

static void apply_request(struct request *request)
{
	CURL *curl;
	CURLcode rc;

	curl = curl_easy_init();
	if (!curl) {
		request->callback(request->closure, -1, 0, 0);
		return;
	}

	curl_easy_setopt(curl, CURLOPT_URL, request->url);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, request);

	/* Perform the request, res will get the return code */ 
	rc = curl_easy_perform(curl);

	/* Check for errors */ 
	if(rc != CURLE_OK) {
		ERROR(interface, "getting url failed: %s (%s)\n",
					curl_easy_strerror(rc), request->url);
		request->callback(request->closure, -1, 0, 0);
	} else {
		request->callback(request->closure, 0, request->response, request->size);
	}
	/* always cleanup */ 
	curl_easy_cleanup(curl);
}

static void *thread_requests(void *data)
{
	struct request *request;

	for(;;) {
		pthread_mutex_lock(&mutex);
		request = requests;
		pthread_mutex_unlock(&mutex);

		if (!request)
			break;
		apply_request(request);

		pthread_mutex_lock(&mutex);
		requests = request->next;
		pthread_mutex_unlock(&mutex);

		request_destroy(request);
	}
	return 0;
}

/* start a new thread */
static int queue_request(struct request *request)
{
	struct request *pr;
	pthread_t tid;
	int rc;

	request->next = 0;

	pthread_mutex_lock(&mutex);
	pr = requests;
	if (pr) {
		while(pr->next)
			pr = pr->next;
		pr->next = request;
		pthread_mutex_unlock(&mutex);
		return 0;
	}

	requests = request;
	pthread_mutex_unlock(&mutex);
	rc = pthread_create(&tid, 0, thread_requests, 0);
	if (rc == 0)
		return 0;

	ERROR(interface, "not able to start thread: %m");
	pthread_mutex_lock(&mutex);
	requests = requests->next;
	request_destroy(request);
	return -rc;
}


int geturl(const char *url, void (*callback)(void *closure, int status, void *buffer, size_t size), void *closure)
{
	struct request *request;

	if (!init_done) {
		init_done = 1;
		curl_global_init(CURL_GLOBAL_DEFAULT);
	}

	request = request_create(url, callback, closure);
	if (!request) {
		ERROR(interface, "Allocation failed");
		return -ENOMEM;
	}

	return queue_request(request);
}

