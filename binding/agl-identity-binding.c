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

#include <errno.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <json-c/json.h>

#define AFB_BINDING_VERSION 1
#include <afb/afb-binding.h>

#include "u2f-bluez.h"
#include "oidc-agent.h"
#include "aia-get.h"

#if !defined(AUTO_START_SCAN)
#define AUTO_START_SCAN 1
#endif

static int expiration_delay = 5;

const struct afb_binding_interface *interface;

static int scanning;

static struct afb_event event;

static struct json_object *current_identity;

static const char default_endpoint[] = "https://agl-graphapi.forgerocklabs.org/getuserprofilefromtoken";
static const char default_vin[] = "4T1BF1FK5GU260429";
static const char *oidc_name;
static char *vin;
static char *endpoint;
static int autoscan = AUTO_START_SCAN;

/***** configuration ********************************************/

static struct json_object *readjson(int fd)
{
	char *buffer;
	struct stat s;
	struct json_object *result = NULL;
	int rc;

	rc = fstat(fd, &s);
	if (rc == 0 && S_ISREG(s.st_mode)) {
		buffer = alloca((size_t)(s.st_size)+1);
		if (read(fd, buffer, (size_t)s.st_size) == (ssize_t)s.st_size) {
			buffer[s.st_size] = 0;
			result = json_tokener_parse(buffer);
		}
	}
	close(fd);

	return result;
}

static struct json_object *get_global_config(const char *name, const char *locale)
{
	int fd = afb_daemon_rootdir_open_locale(interface->daemon, name, O_RDONLY, locale);
	return fd < 0 ? NULL : readjson(fd);
}

static struct json_object *get_local_config(const char *name)
{
	int fd = openat(AT_FDCWD, name, O_RDONLY, 0);
	return fd < 0 ? NULL : readjson(fd);
}

static void confsetstr(struct json_object *conf, const char *name, char **value, const char *def)
{
	struct json_object *v;
	const char *s;
	char *p;

	s = conf && json_object_object_get_ex(conf, name, &v) ? json_object_get_string(v) : def;
	p = *value;
	if (s && p != s) {
		*value = strdup(s);
		free(p);
	}
}

static void confsetint(struct json_object *conf, const char *name, int *value, int def)
{
	struct json_object *v;

	*value = conf && json_object_object_get_ex(conf, name, &v) ? json_object_get_int(v) : def;
}

static void confsetoidc(struct json_object *conf, const char *name)
{
	struct json_object *idp, *appli;

	if (conf
	 && json_object_object_get_ex(conf, "idp", &idp)
	 && json_object_object_get_ex(conf, "appli", &appli)) {
		if (oidc_idp_set(name, idp) && oidc_appli_set(name, name, appli, 1)) {
			oidc_name = name;
		}
	}
}

static void setconfig(struct json_object *conf)
{
	confsetstr(conf, "endpoint", &endpoint, endpoint ? : default_endpoint);
	confsetstr(conf, "vin", &vin, vin ? : default_vin);
	confsetint(conf, "delay", &expiration_delay, expiration_delay);
	confsetint(conf, "autoscan", &autoscan, autoscan);
	confsetoidc(conf, "oidc-aia");
}

static void readconfig()
{
	setconfig(get_global_config("config.json", NULL));
	setconfig(get_local_config("/etc/agl/identity-agent-config.json"));
	setconfig(get_local_config("config.json"));
}

/****************************************************************/

static struct json_object *make_event_object(const char *name, const char *id, const char *nick)
{
	struct json_object *object = json_object_new_object();

	/* TODO: errors */
	json_object_object_add(object, "eventName", json_object_new_string(name));
	json_object_object_add(object, "accountid", json_object_new_string(id));
	if (nick)
		json_object_object_add(object, "nickname", json_object_new_string(nick));
	return object;
}

static int send_event_object(const char *name, const char *id, const char *nick)
{
	return afb_event_push(event, make_event_object(name, id, nick));
}

static void do_login(struct json_object *desc)
{
	struct json_object *object;

	/* switching the user */
	INFO(interface, "Switching to user %s", desc ? json_object_to_json_string(desc) : "null");
	object = current_identity;
	current_identity = json_object_get(desc);
	json_object_put(object);

	if (!json_object_object_get_ex(desc, "name", &object))
		object = 0;
	send_event_object("login", !object ? "null" : json_object_get_string(object)? : "?", 0);
}

static void do_logout()
{
	struct json_object *object;

	INFO(interface, "Switching to no user");
	object = current_identity;
	current_identity = 0;
	json_object_put(object);

	send_event_object("logout", "null", 0);
}

/****************************************************************/

static char *get_upload_url(const char *key)
{
	int rc;
	char *result;

	rc = asprintf(&result, "%s?vin=%s&keytoken=%s", endpoint, vin, key);
	return rc >= 0 ? result : NULL;
}

static void uploaded(void *closure, int status, const void *buffer, size_t size)
{
	struct json_object *object, *subobj;
	char *url = closure;

	/* checks whether discarded */
	if (status == 0 && !buffer)
		goto end; /* discarded */

	/* scan for the status */
	if (status == 0 || !buffer) {
		ERROR(interface, "uploading %s failed %s", url ? : "?", (const char*)buffer ? : "");
		goto end;
	}

	/* get the object */
	DEBUG(interface, "received data: %.*s", (int)size, (char*)buffer);
	object = json_tokener_parse(buffer); /* okay because 0 appended */

	/* extract useful part */
	subobj = NULL;
	if (object && !json_object_object_get_ex(object, "results", &subobj))
		subobj = NULL;
	if (subobj)
		subobj = json_object_array_get_idx(subobj, 0);
	if (subobj && !json_object_object_get_ex(subobj, "data", &subobj))
		subobj = NULL;
	if (subobj)
		subobj = json_object_array_get_idx(subobj, 0);
	if (subobj && !json_object_object_get_ex(subobj, "row", &subobj))
		subobj = NULL;
	if (subobj)
		subobj = json_object_array_get_idx(subobj, 0);

	/* is it a recognized user ? */
	if (!subobj) {
		/* not recognized!! */
		INFO(interface, "unrecognized key for %s", url ? : "?");
		json_object_put(object);
		goto end;
	}

	do_login(subobj);
	json_object_put(object);
end:
	free(url);
}

static void upload_request(const char *address)
{
	char *url = get_upload_url(address);
	if (url)
		aia_get(url, expiration_delay, oidc_name, oidc_name, uploaded, url);
	else
		ERROR(interface, "out of memory");
}

static void key_detected(struct u2f_bluez *device)
{
	const char *address;

	address = u2f_bluez_address(device);
	DEBUG(interface, "Key %s detected", address);
	u2f_bluez_connect(device);
	upload_request(address);
	send_event_object("incoming", address, address);
}

static void scan (struct afb_req request)
{
	int rc;

	if (!scanning) {
		rc = u2f_bluez_scan(key_detected);
		if (rc < 0) {
/*
TODO: solve the issue
			afb_req_fail(request, "failed", "start scan failed");
			return;
*/
			ERROR(interface, "Ignoring scan start failed, because probably already in progress");
		}
		scanning = 1;
	}
	afb_req_success(request, NULL, NULL);
}


static void unscan (struct afb_req request)
{
	u2f_bluez_scan(0);
	scanning = 0;
	afb_req_success(request, NULL, NULL);
}

static void subscribe (struct afb_req request)
{
	int rc;

	rc = afb_req_subscribe(request, event);
	if (rc < 0)
		afb_req_fail(request, "failed", "subscribtion failed");
	else
		afb_req_success(request, NULL, NULL);
}

static void unsubscribe (struct afb_req request)
{
	afb_req_unsubscribe(request, event);
	afb_req_success(request, NULL, NULL);
}

static void login (struct afb_req request)
{
	afb_req_fail(request, "not-implemented-yet", NULL);
}

static void logout (struct afb_req request)
{
	do_logout();
	afb_req_success(request, NULL, NULL);
}

static void get (struct afb_req request)
{
	afb_req_success(request, json_object_get(current_identity), NULL);
}

// NOTE: this sample does not use session to keep test a basic as possible
//       in real application most APIs should be protected with AFB_SESSION_CHECK
static const struct afb_verb_desc_v1 verbs[]= {
  {"subscribe"  , AFB_SESSION_NONE, subscribe    , "subscribe to events"},
  {"unsubscribe", AFB_SESSION_NONE, unsubscribe  , "unsubscribe to events"},
  {"login"      , AFB_SESSION_NONE, login        , "log a user in"},
  {"logout"     , AFB_SESSION_NONE, logout       , "log the current user out"},
  {"get"        , AFB_SESSION_NONE, get          , "get data"},
  {"scan"       , AFB_SESSION_NONE, scan         , "scan for keys"},
  {"unscan"     , AFB_SESSION_NONE, unscan       , "stop scan for keys"},
  {NULL}
};

static const struct afb_binding plugin_desc = {
	.type = AFB_BINDING_VERSION_1,
	.v1 = {
		.info = "AGL identity",
		.prefix = "agl-identity-agent",
		.verbs = verbs
	}
};

const struct afb_binding *afbBindingV1Register (const struct afb_binding_interface *itf)
{
	interface = itf;

	return &plugin_desc;
}

int afbBindingV1ServiceInit(struct afb_service service)
{
	sd_bus *bus = afb_daemon_get_system_bus(interface->daemon);
	int rc = bus ? u2f_bluez_init(bus) : -ENOTSUP;	
	if (rc < 0) {
		errno = -rc;
		return -1;
	}
	event = afb_daemon_make_event(interface->daemon, "event");
	if (!afb_event_is_valid(event))
		return -1;

	readconfig();
	return autoscan ? u2f_bluez_scan(key_detected) : 0;
}

/* vim: set colorcolumn=80: */

