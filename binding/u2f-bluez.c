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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

#include <time.h>

#include <systemd/sd-bus.h>
#include <systemd/sd-event.h>


#include "u2f-bluez.h"

#if defined(FOR_AFB_BINDING)
# include <afb/afb-binding.h>
  extern const struct afb_binding_interface *interface;
#else
# define ERROR(itf,...)  (fprintf(stderr,"ERROR: ")&&fprintf(stderr,__VA_ARGS__)&&fprintf(stderr," (%s:%d)\n",__FILE__,__LINE__))
# define DEBUG(itf,...)  (fprintf(stderr,"DEBUG: ")&&fprintf(stderr,__VA_ARGS__)&&fprintf(stderr," (%s:%d)\n",__FILE__,__LINE__))
#endif

#define CIF(expr)   if((expr) ? (ERROR(interface, "%s",#expr), 1) : 0)
#define CRC(end)    do{if(rc<0){ERROR(interface, "rc<0");goto end;}}while(0)

#define U2F_BT_PING      0x81
#define U2F_BT_KEEPALIVE 0x82
#define U2F_BT_MSG       0x83
#define U2F_BT_ERROR     0xbf

static const char fidoProfile[] = "0000fffd-0000-1000-8000-00805f9b34fb";
static const char batteryProfile[] = "0000180f-0000-1000-8000-00805f9b34fb";

static const char u2fControlPoint[] = "F1D0FFF1-DEAA-ECEE-B42F-C9BA7ED623BB";
static const char u2fStatus[] = "F1D0FFF2-DEAA-ECEE-B42F-C9BA7ED623BB";
static const char u2fControlPointLength[] = "F1D0FFF3-DEAA-ECEE-B42F-C9BA7ED623BB";
static const char u2fServiceRevisionBitfield[] = "F1D0FFF4-DEAA-ECEE-B42F-C9BA7ED623BB";
static const uint16_t u2fServiceRevision = 0x2A28;

static const char BLUEZ_DEST[] = "org.bluez";
static const char BLUEZ_PATH[] = "/org/bluez";
static const char BLUEZ_AGENT_MANAGER_ITF[] = "org.bluez.AgentManager1";
static const char BLUEZ_AGENT_ITF[] = "org.bluez.Agent1";
static const char BLUEZ_ADAPTER_ITF[] = "org.bluez.Adapter1";
static const char BLUEZ_DEVICE_ITF[] = "org.bluez.Device1";
static const char BLUEZ_GATT_SERVICE_ITF[] = "org.bluez.GattService1";
static const char BLUEZ_GATT_CHARACTERISTIC_ITF[] = "org.bluez.GattCharacteristic1";

static const char DBUS_OBJECT_MANAGER_ITF[] = "org.freedesktop.DBus.ObjectManager";
static const char DBUS_PROPERTIES_ITF[] = "org.freedesktop.DBus.Properties";

static const char PAIRINGOBJECT[] = "/pairing";


static sd_bus *sbus;

struct adapter_properties {
	int powered_set;
	int discovering_set;
	int powered;
	int discovering;
};

struct adapter {
	struct adapter *next;
	sd_bus_slot *slot;
	char *path;
	int powered;
	int discovering;
};

struct device_properties {
	int is_fido_set;
	int address_set;
	int paired_set;
	int connected_set;
	int resolved_set;
	int rssi_set;
	int service_data_set;
	const char *address;
	int paired;
	int connected;
	int resolved;
	int rssi;
	int is_fido;
};

struct observer
{
	struct observer *next;
	void *closure;
	struct u2f_bluez_observer callbacks;
};

struct u2f_bluez {
	struct u2f_bluez *next;
	struct observer *observers;
	unsigned refcount;
	int starting;
	char *path;
	char *address;
	char *controlpoint;
	char *status;
	char *cplen;
	sd_bus_slot *slot;
	sd_bus_slot *slotc;
	size_t mtu;
	int paired;
	int connected;
	int resolved;
	int rssi;
	int signaled;
};

static struct adapter *adalist;
static struct u2f_bluez *devlist;
static void (*scanning_callback)(struct u2f_bluez *device);

/************************************************/

static int isprefix(const char *what, const char *where)
{
	int n = 0;
	while(what[n] && what[n] == where[n])
		n++;
	return !what[n] && (!where[n] || where[n] == '/');
}

/************************************************/

static int add_on_signal(const char *sender, const char *path, const char *itf, const char *member,
				sd_bus_slot **slot, sd_bus_message_handler_t callback, void *closure)
{
	int rc, n;
	char *p;

	n = asprintf(&p, "type='signal%s%s%s%s%s%s%s%s'",
				sender ? "', sender='" : "",  sender ? sender : "",
				path ? "', path='" : "",  path ? path : "",
				itf ? "', interface='" : "",  itf ? itf : "",
				member ? "', member='" : "",  member ? member : "");
	if (n < 0) {
		ERROR(interface, "n < 0");
		return -ENOMEM;
	}

	rc = sd_bus_add_match(sbus, slot, p, callback, closure);
	free(p);
	return rc;
}

/************************************************/

/************************************************/
/* ADAPTER */

static int adapter_properties_scan(sd_bus_message *m, struct adapter_properties *props)
{
	int rc;
	char t, b;
	const char *name, *type;

	memset(props, 0, sizeof *props);

	rc = sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, NULL);
	CRC(end);

	while (!sd_bus_message_at_end(m, 0)) {

		rc = sd_bus_message_enter_container(m, SD_BUS_TYPE_DICT_ENTRY, NULL);
		CRC(end);

		rc = sd_bus_message_read_basic(m, SD_BUS_TYPE_STRING, &name);
		CRC(end);

		rc = sd_bus_message_peek_type(m, &t, &type);
		CRC(end);

		rc = sd_bus_message_enter_container(m, SD_BUS_TYPE_VARIANT, NULL);
		CRC(end);

		if (!strcmp(name, "Powered") && !strcmp(type, "b")) {
			rc = sd_bus_message_read_basic(m, 'b', &b);
			CRC(end);
			props->powered = b;
			props->powered_set = 1;
		} else if (!strcmp(name, "Discovering") && !strcmp(type, "b")) {
			rc = sd_bus_message_read_basic(m, 'b', &b);
			CRC(end);
			props->discovering = b;
			props->discovering_set = 1;
		} else {
			rc = sd_bus_message_skip(m, type);
			CRC(end);
		}

		rc = sd_bus_message_exit_container(m);
		CRC(end);

		rc = sd_bus_message_exit_container(m);
		CRC(end);
	}

	rc = sd_bus_message_exit_container(m);
	CRC(end);

end:
	return rc;
}

static int update_adapter_property(sd_bus_message *m, struct adapter *adapter)
{
	struct adapter_properties props;
	int rc;

	rc = adapter_properties_scan(m, &props);
	CRC(end);

	if (props.powered_set)
		adapter->powered = props.powered;

	if (props.discovering_set)
		adapter->discovering = props.discovering;

end:
	return rc;
}

static int adapter_property_changed(sd_bus_message *m, void *userdata, sd_bus_error *ret_error)
{
	int rc;
	const char *itf;

	rc = sd_bus_message_read_basic(m, SD_BUS_TYPE_STRING, &itf);
	CRC(end);

	if (!strcmp(itf, BLUEZ_DEVICE_ITF))
		rc = update_adapter_property(m, userdata);
	else
		rc = sd_bus_message_skip(m, NULL);
	CRC(end);

end:
	//sd_bus_message_unref(m);
	return 0;
}

static void erase_adapter(const char *path)
{
	struct adapter *a, **pa = &adalist;

	while ((a = *pa) && strcmp(a->path, path))
		pa = &a->next;
	if (a) {
		*pa = a->next;
		DEBUG(interface, "<<<<<<<<< -ADAPTER %s >>>>>>>>>>>>>", path);
		sd_bus_slot_unref(a->slot);
		free(a->path);
		free(a);
	}
}

static int get_adapter(const char *path, struct adapter **ada, int create)
{
	int rc;
	struct adapter *adapter = adalist;

	/* get the adapter */
	while (adapter && strcmp(adapter->path, path))
		adapter = adapter->next;

	if (!adapter) {
		adapter = malloc(sizeof *adapter);
		if (!adapter)
			return -ENOMEM;
		adapter->path = strdup(path);
		if (!adapter->path) {
			free(adapter);
			return -ENOMEM;
		}
		rc = add_on_signal(BLUEZ_DEST, path, DBUS_PROPERTIES_ITF, "PropertiesChanged", &adapter->slot, adapter_property_changed, adapter);
		if (rc < 0) {
			free(adapter->path);
			free(adapter);
			return rc;
		}
		adapter->next = adalist;
		adalist = adapter;
		DEBUG(interface, "<<<<<<<<< +ADAPTER %s >>>>>>>>>>>>>", path);
	}

	*ada = adapter;
	return 0;
}

/************************************************/

static void signal_connected(struct u2f_bluez *device)
{
	struct observer *obs, *nxt;

	obs = device->observers;
	while (obs) {
		nxt = obs->next;
		if (obs->callbacks.connected)
			obs->callbacks.connected(obs->closure);
		obs = nxt;
	}
}

static void signal_disconnected(struct u2f_bluez *device)
{
	struct observer *obs, *nxt;

	obs = device->observers;
	while (obs) {
		nxt = obs->next;
		if (obs->callbacks.disconnected)
			obs->callbacks.disconnected(obs->closure);
		obs = nxt;
	}
}

static void signal_started(struct u2f_bluez *device)
{
	struct observer *obs, *nxt;

	obs = device->observers;
	while (obs) {
		nxt = obs->next;
		if (obs->callbacks.started)
			obs->callbacks.started(obs->closure, device->mtu);
		obs = nxt;
	}
}

static void signal_received(struct u2f_bluez *device, const uint8_t *buffer, size_t size)
{
	struct observer *obs, *nxt;

	obs = device->observers;
	while (obs) {
		nxt = obs->next;
		if (obs->callbacks.received)
			obs->callbacks.received(obs->closure, buffer, size);
		obs = nxt;
	}
}

static void signal_sent(struct u2f_bluez *device)
{
	struct observer *obs, *nxt;

	obs = device->observers;
	while (obs) {
		nxt = obs->next;
		if (obs->callbacks.sent)
			obs->callbacks.sent(obs->closure);
		obs = nxt;
	}
}

static void signal_stopped(struct u2f_bluez *device)
{
	struct observer *obs, *nxt;

	obs = device->observers;
	while (obs) {
		nxt = obs->next;
		if (obs->callbacks.stopped)
			obs->callbacks.stopped(obs->closure);
		obs = nxt;
	}
}

static void signal_error(struct u2f_bluez *device, int status, const char *message)
{
	struct observer *obs, *nxt;

	obs = device->observers;
	while (obs) {
		nxt = obs->next;
		if (obs->callbacks.error)
			obs->callbacks.error(obs->closure, status, message);
		obs = nxt;
	}
}

/************************************************/
/* DEVICE */

static struct adapter *adapter_of_device(const char *path)
{
	struct adapter *a = adalist;

	while(a && !isprefix(a->path, path))
		a = a->next;
	return a;
}

static int device_properties_scan(sd_bus_message *m, struct device_properties *props)
{
	int rc;
	int16_t rssi;
	char t, b;
	const char *name, *type, *str;

	memset(props, 0, sizeof *props);

	rc = sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, NULL);
	CRC(end);

	while (!sd_bus_message_at_end(m, 0)) {

		rc = sd_bus_message_enter_container(m, SD_BUS_TYPE_DICT_ENTRY, NULL);
		CRC(end);

		rc = sd_bus_message_read_basic(m, SD_BUS_TYPE_STRING, &name);
		CRC(end);

		rc = sd_bus_message_peek_type(m, &t, &type);
		CRC(end);

		rc = sd_bus_message_enter_container(m, SD_BUS_TYPE_VARIANT, NULL);
		CRC(end);

		if (!strcmp(name, "Paired") && !strcmp(type, "b")) {
			rc = sd_bus_message_read_basic(m, 'b', &b);
			CRC(end);
			props->paired = b;
			props->paired_set = 1;
		} else if (!strcmp(name, "Connected") && !strcmp(type, "b")) {
			rc = sd_bus_message_read_basic(m, 'b', &b);
			CRC(end);
			props->connected = b;
			props->connected_set = 1;
		} else if (!strcmp(name, "ServicesResolved") && !strcmp(type, "b")) {
			rc = sd_bus_message_read_basic(m, 'b', &b);
			CRC(end);
			props->resolved = b;
			props->resolved_set = 1;
		} else if (!strcmp(name, "RSSI") && !strcmp(type, "n")) {
			rc = sd_bus_message_read_basic(m, 'n', &rssi);
			CRC(end);
			props->rssi = rssi;
			props->rssi_set = 1;
		} else if (!strcmp(name, "Address") && !strcmp(type, "s")) {
			rc = sd_bus_message_read_basic(m, 's', &str);
			CRC(end);
			props->address = str;
			props->address_set = 1;
		} else if (!strcmp(name, "ServiceData") && !strcmp(type, "a{sv}")) {
			rc = sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, NULL);
			CRC(end);
			rc = sd_bus_message_enter_container(m, SD_BUS_TYPE_DICT_ENTRY, NULL);
			CRC(end);
			rc = sd_bus_message_read_basic(m, 's', &str);
			CRC(end);
			if (!strcasecmp(str, fidoProfile))
				props->is_fido = 1;
			rc = sd_bus_message_skip(m, NULL);
			CRC(end);
			rc = sd_bus_message_exit_container(m);
			CRC(end);
			rc = sd_bus_message_exit_container(m);
			CRC(end);
			props->service_data_set = 1;
		} else if (!strcmp(name, "UUIDs") && !strcmp(type, "as")) {
			rc = sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, NULL);
			CRC(end);
			while (!sd_bus_message_at_end(m, 0)) {
				rc = sd_bus_message_read_basic(m, 's', &str);
				CRC(end);
				if (!strcasecmp(str, fidoProfile))
					props->is_fido = 1;
			}
			props->is_fido_set = 1;
			rc = sd_bus_message_exit_container(m);
		} else {
			rc = sd_bus_message_skip(m, type);
			CRC(end);
		}

		rc = sd_bus_message_exit_container(m);
		CRC(end);

		rc = sd_bus_message_exit_container(m);
		CRC(end);
	}

	rc = sd_bus_message_exit_container(m);
	CRC(end);

end:
	return rc;
}

static void signal_device(struct u2f_bluez *device)
{
	if (scanning_callback && !device->signaled) {
/*
		device->signaled = 1;
*/
		scanning_callback(device);
	}
}

static void get_mtu(struct u2f_bluez *device);

static int update_device_property(sd_bus_message *m, struct u2f_bluez *device)
{
	struct device_properties props;
	int rc;

	rc = device_properties_scan(m, &props);
	CRC(end);

	if (props.paired_set) {
		device->paired = props.paired;
//printf("props of itf: paired = %d\n", props.paired);
	}

	if (props.connected_set) {
		device->connected = props.connected;
//printf("props of itf: connected = %d\n", props.connected);
		if (props.connected)
			signal_connected(device);
		else
			signal_disconnected(device);
	}

	if (props.resolved_set) {
		device->resolved = props.resolved;
//printf("props of itf: resolved = %d\n", props.resolved);
		if (device->resolved && device->starting)
			get_mtu(device);
	}

	if (props.rssi_set) {
		device->rssi = props.rssi;
//printf("props of itf: rssi = %d\n", props.rssi);
		signal_device(device);
	}

	if (!props.rssi_set && props.service_data_set && props.is_fido) {
//printf("props of itf: extra signaling\n");
		signal_device(device);
	}

end:
	return rc;
}

static int device_property_changed(sd_bus_message *m, void *userdata, sd_bus_error *ret_error)
{
	int rc;
	const char *itf;

	rc = sd_bus_message_read_basic(m, SD_BUS_TYPE_STRING, &itf);
	CRC(end);
//printf("props of itf %s\n", itf);
	if (!strcmp(itf, BLUEZ_DEVICE_ITF))
		rc = update_device_property(m, userdata);
	else
		rc = sd_bus_message_skip(m, NULL);
	CRC(end);

end:
	//sd_bus_message_unref(m);
	return 0;
}

static void erase_device(const char *path)
{
	struct u2f_bluez *d, **pd = &devlist;

	while ((d = *pd) && strcmp(d->path, path))
		pd = &d->next;
	if (d) {
		*pd = d->next;
		DEBUG(interface, "<<<<<<<<< -DEVICE %s >>>>>>>>>>>>>", path);
		sd_bus_slot_unref(d->slot);
		sd_bus_slot_unref(d->slotc);
		free(d->controlpoint);
		free(d->status);
		free(d->cplen);
		free(d->path);
		free(d);
	}
}

static int get_device(const char *path, struct u2f_bluez **dev, int create)
{
	int rc;
	struct u2f_bluez *d = devlist;

	while(d && strcmp(path, d->path))
		d = d->next;

	if (!d) {
		d = calloc(1, sizeof *d);
		if (!d)
			return -ENOMEM;
		d->path = strdup(path);
		if (!d->path) {
			free(d);
			return -ENOMEM;
		}
		rc = add_on_signal(BLUEZ_DEST, path, DBUS_PROPERTIES_ITF, "PropertiesChanged", &d->slot, device_property_changed, d);
		if (rc < 0) {
			free(d->path);
			free(d);
			return rc;
		}
		d->next = devlist;
		devlist = d;
		DEBUG(interface, "<<<<<<<<< +DEVICE %s >>>>>>>>>>>>>", path);
	}
	if (dev)
		*dev = d;
	return 0;
}

/************************************************/
/* CHARACTERISTIC */

static struct u2f_bluez *device_of_characteristic(const char *path)
{
	struct u2f_bluez *d = devlist;

	while(d && !isprefix(d->path, path))
		d = d->next;
	return d;
}

static int erase_characteristic(const char *path)
{
	struct u2f_bluez *d = devlist;
	char **p;

	d = device_of_characteristic(path);
	if (d) {
		if (d->controlpoint && !strcmp(d->controlpoint, path))
			p = &d->controlpoint;
		else if (d->status && !strcmp(d->status, path))
			p = &d->status;
		else if (d->cplen && !strcmp(d->cplen, path))
			p = &d->cplen;
		else
			p = 0;
		if (p) {
			free(*p);
			*p = 0;
//			printf("<<<<<<<<< -CHARACTERISTIC %s of %s >>>>>>>>>>>>>\n", path, d->path);
		}
	}
	return 0;
}

static int add_characteristic(const char *path, const char *uuid)
{
	struct u2f_bluez *d;
	char **p, *q;

	d = device_of_characteristic(path);

	if (d) {
		if (uuid == u2fControlPoint)
			p = &d->controlpoint;
		else if (uuid == u2fStatus)
			p = &d->status;
		else if (uuid == u2fControlPointLength)
			p = &d->cplen;
		else
			p = 0;
		if (p) {
			if (!*p || strcmp(*p, path)) {
				q = strdup(path);
				if (!q)
					return -ENOMEM;
				free(*p);
				*p = q;
			}
//			printf("<<<<<<<<< +CHARACTERISTIC %s of %s >>>>>>>>>>>>>\n", path, d->path);
		}
	}
	return 0;
}

/************************************************/
/* Discovering */

static int scan(const char *adapter_path, int on)
{
	int rc;
	sd_bus_error error = SD_BUS_ERROR_NULL;
	sd_bus_message *r = NULL;

	rc = sd_bus_call_method(sbus, BLUEZ_DEST, adapter_path, BLUEZ_ADAPTER_ITF, on ? "StartDiscovery" : "StopDiscovery", &error, &r, NULL);
	//sd_bus_message_unref(r);
	return rc;
}

/************************************************/
/* Observers for InterfacesAdded / InterfacesRemoved */

static int add_bluez_adapter(sd_bus_message *m, const char *path)
{
	int rc;
	struct adapter *adapter;
	struct adapter_properties props;

	rc = get_adapter(path, &adapter, 1);
	CRC(end);

	rc = adapter_properties_scan(m, &props);
	CRC(end);

	if (props.powered_set)
		adapter->powered = props.powered;

	if (props.discovering_set)
		adapter->discovering = props.discovering;

end:
	return rc;
}

static int add_bluez_device(sd_bus_message *m, const char *path)
{
	int rc;
	struct u2f_bluez *device;
	struct device_properties props;
	char *address;

	rc = device_properties_scan(m, &props);
	CRC(end);

	if (props.is_fido_set && props.is_fido) {
		address = strdup(props.address_set ? props.address : "?");
		rc = address ? 0 : -ENOMEM;
		CRC(end);
		rc = get_device(path, &device, 1);
		CRC(end);
		free(device->address);
		device->address = address;
		device->paired = props.paired;
		device->connected = props.connected;
		device->resolved = props.resolved;
		if (props.rssi_set) {
			device->rssi = props.rssi;
			signal_device(device);
		}
	}

end:
	return rc;
}

static int scan_characteristic(sd_bus_message *m, const char **uuid)
{
	int rc;
	char t;
	const char *name, *type, *value;

	*uuid = 0;

	rc = sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, NULL);
	CRC(end);

	while (!sd_bus_message_at_end(m, 0)) {

		rc = sd_bus_message_enter_container(m, SD_BUS_TYPE_DICT_ENTRY, NULL);
		CRC(end);

		rc = sd_bus_message_read_basic(m, SD_BUS_TYPE_STRING, &name);
		CRC(end);

		rc = sd_bus_message_peek_type(m, &t, &type);
		CRC(end);

		rc = sd_bus_message_enter_container(m, SD_BUS_TYPE_VARIANT, NULL);
		CRC(end);

		if (!strcmp(name, "UUID") && !strcmp(type, "s")) {
			rc = sd_bus_message_read_basic(m, 's', &value);
			CRC(end);
			if (!strcasecmp(value, u2fControlPoint))
				*uuid = u2fControlPoint;
			else if (!strcasecmp(value, u2fStatus))
				*uuid = u2fStatus;
			else if (!strcasecmp(value, u2fControlPointLength))
				*uuid = u2fControlPointLength;
			else if (!strcasecmp(value, u2fServiceRevisionBitfield))
				*uuid = u2fServiceRevisionBitfield;
		} else {
			rc = sd_bus_message_skip(m, type);
			CRC(end);
		}

		rc = sd_bus_message_exit_container(m);
		CRC(end);

		rc = sd_bus_message_exit_container(m);
		CRC(end);
	}

	rc = sd_bus_message_exit_container(m);
	CRC(end);

end:
	return rc;
}

static int add_bluez_characteristic(sd_bus_message *m, const char *path)
{
	int rc;
	const char *uuid;

	rc = scan_characteristic(m, &uuid);
	CRC(end);

	if (uuid) {
		rc = add_characteristic(path, uuid);
		CRC(end);
	}

end:
	return rc;
}

static int add_bluez_object(sd_bus_message *m)
{
	int rc, isdev, ischar, isada;
	const char *itf, *path;

	/*
	 * path
	 */
	rc = sd_bus_message_read_basic(m, SD_BUS_TYPE_OBJECT_PATH, &path);
	CRC(end);

	/*
	 * m: DICT<STRING,DICT<STRING,VARIANT>>
	 *    a{sa{sv}}
	 */
	rc = sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, NULL);
	CRC(end);

	while (!sd_bus_message_at_end(m, 0)) {

		rc = sd_bus_message_enter_container(m, SD_BUS_TYPE_DICT_ENTRY, NULL);
		CRC(end);

		rc = sd_bus_message_read_basic(m, SD_BUS_TYPE_STRING, &itf);
		CRC(end);

//		printf("+%s[%s]\n", path, itf);

		isdev = !strcmp(itf, BLUEZ_DEVICE_ITF);
		ischar = !strcmp(itf, BLUEZ_GATT_CHARACTERISTIC_ITF);
		isada = !strcmp(itf, BLUEZ_ADAPTER_ITF);

		if (isada)
			rc = add_bluez_adapter(m, path);
		else if (isdev)
			rc = add_bluez_device(m, path);
		else if (ischar)
			rc = add_bluez_characteristic(m, path);
		else
			rc = sd_bus_message_skip(m, NULL);

		rc = sd_bus_message_exit_container(m);
		CRC(end);
	}
	rc = sd_bus_message_exit_container(m);

end:
	return rc;
}

static int on_interface_added(sd_bus_message *m, void *userdata, sd_bus_error *ret_error)
{
	add_bluez_object(m);
	return 0;
}

static int on_interface_removed(sd_bus_message *m, void *userdata, sd_bus_error *ret_error)
{
	int rc, isdev = 0, ischar = 0, isada = 0;
	const char *itf, *path;

	/*
	 * path
	 */
	rc = sd_bus_message_read_basic(m, SD_BUS_TYPE_OBJECT_PATH, &path);
	CRC(end);

	/*
	 * removed interfaces: as
	 */
	rc = sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, NULL);
	CRC(end);

	while (!sd_bus_message_at_end(m, 0)) {

		rc = sd_bus_message_read_basic(m, SD_BUS_TYPE_STRING, &itf);
		CRC(end);

		isdev  |= !strcmp(itf, BLUEZ_DEVICE_ITF);
		ischar |= !strcmp(itf, BLUEZ_GATT_CHARACTERISTIC_ITF);
		isada  |= !strcmp(itf, BLUEZ_ADAPTER_ITF);

	}
	rc = sd_bus_message_exit_container(m);
	CRC(end);

	/*
	 * remove items if found
	 */
	if (isada)
		erase_adapter(path);

	else if (isdev)
		erase_device(path);

	else if (ischar)
		erase_characteristic(path);

end:
	return 0;
}

static int add_default_observers()
{
	sd_bus_slot *slot;
	int rc;

	rc = add_on_signal(BLUEZ_DEST, "/", DBUS_OBJECT_MANAGER_ITF, "InterfacesAdded", &slot, on_interface_added, NULL);
	CRC(end);

	rc = add_on_signal(BLUEZ_DEST, "/", DBUS_OBJECT_MANAGER_ITF, "InterfacesRemoved", &slot, on_interface_removed, NULL);
	CRC(end);

end:
	return rc;
}

/************************************************/
/* PAIRING AGENT */

static sd_bus_slot *pairing_slot;

static int pairing_agent(sd_bus_message *m, void *userdata, sd_bus_error *ret_error)
{
	int rc;
	const char *member;

	if (strcmp(BLUEZ_AGENT_ITF, sd_bus_message_get_interface(m)))
		return 0;

	member = sd_bus_message_get_member(m);
	if (!strcmp(member, "RequestPasskey"))
		rc = sd_bus_reply_method_return(m, "u", (uint32_t)0);
	else if (!strcmp(member, "RequestAuthorization") || !strcmp(member, "RequestService"))
		rc = sd_bus_reply_method_return(m, NULL);
	else
		return 0;
	return rc < 0 ? rc : 1;
}

static int register_pairing_agent()
{
	int rc;
	sd_bus_error error = SD_BUS_ERROR_NULL;
	sd_bus_message *r = NULL;

	rc = sd_bus_add_object(sbus, &pairing_slot, PAIRINGOBJECT, pairing_agent, 0);
	CRC(end);

	rc = sd_bus_call_method(sbus, BLUEZ_DEST, BLUEZ_PATH, BLUEZ_AGENT_MANAGER_ITF, "RegisterAgent", &error, &r, "os", PAIRINGOBJECT, "KeyboardOnly");
	CRC(end);
end:
	//sd_bus_message_unref(r);
	return rc;
}

/************************************************/

static int add_all_bluez_objects()
{
	int rc;
	sd_bus_error error = SD_BUS_ERROR_NULL;
	sd_bus_message *m = NULL, *r = NULL;

	/* call the manager */
	rc = sd_bus_message_new_method_call(sbus, &r, BLUEZ_DEST, "/", DBUS_OBJECT_MANAGER_ITF, "GetManagedObjects");
	if (rc < 0) {
		ERROR(interface, "creation of request for managed objects failed: %s", strerror(-rc));
		return rc;
	}
	rc = sd_bus_call(sbus, r, 0, &error, &m);
	//sd_bus_message_unref(r);
	if (rc < 0) {
		ERROR(interface, "calling managed objects failed: %s", strerror(-rc));
		return rc;
	}

	/*
	 * GetManagedObjects -> DICT<OBJPATH,DICT<STRING,DICT<STRING,VARIANT>>>
	 *                      a{oa{sa{sv}}}
	 */
	rc = sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, NULL);
	CRC(end);

	while (!sd_bus_message_at_end(m, 0)) {

		rc = sd_bus_message_enter_container(m, SD_BUS_TYPE_DICT_ENTRY, NULL);
		CRC(end);

		rc = add_bluez_object(m);
		CRC(end);

		rc = sd_bus_message_exit_container(m);
		CRC(end);

	}
	rc = sd_bus_message_exit_container(m);
end:
	//sd_bus_message_unref(m);
	return rc;
}

/************************************************/


int u2f_bluez_init(sd_bus *bus)
{
	int rc;

	sbus = sd_bus_ref(bus);

	rc = register_pairing_agent();
	CRC(end);

	rc = add_default_observers();
	CRC(end);

	rc = add_all_bluez_objects();
	CRC(end);
end:
	return rc;
}

int u2f_bluez_scan(void (*callback)(struct u2f_bluez *device))
{
	int rc = 0;
	struct adapter *ada = adalist;
	struct u2f_bluez *dev = devlist;

	scanning_callback = callback;
	while (dev) {
		dev->signaled = 0;
		dev = dev->next;
	}
	while(!rc && ada) {
		rc = scan(ada->path, !!scanning_callback);
		ada = ada->next;
	}
	return rc;
}
	
struct u2f_bluez *u2f_bluez_addref(struct u2f_bluez *device)
{
	if (device)
		device->refcount++;
	return device;
}

void u2f_bluez_unref(struct u2f_bluez *device)
{
	if (device && device->refcount)
		if (!--device->refcount)
			{/*do-nothing*/}
}

int u2f_bluez_get(struct u2f_bluez **device, const char *address)
{
	struct u2f_bluez *d = devlist;

	while(d && (!d->address || strcmp(address, d->address)))
		d = d->next;
	if (!d)
		return -ENOENT;
	if (device)
		*device = u2f_bluez_addref(d);

	return 0;
}

const char *u2f_bluez_address(struct u2f_bluez *device)
{
	return device->address;
}

int u2f_bluez_is_paired(struct u2f_bluez *device)
{
	return !!device->paired;
}

int u2f_bluez_is_connected(struct u2f_bluez *device)
{
	return !!device->connected;
}



















int u2f_bluez_observer_add(struct u2f_bluez *device, struct u2f_bluez_observer *observer, void *closure)
{
	struct observer **prv, *obs;

	prv = &device->observers;
	while ((obs = *prv) && (obs->closure != closure || memcmp(observer, &obs->callbacks, sizeof *observer)))
		prv = &obs->next;

	if (!obs) {
		obs = calloc(1, sizeof *obs);
		if (!obs)
			return -ENOMEM;

		obs->closure = closure;
		memcpy(&obs->callbacks, observer, sizeof *observer);
		*prv = obs;
	}
	return 0;
}

int u2f_bluez_observer_delete(struct u2f_bluez *device, struct u2f_bluez_observer *observer, void *closure)
{
	struct observer **prv, *obs;

	prv = &device->observers;
	while ((obs = *prv) && (obs->closure != closure || memcmp(observer, &obs->callbacks, sizeof *observer)))
		prv = &obs->next;

	if (!obs)
		return -ENOENT;

	*prv = obs->next;
	free(obs);
	return 0;
}



/************************************************/

static int charac_status_changed(sd_bus_message *m, void *userdata, sd_bus_error *error)
{
	uint8_t *frame;
	const char *name;
	size_t size;
	int rc = 0;
	struct u2f_bluez *device = userdata;

	if (sd_bus_error_is_set(error) || sd_bus_message_is_method_error(m, NULL))
		rc = -EACCES;
	CRC(end);

	rc = sd_bus_message_skip(m, "s");
	CRC(end);

	rc = sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, "{sv}");
	CRC(end);

	frame = 0;
	size = 0;
	while (!sd_bus_message_at_end(m, 0)) {

		rc = sd_bus_message_enter_container(m, SD_BUS_TYPE_DICT_ENTRY, NULL);
		CRC(end);

		rc = sd_bus_message_read_basic(m, SD_BUS_TYPE_STRING, &name);
		CRC(end);

		if (strcmp(name, "Value")) {
			rc = sd_bus_message_skip(m, NULL);
			CRC(end);
		} else {
			rc = sd_bus_message_enter_container(m, SD_BUS_TYPE_VARIANT, "ay");
			CRC(end);

			rc = sd_bus_message_read_array(m, 'y', (const void**)&frame, &size);
			CRC(end);

			if (!frame || !size)
				rc = -EACCES;
			CRC(end);

			rc = sd_bus_message_exit_container(m);
			CRC(end);
		}

		rc = sd_bus_message_exit_container(m);
		CRC(end);
	}
	rc = sd_bus_message_exit_container(m);
	CRC(end);

	if (!frame)
		goto end;

	signal_received(device, frame, size);

end:
	if (rc < 0)
		signal_error(device, rc, "status change error");
	return 0;
}

/************************************************/

static int stop_complete(sd_bus_message *m, void *userdata, sd_bus_error *error)
{
	struct u2f_bluez *device = userdata;

	if (sd_bus_error_is_set(error) || sd_bus_message_is_method_error(m, NULL)) {
		signal_error(device, -EPROTO, "failed to stop notify");
	} else
		signal_stopped(device);

	u2f_bluez_unref(device);
	//sd_bus_message_unref(m);
	return 0;
}

void u2f_bluez_stop(struct u2f_bluez *device)
{
	int rc;

	device->starting = 0;
	if (!device->slotc)
		signal_stopped(device);
	else {
		sd_bus_slot_unref(device->slotc);
		device->slotc = 0;
		device->mtu = 0;
		rc = sd_bus_call_method_async(sbus, NULL, BLUEZ_DEST, device->status, BLUEZ_GATT_CHARACTERISTIC_ITF, "StopNotify", stop_complete, device, NULL);
		if (rc >= 0)
			u2f_bluez_addref(device);
		else
			signal_error(device, -EPROTO, "can't stop notify");
	}	
}


/************************************************/

static void disconnecting_error(struct u2f_bluez *device, int status, const char *message)
{
	u2f_bluez_disconnect(device);
	signal_error(device, status, message);
}

static int ignoremsg(sd_bus_message *m, void *userdata, sd_bus_error *error)
{
	//sd_bus_message_unref(m);
	return 0;
}

void u2f_bluez_disconnect(struct u2f_bluez *device)
{
	if (device->slotc)
		u2f_bluez_stop(device);
	sd_bus_call_method_async(sbus, NULL, BLUEZ_DEST, device->path, BLUEZ_DEVICE_ITF, "Disconnect", ignoremsg, NULL, NULL);
	device->mtu = 0;
}

/************************************************/

static void start(struct u2f_bluez *device)
{
	device->starting = 0;
	signal_started(device);
}

static int notify_status_complete(sd_bus_message *m, void *userdata, sd_bus_error *error)
{
	struct u2f_bluez *device = userdata;

	if (sd_bus_error_is_set(error) || sd_bus_message_is_method_error(m, NULL)) {
		disconnecting_error(device, -EPROTO, "failed to start notify");
		sd_bus_slot_unref(device->slotc);
		device->slotc = 0;
	} else
		start(device);

	u2f_bluez_unref(device);
	//sd_bus_message_unref(m);
	return 0;
}

static void notify_status(struct u2f_bluez *device)
{
	int rc;

	if (device->slotc)
		start(device);
	else {
		rc = add_on_signal(BLUEZ_DEST, device->status, DBUS_PROPERTIES_ITF, "PropertiesChanged", &device->slotc, charac_status_changed, device);
		if (rc < 0)
			disconnecting_error(device, -EPROTO, "failed observe status");
		else {
			rc = sd_bus_call_method_async(sbus, NULL, BLUEZ_DEST, device->status, BLUEZ_GATT_CHARACTERISTIC_ITF, "StartNotify",
					notify_status_complete, device, NULL);
			if (rc >= 0)
				u2f_bluez_addref(device);
			else {
				disconnecting_error(device, -EPROTO, "can't start notify");
				sd_bus_slot_unref(device->slotc);
				device->slotc = 0;
			}
		}
	}
}

/************************************************/

static int get_mtu_complete(sd_bus_message *m, void *userdata, sd_bus_error *error)
{
	const uint8_t *array;
	size_t mtu, size;
	int rc = 0;
	struct u2f_bluez *device = userdata;

	if (sd_bus_error_is_set(error) || sd_bus_message_is_method_error(m, NULL))
		disconnecting_error(device, -EPROTO, "failed to get mtu");
	else {
		rc = sd_bus_message_read_array(m, 'y', (const void**)&array, &size);
		if (rc < 0 || size != 2)
			disconnecting_error(device, -EPROTO, "bad answer from get mtu");
		else {
			mtu = (((size_t)array[0]) << 8) | ((size_t)array[1]);
//printf("********* MTU = %d *******\n", (int)mtu);
			if (mtu < 3)
				disconnecting_error(device, -EPROTO, "bad MTU");
			else {
				device->mtu = mtu;
				notify_status(device);
			}
		}
	}

	u2f_bluez_unref(device);
	//sd_bus_message_unref(m);
	return 0;
}

static void get_mtu(struct u2f_bluez *device)
{
	int rc;

	if (!device->cplen || !device->status || !device->controlpoint)
		disconnecting_error(device, -EPROTO, "failed to connect GATT");
	else if (device->mtu != 0)
		notify_status(device);
	else {
		rc = sd_bus_call_method_async(sbus, NULL, BLUEZ_DEST, device->cplen, BLUEZ_GATT_CHARACTERISTIC_ITF, "ReadValue",
				get_mtu_complete, device, "a{sv}", (unsigned)0);
		if (rc >= 0)
			u2f_bluez_addref(device);
		else
			disconnecting_error(device, -EPROTO, "can't get MTU");
	}
}

/************************************************/

static void connected(struct u2f_bluez *device)
{
	if (device->starting && device->resolved)
		get_mtu(device);
}

static int connecting_complete(sd_bus_message *m, void *userdata, sd_bus_error *error)
{
	struct u2f_bluez *device = userdata;

	if (!device->connected)
		disconnecting_error(device, -EPROTO, "failed to connect");
	else
		connected(device);

	u2f_bluez_unref(device);
	//sd_bus_message_unref(m);
	return 0;
}

static void connect(struct u2f_bluez *device)
{
	int rc;
	if (device->connected)
		connected(device);
	else {
		rc = sd_bus_call_method_async(sbus, NULL, BLUEZ_DEST, device->path, BLUEZ_DEVICE_ITF, "Connect", connecting_complete, device, NULL);
		if (rc >= 0)
			u2f_bluez_addref(device);
		else
			disconnecting_error(device, -EPROTO, "can't connect");
	}
}

/************************************************/

static int pairing_complete(sd_bus_message *m, void *userdata, sd_bus_error *error)
{
	struct u2f_bluez *device = userdata;

	if (device->paired)
		connect(device);
	else
		disconnecting_error(device, -EPROTO, "failed to pair");
	u2f_bluez_unref(device);
	//sd_bus_message_unref(m);
	return 0;
}

void u2f_bluez_connect(struct u2f_bluez *device)
{
	int rc;

	if (device->paired)
		connect(device);
	else {
		rc = sd_bus_call_method_async(sbus, NULL, BLUEZ_DEST, device->path, BLUEZ_DEVICE_ITF, "Pair", pairing_complete, device, NULL);
		if (rc >= 0)
			u2f_bluez_addref(device);
		else
			disconnecting_error(device, -EPROTO, "can't pair");
	}
}

void u2f_bluez_start(struct u2f_bluez *device)
{
	device->starting = 1;
	u2f_bluez_connect(device);
}

/************************************************/

static int send_complete(sd_bus_message *m, void *userdata, sd_bus_error *error)
{
	struct u2f_bluez *device = userdata;

	if (sd_bus_error_is_set(error) || sd_bus_message_is_method_error(m, NULL))
		signal_error(device, -EACCES, "failed to write");
	else
		signal_sent(device);

	//sd_bus_message_unref(m);
	return 0;
}

void u2f_bluez_send(struct u2f_bluez *device, const uint8_t *buffer, size_t size)
{
	int rc = 0;
	sd_bus_message *m = NULL;

	rc = sd_bus_message_new_method_call(sbus, &m, BLUEZ_DEST, device->controlpoint, BLUEZ_GATT_CHARACTERISTIC_ITF, "WriteValue");
	CRC(end);

	rc = sd_bus_message_append_array(m, 'y', buffer, size);
	CRC(end);

	rc = sd_bus_message_append(m, "a{sv}", (unsigned)0);
	CRC(end);

	rc = sd_bus_call_async(sbus, 0, m, send_complete, device, 5000000);
	CRC(end);

end:
	if (rc < 0)
		signal_error(device, -EACCES, "can't write");
	//sd_bus_message_unref(m);
}

