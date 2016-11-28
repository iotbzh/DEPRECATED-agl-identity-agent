#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

#include <time.h>

#include <systemd/sd-bus.h>
#include <systemd/sd-event.h>

#include "u2f-protocol.h"
#include "u2f-bluez.h"

#ifndef ERROR
#define ERROR(...)  (fprintf(stderr,"ERROR: "),fprintf(stderr,__VA_ARGS__),fprintf(stderr," (%s:%d)\n",__FILE__,__LINE__),1)
#endif

#define CIF(expr)   if((expr) ? (ERROR("%s",#expr), 1) : 0)
#define CRC(end)    do{CIF(rc<0)goto end;}while(0)

#define U2F_BT_PING      0x81
#define U2F_BT_KEEPALIVE 0x82
#define U2F_BT_MSG       0x83
#define U2F_BT_ERROR     0xbf

/*
	UUID: Generic Access Profile    (00001800-0000-1000-8000-00805f9b34fb)
	UUID: Generic Attribute Profile (00001801-0000-1000-8000-00805f9b34fb)
	UUID: Device Information        (0000180a-0000-1000-8000-00805f9b34fb)
	UUID: Battery Service           (0000180f-0000-1000-8000-00805f9b34fb)
	UUID: Fast IDentity Online Al.. (0000fffd-0000-1000-8000-00805f9b34fb)
*/

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
	int rssi_set;
	int service_data_set;
	const char *address;
	int paired;
	int connected;
	int rssi;
	int is_fido;
};

struct device {
	struct device *next;
	char *path;
	char *address;
	char *controlpoint;
	char *status;
	char *cplen;
	sd_bus_slot *slot;
	size_t mtu;
	int paired;
	int connected;
	int rssi;
	int signaled;
};

static struct adapter *adalist;
static struct device *devlist;
static int scanning;

static void (*signal_device_callback)(const char *address);

/********************************************************************************************************/

static int isprefix(const char *what, const char *where)
{
	int n = 0;
	while(what[n] && what[n] == where[n])
		n++;
	return !what[n] && (!where[n] || where[n] == '/');
}

/********************************************************************************************************/

static int add_on_signal(const char *sender, const char *path, const char *itf, const char *member, sd_bus_slot **slot, sd_bus_message_handler_t callback, void *closure)
{
	int rc, n;
	char *p;

	n = asprintf(&p, "type='signal%s%s%s%s%s%s%s%s'",
				sender ? "', sender='" : "",  sender ? sender : "",
				path ? "', path='" : "",  path ? path : "",
				itf ? "', interface='" : "",  itf ? itf : "",
				member ? "', member='" : "",  member ? member : "");
	CIF(n < 0) return -ENOMEM;

	rc = sd_bus_add_match(sbus, slot, p, callback, closure);
	free(p);
	return rc;
}

/********************************************************************************************************/

struct pairing_data {
	struct device *device;
	void (*callback)(void *closure, int paired);
	void *closure;
};

static int pairing_complete(sd_bus_message *m, void *userdata, sd_bus_error *error)
{
	struct pairing_data *data = userdata;

	if (data && data->callback)
		data->callback(data->closure, data->device->paired);
	free(data);

end:
	sd_bus_message_unref(m);
	return 0;
}

static int request_device_pairing(struct device *device, void (*callback)(void *closure, int paired), void *closure)
{
	int rc;
	sd_bus_error error = SD_BUS_ERROR_NULL;
	struct pairing_data *data;

	data = malloc(sizeof *data);
	if (!data) {
		rc= -ENOMEM;
		CRC(end);
	}
	data->device = device;
	data->callback = callback;
	data->closure = closure;

	rc = sd_bus_call_method_async(sbus, NULL, BLUEZ_DEST, device->path, BLUEZ_DEVICE_ITF, "Pair", pairing_complete, data, NULL);
	CRC(end);

end:
	return rc;
}

/********************************************************************************************************/

struct connecting_data {
	struct device *device;
	void (*callback)(void *closure, int connected);
	void *closure;
};

static int connecting_complete(sd_bus_message *m, void *userdata, sd_bus_error *error)
{
	struct connecting_data *data = userdata;

	if (data && data->callback)
		data->callback(data->closure, data->device->connected);
	free(data);

end:
	sd_bus_message_unref(m);
	return 0;
}

static int request_device_connecting(struct device *device, void (*callback)(void *closure, int connected), void *closure)
{
	int rc;
	sd_bus_error error = SD_BUS_ERROR_NULL;
	struct connecting_data *data;

	data = malloc(sizeof *data);
	if (!data) {
		rc= -ENOMEM;
		CRC(end);
	}
	data->device = device;
	data->callback = callback;
	data->closure = closure;

	rc = sd_bus_call_method_async(sbus, NULL, BLUEZ_DEST, device->path, BLUEZ_DEVICE_ITF, "Connect", connecting_complete, data, NULL);
	CRC(end);

end:
	return rc;
}

/********************************************************************************************************/
/* ADAPTER */

static int adapter_set_discover_filter(struct adapter *adapter)
{
	int rc;
	sd_bus_error error = SD_BUS_ERROR_NULL;
	sd_bus_message *m = NULL, *r = NULL;

	rc = sd_bus_message_new_method_call(sbus, &m, BLUEZ_DEST, adapter->path, BLUEZ_ADAPTER_ITF, "SetDiscoveryFilter");
	CRC(end);

	rc = sd_bus_message_open_container(m, SD_BUS_TYPE_ARRAY, "{sv}");
	CRC(end);
	{
	  rc = sd_bus_message_open_container(m, SD_BUS_TYPE_DICT_ENTRY, "sv");
	  CRC(end);
	  {
	    rc = sd_bus_message_append_basic(m, SD_BUS_TYPE_STRING, "UUIDs");
	    CRC(end);

	    rc = sd_bus_message_open_container(m, SD_BUS_TYPE_VARIANT, "as");
	    CRC(end);
	    {
	      rc = sd_bus_message_open_container(m, SD_BUS_TYPE_ARRAY, "s");
	      CRC(end);

	      rc = sd_bus_message_append_basic(m, SD_BUS_TYPE_STRING, fidoProfile);
	      CRC(end);

	      rc = sd_bus_message_close_container(m);
	      CRC(end);
	    }
	    rc = sd_bus_message_close_container(m);
	    CRC(end);
	  }
	  rc = sd_bus_message_close_container(m);
	  CRC(end);

	  rc = sd_bus_message_open_container(m, SD_BUS_TYPE_DICT_ENTRY, "sv");
	  CRC(end);
	  {
	    rc = sd_bus_message_append_basic(m, SD_BUS_TYPE_STRING, "Transport");
	    CRC(end);

	    rc = sd_bus_message_open_container(m, SD_BUS_TYPE_VARIANT, "s");
	    CRC(end);

	    rc = sd_bus_message_append_basic(m, SD_BUS_TYPE_STRING, "le");
	    CRC(end);

	    rc = sd_bus_message_close_container(m);
	    CRC(end);
	  }
	  rc = sd_bus_message_close_container(m);
	  CRC(end);
	}
	rc = sd_bus_message_close_container(m);
	CRC(end);

	rc = sd_bus_call(sbus, m, 0, &error, &r);
	CRC(end);
end:
	sd_bus_message_unref(m);
	sd_bus_message_unref(r);
	return rc;
}

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
	sd_bus_message_unref(m);
	return 0;
}

static int erase_adapter(const char *path)
{
	struct adapter *a, **pa = &adalist;

	while ((a = *pa) && strcmp(a->path, path))
		pa = &a->next;
	if (a) {
		*pa = a->next;
		printf("<<<<<<<<< -ADAPTER %s >>>>>>>>>>>>>\n", path);
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
		if (rc >= 0)
			rc = adapter_set_discover_filter(adapter);
		if (rc < 0) {
			free(adapter->path);
			free(adapter);
			return rc;
		}
		adapter->next = adalist;
		adalist = adapter;
		printf("<<<<<<<<< +ADAPTER %s >>>>>>>>>>>>>\n", path);
	}

	*ada = adapter;
	return 0;
}

/********************************************************************************************************/
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

static int signal_device(struct device *device)
{
	if (scanning && !device->signaled) {
		device->signaled = 1;
		if (signal_device_callback && device->address)
			signal_device_callback(device->address);
	}
}

static int update_device_property(sd_bus_message *m, struct device *device)
{
	struct device_properties props;
	int rc;

	rc = device_properties_scan(m, &props);
	CRC(end);

	if (props.paired_set)
		device->paired = props.paired;

	if (props.connected_set)
		device->connected = props.connected;

	if (props.rssi_set) {
		device->rssi = props.rssi;
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

	if (!strcmp(itf, BLUEZ_DEVICE_ITF))
		rc = update_device_property(m, userdata);
	else
		rc = sd_bus_message_skip(m, NULL);
	CRC(end);

end:
	sd_bus_message_unref(m);
	return 0;
}

static int erase_device(const char *path)
{
	struct device *d, **pd = &devlist;

	while ((d = *pd) && strcmp(d->path, path))
		pd = &d->next;
	if (d) {
		*pd = d->next;
		printf("<<<<<<<<< -DEVICE %s >>>>>>>>>>>>>\n", path);
		sd_bus_slot_unref(d->slot);
		free(d->controlpoint);
		free(d->status);
		free(d->cplen);
		free(d->path);
		free(d);
	}
}

static int get_device(const char *path, struct device **dev, int create)
{
	int rc;
	struct device *d = devlist;

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
		printf("<<<<<<<<< +DEVICE %s >>>>>>>>>>>>>\n", path);
	}
	if (dev)
		*dev = d;
	return 0;
}

/********************************************************************************************************/
/* CHARACTERISTIC */

static struct device *device_of_characteristic(const char *path)
{
	struct device *d = devlist;

	while(d && !isprefix(d->path, path))
		d = d->next;
	return d;
}

static int erase_characteristic(const char *path)
{
	int rc;
	struct device *d = devlist;
	char **p, *q;

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
			printf("<<<<<<<<< -CHARACTERISTIC %s of %s >>>>>>>>>>>>>\n", path, d->path);
		}
	}
	return 0;
}

static int add_characteristic(const char *path, const char *uuid)
{
	int rc;
	struct device *d;
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
			printf("<<<<<<<<< +CHARACTERISTIC %s of %s >>>>>>>>>>>>>\n", path, d->path);
		}
	}
	return 0;
}

/********************************************************************************************************/
/* Discovering */

static int scan(const char *adapter_path, int on)
{
	int rc;
	sd_bus_error error = SD_BUS_ERROR_NULL;
	sd_bus_message *r = NULL;

	rc = sd_bus_call_method(sbus, BLUEZ_DEST, adapter_path, BLUEZ_ADAPTER_ITF, on ? "StartDiscovery" : "StopDiscovery", &error, &r, NULL);
	sd_bus_message_unref(r);
	return rc;
}

/*
static int discover(const char *adapter_path)
{
	int rc;
	sd_bus_error error = SD_BUS_ERROR_NULL;

	rc = sd_bus_set_property(sbus, BLUEZ_DEST, adapter_path, BLUEZ_ADAPTER_ITF, "Pairable", &error, "b", (char)1);
	CRC(end);

	rc = set_discover_filter(adapter_path, 1);
	CRC(end);

	rc = scan(adapter_path, 1);
	CRC(end);
	return 0;
end:
	set_discover_filter(adapter_path, 0);
	return rc;
}
*/

/********************************************************************************************************/
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
	struct device *device;
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
		device->rssi = props.rssi;
		signal_device(device);
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

		printf("+%s[%s]\n", path, itf);

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

/********************************************************************************************************/
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
	sd_bus_message_unref(r);
	return rc;
}

/********************************************************************************************************/

static int add_all_bluez_objects()
{
	int rc;
	sd_bus_error error = SD_BUS_ERROR_NULL;
	sd_bus_message *m = NULL, *r = NULL;

	/* call the manager */
	rc = sd_bus_message_new_method_call(sbus, &r, BLUEZ_DEST, "/", DBUS_OBJECT_MANAGER_ITF, "GetManagedObjects");
	if (rc < 0) {
		ERROR("creation of request for managed objects failed: %s", strerror(-rc));
		return rc;
	}
	rc = sd_bus_call(sbus, r, 0, &error, &m);
	sd_bus_message_unref(r);
	if (rc < 0) {
		ERROR("calling managed objects failed: %s", strerror(-rc));
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
	sd_bus_message_unref(m);
	return rc;
}

/********************************************************************************************************/


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

int u2f_bluez_scan_start(void (*callback)(const char *address))
{
	int rc = 0;
	struct adapter *ada = adalist;
	struct device *dev = devlist;

	scanning = 0;
	while (dev) {
		dev->signaled = 0;
		dev = dev->next;
	}
	signal_device_callback = callback;
	scanning = 1;
	while(!rc && ada) {
		rc = scan(ada->path, 1);
		ada = ada->next;
	}
	return rc;
}
	
int u2f_bluez_scan_stop()
{
	int rc = 0;
	struct adapter *ada = adalist;

	signal_device_callback = 0;
	scanning = 0;
	while(!rc && ada) {
		rc = scan(ada->path, 1);
		ada = ada->next;
	}
	return rc;
}

int u2f_bluez_is_paired(const char *address)
{
	struct device *d = devlist;

	while(d && (!d->address || strcmp(address, d->address)))
		d = d->next;
	if (!d)
		return -ENOENT;

	return !!d->paired;
}


/********************************************************************************************************/

struct sending {
	struct device *device;
	uint8_t *buffer;
	size_t size;
	size_t mtu;
	size_t offset;
	void (*callback)(void *closure, int status, const uint8_t *buffer, size_t size);
	void *closure;
	sd_bus_slot *slot;
	uint8_t cmd;
	uint8_t sts;
};

static void terminate_send(struct sending *sending, int status)
{
	if (sending->slot) {
		sd_bus_call_method_async(sbus, NULL, BLUEZ_DEST, sending->device->status, BLUEZ_GATT_CHARACTERISTIC_ITF, "StopNotify",
				NULL, NULL, NULL);
		sd_bus_slot_unref(sending->slot);
	}
	sending->callback(sending->closure, status < 0 ? status : sending->sts, sending->buffer, sending->size);
	free(sending);
}

static int charac_send_read_value(const char *charac, uint16_t offset, sd_bus_message_handler_t handler, void *closure)
{
	int rc = 0;

	if (!charac)
		rc = -EACCES;
	CRC(end);

	rc = sd_bus_call_method_async(sbus, NULL, BLUEZ_DEST, charac, BLUEZ_GATT_CHARACTERISTIC_ITF, "ReadValue",
				handler, closure, "a{sv}", (unsigned)1, "offset", "q", (uint16_t)0);
	CRC(end);
end:
	return rc;
}

static int sending_status_changed(sd_bus_message *m, void *userdata, sd_bus_error *error)
{
	return 0;
}

static void send_frame(struct sending *sending);

static int send_frame_done(sd_bus_message *m, void *userdata, sd_bus_error *error)
{
	int rc = 0;
	struct sending *sending = userdata;
	size_t off;

	if (sd_bus_error_is_set(error))
		rc = -EACCES;
	CRC(end);

	off = sending->offset;
	off += sending->mtu - 1 - (off ? 0 : 2);
	if (off < sending->size) {
		sending->offset = off;
		send_frame(sending);
		return 0;
	}
	rc = -ENOTSUP;

end:
	if (rc < 0)
		terminate_send(sending, rc);
	return 0;
}

static void send_frame(struct sending *sending)
{
	int rc = 0;
	size_t i, n, sz, mtu, off;
	uint8_t *buffer, *org;
	sd_bus_message *m = NULL;

	n = (sz = sending->size) - (off = sending->offset);
	if (!n)
		return;

	buffer = alloca(mtu = sending->mtu);
	if (off == 0) {
		buffer[0] = sending->cmd;
		buffer[1] = (uint8_t)(sz >> 8);
		buffer[2] = (uint8_t)(sz);
		i = 3;
	} else {
		buffer[0] = (uint8_t)((off / (mtu - 1)) & 0x7f);
		i = 1;
	}

	org = sending->buffer;
	while (i < mtu && off < sz)
		buffer[i++] = org[off++];
/*
	while (i < mtu)
		buffer[i++] = 0;
*/
	rc = sd_bus_message_new_method_call(sbus, &m, BLUEZ_DEST, sending->device->controlpoint, BLUEZ_GATT_CHARACTERISTIC_ITF, "WriteValue");
	CRC(end);

	rc = sd_bus_message_append_array(m, 'y', buffer, i);
	CRC(end);

	rc = sd_bus_message_append(m, "a{sv}", (unsigned)1, "offset", "q", (uint16_t)sending->offset);
	CRC(end);

	rc = sd_bus_call_async(sbus, 0, m, send_frame_done, sending, 5000000);
	CRC(end);

end:
	if (rc < 0)
		terminate_send(sending, rc);
}

static int send_start_notify_done(sd_bus_message *m, void *userdata, sd_bus_error *error)
{
	int rc = 0;
	struct sending *sending = userdata;

	if (sd_bus_error_is_set(error))
		rc = -EACCES;
	CRC(end);

	send_frame(sending);
	
end:
	if (rc < 0)
		terminate_send(sending, rc);
	return 0;
}

static int send_get_mtu_done(sd_bus_message *m, void *userdata, sd_bus_error *error)
{
	uint8_t hi, lo;
	int rc = 0;
	struct sending *sending = userdata;

	if (sd_bus_error_is_set(error))
		rc = -EACCES;
	CRC(end);

	rc = sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, "y");
	CRC(end);

	rc = sd_bus_message_read_basic(m, 'y', &hi);
	CRC(end);

	rc = sd_bus_message_read_basic(m, 'y', &lo);
	CRC(end);

	rc = sd_bus_message_exit_container(m);
	CRC(end);

	sending->mtu = (((size_t)hi) << 8) | ((size_t)lo);

printf("********* MTU = %d   (len=%d) *******\n", (int)sending->mtu, (int)sending->size);

	if (sending->mtu < 3)
		rc = -ECANCELED;
	CRC(end);

	rc = add_on_signal(BLUEZ_DEST, sending->device->status, DBUS_PROPERTIES_ITF, "PropertiesChanged", &sending->slot, sending_status_changed, sending);
	CRC(end);

	rc = sd_bus_call_method_async(sbus, NULL, BLUEZ_DEST, sending->device->status, BLUEZ_GATT_CHARACTERISTIC_ITF, "StartNotify",
				send_start_notify_done, sending, NULL);
	CRC(end);
end:
	if (rc < 0)
		terminate_send(sending, rc);
	return 0;
}

static int send_get_mtu(struct sending *sending)
{
	int rc = 0;
	sd_bus_message *m;

	if (!sending->device->cplen)
		rc = -EACCES;
	CRC(end);

	rc = charac_send_read_value(sending->device->cplen, 0, send_get_mtu_done, sending);
	CRC(end);
end:
	return rc;
}


static void on_connecting_done(void *closure, int connected)
{
	struct sending *sending = closure;
	int rc = connected ? send_get_mtu(sending) : -EACCES;
	if (rc < 0)
		terminate_send(sending, rc);
}

static int send_connect(struct sending *sending)
{
	return sending->device->connected ? send_get_mtu(sending) : request_device_connecting(sending->device, on_connecting_done, sending);
}

static void on_pairing_done(void *closure, int paired)
{
	struct sending *sending = closure;
	int rc = paired ? send_connect(sending) : -EACCES;
	if (rc < 0)
		terminate_send(sending, rc);
}

static int send_pair(struct sending *sending)
{
	return sending->device->paired ? send_connect(sending) : request_device_pairing(sending->device, on_pairing_done, sending);
}

static int send(const char *address, uint8_t cmd, const uint8_t *buffer, size_t size, void (*callback)(void *closure, int status, const uint8_t *buffer, size_t size), void *closure)
{
	int rc = 0;
	struct device *d = devlist;
	struct sending *sending = 0;

	if (size > 65535)
		rc = -EINVAL;
	CRC(error);

	while(d && (!d->address || strcmp(address, d->address)))
		d = d->next;
	if (!d)
		rc = -ENOENT;
	CRC(error);

	sending = calloc(1, sizeof *sending);
	if (!sending)
		rc = -ENOMEM;
	CRC(error);

	sending->buffer = malloc(size);
	if (!sending->buffer)
		rc = -ENOMEM;
	CRC(error);

	sending->device = d;
	memcpy(sending->buffer, buffer, size);
	sending->size = size;
	sending->cmd = cmd;
	sending->callback = callback;
	sending->closure = closure;

	rc = send_pair(sending);
	CRC(error);

	return 0;
error:
	if (sending) {
		free(sending->buffer);
		free(sending);
	}
	return rc;
}

struct sending_message {
	struct u2f_proto *message;
	void (*callback)(void *closure, int status, struct u2f_proto *msg);
	void *closure;
};

static void send_message_complete(void *closure, int status, const uint8_t *buffer, size_t size)
{
	struct sending_message *sending = closure;
	/* TODO */
	sending->callback(sending->closure, status, sending->message);
	u2f_protocol_unref(sending->message);
	free(sending);
}

int u2f_bluez_send_message(const char *address, struct u2f_proto *msg, void (*callback)(void *closure, int status, struct u2f_proto *msg), void *closure)
{
	int rc;
	struct sending_message *sending = 0;
	const uint8_t *buffer;
	size_t size;

	rc = u2f_protocol_get_extended_request(msg, &buffer, &size);
	CRC(error);

	sending = calloc(1, sizeof *sending);
	if (!sending)
		return -ENOMEM;

	sending->message = u2f_protocol_addref(msg);
	sending->callback = callback;
	sending->closure = closure;

	rc = send(address, U2F_BT_MSG, buffer, size, send_message_complete, sending);
	CRC(error);

	return 0;

error:
	if (sending) {
		u2f_protocol_unref(sending->message);
		free(sending);
	}
	return rc;
}



