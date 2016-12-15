<img src=apteryx.jpg width=300 height=300 />

Centralized configuration database.

Stores data in a tree like structure with nodes referenced by
"paths" that have a file system-like format.
i.e. /root/node1/node2/node3 = value

## API
* **SET** - set the value for the specified path
* **VALIDATE** - accept / deny sets that match the specified path
* **WATCH** - watch for changes in the specified path
* **GET** - get the value stored at the specified path
* **PROVIDE** - provide the value stored at the specified path
* **SEARCH** - look for sub-paths that match the requested root path
* **INDEX** - provide search results for the specified root path
* **PRUNE** - from a requested root path, set values for all sub-paths to NULL
* **PROXY** - proxy gets and sets to the requested path via the specified URL

## Paths
Apteryx paths are similar to unix paths.
* Use forward-slash / as a separator
* Start with a separator
* Spaces are prohibited
* Double separator is prohibited (i.e. "/test//example" is invalid)
* Some functions take a path and a key, this is treated as if they were joined with a separator, i.e. func(path, key, ...) called with ("/test/example", "name",...) would access "/test/example/name"
* Avoid collisions by selecting a starting path that is unique and not shorthand, i.e. "/av" is not acceptable, but "/antivirus" is, preferably the name of the library also matches the path used. 
* Full paths include the Apteryx instance url e.g.
```
UNIX       "unix:///<unix-path>[:<apteryx-path>]"    e.g. unix:///tmp/apteryx:/system/hostname
TCP(IPv4)  "tcp://<IPv4>:<port>[:<apteryx-path>]"    e.g. tcp://192.168.1.2:9999:/system/hostname
TCP(IPv6)  "tcp:[<IPv6>]:<port>[:<apteryx-path>]"    e.g. tcp://[fc00::1]:9999:/system/hostname
```

## Validating
Care must be taken when registering validation functions with apteryx_validate. Calls made to apteryx_set will block until the apteryx_validate callback is processed - this introduces a possible loop that can only be broken with a timeout. In order to avoid this, a process should avoid setting a value that it validates itself, and particularly avoid doing this from a watch callback.

## Simple Example
```
#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <apteryx.h>

#define SYSTEM_PATH "/system"
#define SYSTEM_HOSTNAME SYSTEM_PATH "/hostname"
#define SYSTEM_TIMEZONE SYSTEM_PATH "/timezone"
#define SYSTEM_TIME SYSTEM_PATH "/time"

bool watch_timezone (const char *path, const char *value)
{
	char *cmd = NULL;

	/* When the timezone is unset, use UTC */
	if (value == NULL)
	{
		value = "UTC";
	}

	/* Create symlink from /etc/localtime to /usr/share/zoneinfo/(value) */
	asprintf (&cmd, "ln -sf /usr/share/zoneinfo/%s /etc/localtime", value);
	system (cmd);
	free (cmd);
	return true;
}

char *provide_time (const char *path)
{
	char *ret = NULL;
	time_t rawtime;

	time ( &rawtime );
	ret = strdup (ctime (&rawtime));
	char *nl = strchr (ret, '\n');
	nl[0] = '\0';
	return ret;
}

int main (int argc, char *argv[])
{
	char *value;

	apteryx_init (false);
	apteryx_watch (SYSTEM_TIMEZONE, watch_timezone);
	apteryx_provide (SYSTEM_TIME, provide_time);
	apteryx_set (SYSTEM_HOSTNAME, "host1");
	value = apteryx_get (SYSTEM_TIME);
	printf ("%s\n", value);
	free ((void*)value);
	while (1)
	{
		sleep (100);
	}
}
```

```
sudo apt-get install libglib2.0-dev libcunit1-dev liblua5.2-dev
gcc -o clockd clockd.c -I. -L. -lapteryx -std=c99 `pkg-config --cflags glib-2.0` `pkg-config --libs glib-2.0`
LD_LIBRARY_PATH=. ./clockd &
```

```
apteryx -g /clock/time
apteryx -s /clock/timezone NZ # This might require you to run clockd as root
apteryx -g /clock/time
```

## Unit tests
```
make test
```

## Client
```
Usage: apteryx [-h] [-s|-g|-f|-t|-w|-p|-x|-l] [<path>] [<value>]
  -h   show this help
  -d   debug
  -s   set <path>=<value>
  -g   get <path>
  -f   find <path>
  -t   traverse database from <path>
  -w   watch changes to the path <path>
  -p   provide <value> for <path>
  -x   proxy <path> via url <value>
  -l   last change <path>

  Internal settings
    /apteryx/debug
    /apteryx/sockets
    /apteryx/watchers
    /apteryx/providers
    /apteryx/validators
    /apteryx/proxies
    /apteryx/counters
```

Examples:
```
./apteryxd -b -p apteryx.pid
LD_LIBRARY_PATH=. ./apteryx -s /interfaces/eth0/description "our lan"
LD_LIBRARY_PATH=. ./apteryx -s /interfaces/eth0/state "up"
LD_LIBRARY_PATH=. ./apteryx -g /interfaces/eth0/description
/interfaces/eth0/description/ = our lan
LD_LIBRARY_PATH=. ./apteryx -t /interfaces/eth0/
/interfaces/eth0/description                                    our lan
/interfaces/eth0/state                                          up
./apteryxd -b -p apteryx2.pid -l tcp://127.0.0.1:9999
LD_LIBRARY_PATH=. ./apteryx -s tcp://127.0.0.1:9999:/test/dog cat
LD_LIBRARY_PATH=. ./apteryx -g /remote/node/test/dog
LD_LIBRARY_PATH=. ./apteryx -x /remote/node/* tcp://127.0.0.1:9999
LD_LIBRARY_PATH=. ./apteryx -g /remote/node/test/dog
```

