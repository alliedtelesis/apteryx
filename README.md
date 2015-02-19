# Apteryx
Centralized configuration database.

Stores data in a tree like structure with nodes referenced by
"paths" that have a file system-like format.
i.e. /root/node1/node2/node3 = value

## API
* **SET** - set the value for the specified path
* **WATCH** - watch for changes in the specified path
* **GET** - get the value stored at the specified path
* **PROVIDE** - provide the value stored at the specified path
* **SEARCH** - look for sub-paths that match the requested root path

## Paths
Apteryx paths are similar to unix paths.
* Use forward-slash / as a separator
* Start with a separator
* Spaces are prohibited
* Double separator is prohibited (i.e. "/test//example" is invalid)
* Some functions take a path and a key, this is treated as if they were joined with a separator, i.e. func(path, key, ...) called with ("/test/example", "name",...) would access "/test/example/name"
* Avoid collisions by selecting a starting path that is unique and not shorthand, i.e. "/av" is not acceptable, but "/antivirus" is, preferably the name of the library also matches the path used. 

## Example
```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <apteryx.h>

int
main (int argc, char **argv)
{
    apteryx_set ("/interfaces/eth0/description", "our lan");
    apteryx_set ("/interfaces/eth0/state", "up");
    apteryx_set ("/interfaces/eth1/description", "our wan");
    apteryx_set ("/interfaces/eth1/state", "down");

    printf ("\nInterfaces:\n");
    GList* paths = apteryx_search ("/interfaces/");
    for (GList* _iter= paths; _iter; _iter = _iter->next)
    {
        char *path, *value;
        path = (char *)_iter->data;
        printf ("  %s\n", strrchr (path, '/') + 1);
        value = apteryx_get_string (path, "description");
        printf ("    description     %s\n", value);
        free ((void*)value);
        value = apteryx_get_string (path, "state");
        printf ("    state           %s\n", value);
        free ((void*)value);
    }
    g_list_free_full (paths, free);

    return 0;
}

'''

'''
sudo apt-get install libglib2.0-dev libcunit1-dev libprotobuf-c0-dev protobuf-c-compiler
gcc -o example example.c -I. -L. -lapteryx -std=c99 `pkg-config --cflags glib-2.0` `pkg-config --libs glib-2.0`
LD_LIBRARY_PATH=. ./example

Interfaces:
  eth0
    description      our lan
    state            up
  eth1
    description      our wan
    state            down
'''

## Unit tests
'''
make test
'''

## Client
'''
Usage: apteryx [-h] [-s|-g|-f|-t|-w|-p] [<path>] [<value>]
  -h   show this help
  -d   debug
  -s   set <path>=<value>
  -g   get <path>
  -f   find <path>
  -t   traverse database from <path>
  -w   watch changes to the path <path>
  -p   provide <value> for <path>

  Internal settings
    /apteryx/debug
    /apteryx/counters
    /apteryx/watchers
    /apteryx/providers
    /apteryx/cache
'''

Examples:
'''
./apteryxd -b -p ./apteryxd.pid
LD_LIBRARY_PATH=. ./apteryx -s /interfaces/eth0/description "our lan"
LD_LIBRARY_PATH=. ./apteryx -s /interfaces/eth0/state "up"
LD_LIBRARY_PATH=. ./apteryx -g /interfaces/eth0/description
/interfaces/eth0/description/ = our lan
LD_LIBRARY_PATH=. ./apteryx -t /interfaces/eth0/
/interfaces/eth0/description                                    our lan
/interfaces/eth0/state                                          up
'''
