/**
 * @file config.c
 * Used for Apteryx configuration by Apteryx.
 *
 * Copyright 2015, Allied Telesis Labs New Zealand, Ltd
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this library. If not, see <http://www.gnu.org/licenses/>
 */
#include <glib.h>
#include "apteryx.h"
#include "internal.h"

/* RPC Service */
//extern rpc_instance rpc;

static bool
handle_debug_set (const char *path, const char *value)
{
    if (value)
        apteryx_debug = atoi (value);
    else
        apteryx_debug = false;
    DEBUG ("DEBUG %s\n", apteryx_debug ? "enabled" : "disabled");
    return true;
}

static cb_info_t *
update_callback (GList **list, const char *guid, const char *value)
{
    cb_info_t *cb;
    uint64_t pid, callback, hash;

    /* Parse callback info from the encoded guid */
    if (sscanf (guid, "%"PRIX64"-%"PRIx64"-%"PRIx64"",
            &pid, &callback, &hash) != 3)
    {
        ERROR ("Invalid GUID (%s)\n", guid ?: "NULL");
        return NULL;
    }

    /* Find an existing callback */
    cb = cb_find (list, guid);
    if (!cb && !value)
    {
        DEBUG ("Non-existant Callback GUID(%s)\n", guid);
        return NULL;
    }
    else if (cb && value)
    {
        DEBUG ("Callback GUID(%s) already exists - releasing old version\n", guid);
        cb_destroy (cb);
        cb_release (cb);
    }

    /* Create or destroy */
    if (value)
    {
        /* Create a callback */
        DEBUG ("Callback GUID(%s) created\n", guid);
        cb = cb_create (list, guid, value, pid, callback);
    }
    else
    {
        /* Remove the callback */
        DEBUG ("Callback GUID(%s) released\n", guid);
        cb_destroy (cb);
    }

    /* Return the reference */
    return cb;
}

static bool
handle_indexers_set (const char *path, const char *value)
{
    const char *guid = path + strlen (APTERYX_INDEXERS_PATH"/");
    cb_info_t *cb;

    DEBUG ("CFG-Index: %s = %s\n", guid, value);

    cb = update_callback (&index_list, guid, value);
    cb_release (cb);
    return true;
}

static bool
handle_watchers_set (const char *path, const char *value)
{
    const char *guid = path + strlen (APTERYX_WATCHERS_PATH"/");
    cb_info_t *cb;

    DEBUG ("CFG-Watch: %s = %s\n", guid, value);

    cb = update_callback (&watch_list, guid, value);
    cb_release (cb);
    return true;
}

static bool
handle_providers_set (const char *path, const char *value)
{
    const char *guid = path + strlen (APTERYX_PROVIDERS_PATH"/");
    cb_info_t *cb;

    DEBUG ("CFG-Provide: %s = %s\n", guid, value);

    cb = update_callback (&provide_list, guid, value);
    cb_release (cb);
    return true;
}

static bool
handle_validators_set (const char *path, const char *value)
{
    const char *guid = path + strlen (APTERYX_VALIDATORS_PATH"/");
    cb_info_t *cb;

    DEBUG ("CFG-Validate: %s = %s\n", guid, value);

    cb = update_callback (&validation_list, guid, value);
    cb_release (cb);
    return true;
}

void
config_init (void)
{
    cb_info_t *cb;

    /* Debug set */
    cb = cb_create (&watch_list, "debug", APTERYX_DEBUG_PATH,
            (uint64_t) getpid (), (uint64_t) (size_t) handle_debug_set);
    cb_release (cb);

    /* Indexers */
    cb = cb_create (&watch_list, "indexers", APTERYX_INDEXERS_PATH"/",
            (uint64_t) getpid (), (uint64_t) (size_t) handle_indexers_set);
    cb_release (cb);

    /* Watchers */
    cb = cb_create (&watch_list, "watchers", APTERYX_WATCHERS_PATH"/",
            (uint64_t) getpid (), (uint64_t) (size_t) handle_watchers_set);
    cb_release (cb);

    /* Providers */
    cb = cb_create (&watch_list, "providers", APTERYX_PROVIDERS_PATH"/",
            (uint64_t) getpid (), (uint64_t) (size_t) handle_providers_set);
    cb_release (cb);

    /* Validators */
    cb = cb_create (&watch_list, "validators", APTERYX_VALIDATORS_PATH"/",
            (uint64_t) getpid (), (uint64_t) (size_t) handle_validators_set);
    cb_release (cb);
}
