/**
 * @file json.c
 * Used for import/export in JSON format.
 *
 * Copyright 2014, Allied Telesis Labs New Zealand, Ltd
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
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "internal.h"
#ifdef TEST
#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#endif

typedef struct
{
    char *cur;
    char *end;
    char *start;
} string;

static void
sb_puts(string *sb, const char *str)
{
    size_t need = strlen(str);
    if ((size_t)(sb->end - sb->cur) < need)
    {
        size_t length = (size_t)(sb->cur - sb->start);
        size_t alloc = (size_t)(sb->end - sb->start);
        if (alloc == 0) alloc = need;
        while (alloc < length + need) {
            alloc *= 2;
        }
        sb->start = (char*) realloc(sb->start, alloc + 1);
        sb->cur = sb->start + length;
        sb->end = sb->start + alloc;
    }
    memcpy(sb->cur, str, need);
    sb->cur += need;
    *sb->cur = 0;
}

typedef enum {
    JSON_NULL,
    JSON_BOOL,
    JSON_INTEGER,
    JSON_STRING,
    JSON_ARRAY,
    JSON_OBJECT,
} json_type;

typedef struct json json;
struct json
{
    json *parent, *prev, *next;
    json_type type;
    char *key;
    union {
        bool b;
        int i;
        char *s;
        struct {
            json *head, *tail;
        } children;
    };
};

static json *
json_new (json_type type)
{
    json *node = (json*) calloc (1, sizeof(json));
    if (node)
    {
        node->type = type;
    }
    return node;
}

static void
json_delete (json *node)
{
    json *parent, *child, *next;

    if (node == NULL)
        return;

    /* Remove from parent */
    parent = node->parent;
    if (parent != NULL)
    {
        if (node->prev != NULL)
            node->prev->next = node->next;
        else
            parent->children.head = node->next;
        if (node->next != NULL)
            node->next->prev = node->prev;
        else
            parent->children.tail = node->prev;
        if (node->key)
            free (node->key);
        node->parent = NULL;
        node->prev = node->next = NULL;
        node->key = NULL;
    }

    /* Free */
    switch (node->type)
    {
        case JSON_STRING:
            free (node->s);
            break;
        case JSON_ARRAY:
        case JSON_OBJECT:
            for (child = node->children.head; child != NULL; child = next)
            {
                next = child->next;
                json_delete (child);
            }
            break;
        default:
            break;
    }
    free (node);
}

static void
json_append (json *parent, char *key, json *child)
{
    child->parent = parent;
    child->prev = parent->children.tail;
    child->next = NULL;
    child->key = key;

    if (parent->children.tail != NULL)
        parent->children.tail->next = child;
    else
        parent->children.head = child;
    parent->children.tail = child;
}

static void
json_format (string *out, const json *node)
{
    const json *member;
    char buf[64];

    switch (node->type) {
        case JSON_NULL:
            sb_puts(out, "null");
            break;
        case JSON_BOOL:
            sb_puts(out, node->b ? "true" : "false");
            break;
        case JSON_STRING:
            sb_puts(out, "\"");
            sb_puts(out, node->s);
            sb_puts(out, "\"");
            break;
        case JSON_INTEGER:
            sprintf(buf, "%.i", node->i);
            sb_puts(out, buf);
            break;
        case JSON_ARRAY:
            sb_puts(out, "[");
            for (member = node->children.head; member != NULL; member=member->next) {
                json_format(out, member);
                if (member->next != NULL)
                    sb_puts(out, ",");
            }
            sb_puts(out, "]");
            break;
        case JSON_OBJECT:
            sb_puts(out, "{");
            for (member = node->children.head; member != NULL; member=member->next) {
                sb_puts(out, "\"");
                sb_puts(out, member->key);
                sb_puts(out, "\"");
                sb_puts(out, ":");
                json_format(out, member);
                if (member->next != NULL)
                    sb_puts(out, ",");
            }
            sb_puts(out, "}");
            break;
        default:
            break;
    }
}

static char *
json_encode(const json *node)
{
    string s = {};
    json_format (&s, node);
    return s.start;
}

static json *
traverse_path (const char *path)
{
    json *j = NULL;
    int len = strlen (path);
    char *_path = strndup (path, len-1);
    char *key = "";
    GList *children = NULL, *iter;
    unsigned char *value = NULL;
    size_t size;

    /* Get the key */
    if (strrchr(_path, '/'))
        key = strrchr(_path, '/') + 1;

    /* Get value and/or children */
    children = db_search (path);

    /* Value or children */
    if (children == NULL && db_get (_path, &value, &size) && value && size) {
        j = json_new (JSON_STRING);
        j->s = (char*)value;
    }
    else if (children) {
        j = json_new (JSON_OBJECT);
        j->key = strdup (key);
        free (_path);
        for (iter = children; iter; iter = g_list_next (iter))
        {
            if (asprintf(&_path, "%s/", (const char *) iter->data))
            {
                json *child = traverse_path ((const char *) _path);
                key = strrchr(iter->data, '/') + 1;
                json_append (j, strdup (key), child);
                free(_path);
            }
        }
        g_list_free_full(children, free);
    }
    else
    {
        free (_path);
    }

    return j;
}

bool
export_json (const char *path, char **data)
{
    int len = path ? strlen (path) : 0;
    unsigned char *value = NULL;
    size_t size;

    if (!path || len == 0 || path[0] != '/')
        return false;

    if (path[len-1] == '/')
    {
        json *json = traverse_path (path);
        if (json)
        {
            *data = json_encode (json);
            json_delete (json);
            return (*data != NULL);
        }
        return false;
    }

    if (!db_get (path, &value, &size))
        return false;

    if (!asprintf (data, "{\"%s\": \"%s\"}",
            strrchr(path, '/') + 1,
            bytes_to_string(value, size))) {
        free (value);
        return false;
    }
    free (value);
    return true;
}


#ifdef TEST

void
test_json_null ()
{
    json *j;
    char *s;

    CU_ASSERT ((j = json_new (JSON_NULL)) != NULL);
    CU_ASSERT ((s = json_encode(j)) != NULL);
    CU_ASSERT (strcmp (s, "null") == 0);
    free (s);
    json_delete (j);
}

void
test_json_bool ()
{
    json *j;
    char *s;

    CU_ASSERT ((j = json_new (JSON_BOOL)) != NULL);
    j->b = false;
    CU_ASSERT ((s = json_encode(j)) != NULL);
    CU_ASSERT (strcmp (s, "false") == 0);
    free (s);
    j->b = true;
    CU_ASSERT ((s = json_encode(j)) != NULL);
    CU_ASSERT (strcmp (s, "true") == 0);
    free (s);
    json_delete (j);
}

void
test_json_int ()
{
    json *j;
    char *s;

    CU_ASSERT ((j = json_new (JSON_INTEGER)) != NULL);
    j->i = 99999;
    CU_ASSERT ((s = json_encode(j)) != NULL);
    CU_ASSERT (strcmp (s, "99999") == 0);
    free (s);
    j->i = -999;
    CU_ASSERT ((s = json_encode(j)) != NULL);
    CU_ASSERT (strcmp (s, "-999") == 0);
    free (s);
    json_delete (j);
}

void
test_json_string ()
{
    json *j;
    char *s;

    CU_ASSERT ((j = json_new (JSON_STRING)) != NULL);
    j->s = strdup ("testing12345");
    CU_ASSERT ((s = json_encode(j)) != NULL);
    CU_ASSERT (strcmp (s, "\"testing12345\"") == 0);
    json_delete (j);
    free (s);
}

void
test_json_object ()
{
    json *parent, *child;
    char *s;

    CU_ASSERT ((child = json_new (JSON_STRING)) != NULL);
    child->s = strdup ("testing12345");
    CU_ASSERT ((parent = json_new (JSON_OBJECT)) != NULL);
    json_append (parent, strdup ("key"), child);
    CU_ASSERT ((s = json_encode(parent)) != NULL);
    CU_ASSERT (strcmp (s, "{\"key\":\"testing12345\"}") == 0);
    json_delete (parent);
    free (s);
}

void
test_json_array ()
{
    json *parent, *child1, *child2;
    char *s;

    CU_ASSERT ((child1 = json_new (JSON_STRING)) != NULL);
    child1->s = strdup ("testing12345");
    CU_ASSERT ((child2 = json_new (JSON_STRING)) != NULL);
    child2->s = strdup ("testing67890");
    CU_ASSERT ((parent = json_new (JSON_ARRAY)) != NULL);
    json_append (parent, NULL, child1);
    json_append (parent, NULL, child2);
    CU_ASSERT ((s = json_encode (parent)) != NULL);
    CU_ASSERT (strcmp (s, "[\"testing12345\",\"testing67890\"]") == 0);
    json_delete (parent);
    free (s);
}

void
test_json_complex_object ()
{
    json *parent1, *parent2, *child;
    char *s;

    CU_ASSERT ((child = json_new (JSON_STRING)) != NULL);
    child->s = strdup ("testing12345");
    CU_ASSERT ((parent1 = json_new (JSON_OBJECT)) != NULL);
    json_append (parent1, strdup ("parent1"), child);
    CU_ASSERT ((parent2 = json_new (JSON_OBJECT)) != NULL);
    json_append (parent2, strdup ("parent2"), parent1);
    CU_ASSERT ((s = json_encode(parent2)) != NULL);
    CU_ASSERT (strcmp (s, "{\"parent2\":{\"parent1\":\"testing12345\"}}") == 0);
    json_delete (parent2);
    free (s);
}

void
test_json_export_empty_node ()
{
    const char *path = "/test/json";
    char *data = NULL;

    db_init ();
    CU_ASSERT (export_json (path, &data) != true);
    CU_ASSERT (data == NULL);
    db_shutdown ();
}

void
test_json_export_empty_with_children ()
{
    const char *path = "/test/json/child";
    char *data = NULL;

    db_init ();
    db_add (path, (const unsigned char *) "test", strlen ("test") + 1);
    CU_ASSERT (export_json ("/test/json", &data) != true);
    CU_ASSERT (data == NULL);
    db_delete (path);
    db_shutdown ();
}

void
test_json_export_single_node ()
{
    const char *path = "/test/json";
    char *data = NULL;

    db_init ();
    db_add (path, (const unsigned char *) "test", strlen ("test") + 1);
    CU_ASSERT (export_json (path, &data));
    CU_ASSERT (data != NULL);
    CU_ASSERT (strcmp (data, "{\"json\": \"test\"}") == 0);
    free (data);
    db_delete (path);
    db_shutdown ();
}

void
test_json_export_long_value ()
{
    const char *path = "/test/json";
    const char *value = "123456789012345678901234567890"
            "12345678901234567890123456789012345678901234567890"
            "12345678901234567890123456789012345678901234567890"
            "12345678901234567890123456789012345678901234567890"
            "12345678901234567890123456789012345678901234567890"
            "12345678901234567890123456789012345678901234567890"
            "12345678901234567890123456789012345678901234567890";
    char *result = NULL;
    char *data = NULL;

    db_init ();
    db_add (path, (const unsigned char *) value, strlen (value) + 1);
    CU_ASSERT (export_json (path, &data));
    CU_ASSERT (data != NULL);
    CU_ASSERT (asprintf (&result, "{\"json\": \"%s\"}", value));
    CU_ASSERT (strcmp (data, result) == 0);
    free (result);
    free (data);
    db_delete (path);
    db_shutdown ();
}

void
test_json_export_long_path ()
{
    const char *path = "/test/json/1/2/3/4/5/6/7/8/9/0/1/2/3/4/5/6/7/8/9/0"
            "/1/2/3/4/5/6/7/8/9/0/12345678901234567890123456789012345678901234567890";
    char *data = NULL;

    db_init ();
    db_add (path, (const unsigned char *) "test", strlen ("test") + 1);
    CU_ASSERT (export_json (path, &data));
    CU_ASSERT (data != NULL);
    CU_ASSERT (strcmp (data, "{\"12345678901234567890123456789012345678901234567890\": \"test\"}") == 0);
    free (data);
    db_delete (path);
    db_shutdown ();
}

void
test_json_export_complex_node ()
{
    const char *path = "/test/json";
    char *s = NULL;

    db_init ();
    db_add (path, (const unsigned char *) "test", strlen ("test") + 1);
    CU_ASSERT (export_json ("/test/", &s));
    CU_ASSERT (s != NULL);
    CU_ASSERT (strcmp (s, "{\"json\":\"test\"}") == 0);
    free (s);
    db_delete (path);
    db_shutdown ();
}

void
test_json_export_2_nodes ()
{
    const char *path1 = "/test/path1";
    const char *path2 = "/test/path2";
    char *s = NULL;

    db_init ();
    db_add (path1, (const unsigned char *) "value1", strlen ("value1") + 1);
    db_add (path2, (const unsigned char *) "value2", strlen ("value2") + 1);
    CU_ASSERT (export_json ("/test/", &s));
    CU_ASSERT (s != NULL);
    CU_ASSERT (strcmp (s, "{\"path1\":\"value1\",\"path2\":\"value2\"}") == 0);
    free (s);
    db_delete (path1);
    db_delete (path2);
    db_shutdown ();
}

void
test_json_export_2_deep ()
{
    const char *path = "/test/path1/path2";
    char *s = NULL;

    db_init ();
    db_add (path, (const unsigned char *) "value", strlen ("value") + 1);
    CU_ASSERT (export_json ("/test/", &s));
    CU_ASSERT (s != NULL);
    CU_ASSERT (strcmp (s, "{\"path1\":{\"path2\":\"value\"}}") == 0);
    free (s);
    db_delete (path);
    db_shutdown ();
}

void
test_json_export_parent_value ()
{
    const char *path1 = "/test/path1";
    const char *path2 = "/test/path1/path2";
    char *s = NULL;

    db_init ();
    db_add (path1, (const unsigned char *) "value1", strlen ("value1") + 1);
    db_add (path2, (const unsigned char *) "value2", strlen ("value2") + 1);
    CU_ASSERT (export_json ("/test/", &s));
    CU_ASSERT (s != NULL);
    CU_ASSERT (strcmp (s, "{\"path1\":{\"path2\":\"value2\"}}") == 0);
    free (s);
    db_delete (path1);
    db_delete (path2);
    db_shutdown ();
}

CU_TestInfo tests_json[] = {
    { "null", test_json_null },
    { "bool", test_json_bool },
    { "integer", test_json_int },
    { "string", test_json_string },
    { "object", test_json_object },
    { "array", test_json_array },
    { "complex object", test_json_complex_object },
    { "empty node", test_json_export_empty_node },
    { "empty with children", test_json_export_empty_with_children },
    { "single node", test_json_export_single_node },
    { "long value", test_json_export_long_value },
    { "long path", test_json_export_long_path },
    { "complex node", test_json_export_complex_node },
    { "2 nodes", test_json_export_2_nodes },
    { "2 deep", test_json_export_2_deep },
    { "parent has value", test_json_export_parent_value },
    CU_TEST_INFO_NULL,
};
#endif
