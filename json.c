/**
 * @file json.c
 * Used for import/export in JSON format.
 *
 * Based on code by:
 * Copyright (C) 2011 Joseph A. Adams (joeyadams3.14159@gmail.com)
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
#include <errno.h>
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
        long i;
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
            sprintf(buf, "%li", node->i);
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

static inline void
skip_space(const char **sp)
{
    const char *s = *sp;
    while (*s == '\t' || *s == '\n' || *s == '\r' || *s == ' ')
        s++;
    *sp = s;
}

static bool
json_parse(const char **sp, json **out)
{
    const char *s = *sp;

    switch (*s) {
        case 'n':
            if (strcmp (s, "null") == 0) {
                *out = json_new (JSON_NULL);
                *sp = s + 4;
                return true;
            }
            return false;

        case 'f':
            if (strcmp (s, "false") == 0) {
                *out = json_new (JSON_BOOL);
                (*out)->b = false;
                *sp = s + 5;
                return true;
            }
            return false;

        case 't':
            if (strcmp (s, "true") == 0) {
                *out = json_new (JSON_BOOL);
                (*out)->b = true;
                *sp = s + 4;
                return true;
            }
            return false;

        case '"': {
            char *str = strchr (s+1, '\"');
            if (str) {
                size_t len = (size_t)str - (size_t)s - 1;
                *out = json_new (JSON_STRING);
                (*out)->s = strndup (s+1, len);
                *sp = s + len + 2;
                return true;
            }
            return false;
        }

        case '{':{
            *out = json_new (JSON_OBJECT);
            s++;
            skip_space (&s);
            while (*s != '}') {
                char *str;
                size_t len;
                char *key;
                json *element;

                if (*s != '\"' || (str = strchr (s+1, '\"')) == NULL) {
                    json_delete (*out);
                    return false;
                }
                len = (size_t)str - (size_t)s - 1;
                key = strndup (s+1, len);
                s = s + len + 2;
                skip_space (&s);

                if (*s++ != ':') {
                   json_delete (*out);
                   free (key);
                   return false;
                }
                skip_space (&s);

                if (!json_parse (&s, &element)) {
                    json_delete (*out);
                    return false;
                }
                json_append (*out, key, element);
                skip_space (&s);
                if (*s != '}' && *s++ != ',') {
                    json_delete (*out);
                    return false;
                }
                skip_space (&s);
            }
            s++;
            *sp = s;
            return true;
        }

        case '[': {
            *out = json_new (JSON_ARRAY);
            s++;
            skip_space (&s);
            while (*s != ']') {
                json *element;
                if (!json_parse (&s, &element)){
                    json_delete (*out);
                    return false;
                }
                json_append (*out, NULL, element);
                skip_space (&s);
                if (*s != ']' && *s++ != ',') {
                    json_delete (*out);
                    return false;
                }
                skip_space (&s);
            }
            s++;
            *sp = s;
            return true;
        }

        default: {
            long num = strtol(s, (char **)sp, 10);
            if (errno != EINVAL) {
                *out = json_new (JSON_INTEGER);
                (*out)->i = num;
                return true;
            }
            return false;
        }
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
json_decode(const char *data)
{
    const char *s = data;
    json *ret;

    if (!json_parse(&s, &ret))
        return NULL;
    if (*s != 0) {
        json_delete(ret);
        return NULL;
    }
    return ret;
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

bool
traverse_object (const char *path, json *object)
{
    char *_path = NULL;
    while (object)
    {
        if (object->type == JSON_OBJECT)
        {
            if (!asprintf (&_path, "%s%s/", path, object->key))
                goto error;
            if (!traverse_object (_path, object->children.head))
                goto error;
            free (_path);
            _path = NULL;
        }
        else if (object->type == JSON_STRING)
        {
            if (!asprintf (&_path, "%s%s", path, object->key))
                goto error;
            if (strlen (object->s) == 0)
            {
                if (!db_delete (_path))
                    goto error;
            }
            else if (!db_add (_path, (unsigned char*)object->s, strlen (object->s)))
                goto error;
            free (_path);
            _path = NULL;
        }
        else
        {
            goto error;
        }
        object = object->next;
    }
    return true;
error:
    if (_path)
        free (_path);
    return false;
}

bool
import_json (const char *path, char *data)
{
    int len = path ? strlen (path) : 0;
    json *tree;

    if (!path || len == 0 || path[0] != '/' ||
        path[len-1] != '/' || !data)
        return false;

    tree = json_decode (data);
    if (!tree || tree->type != JSON_OBJECT)
    {
        json_delete (tree);
        return false;
    }

    if (!traverse_object (path, tree->children.head))
    {
        json_delete (tree);
        return false;
    }

    json_delete (tree);
    return true;
}

#ifdef TEST

void
test_json_null ()
{
    const char *test = "null";
    json *j;
    char *s;

    CU_ASSERT ((j = json_new (JSON_NULL)) != NULL);
    CU_ASSERT ((s = json_encode(j)) != NULL);
    CU_ASSERT (strcmp (s, test) == 0);
    json_delete (j);
    free (s);
    CU_ASSERT (json_decode (" null") == NULL);
    CU_ASSERT (json_decode ("null ") == NULL);
    CU_ASSERT (json_decode ("Null") == NULL);
    CU_ASSERT (json_decode ("nu11") == NULL);
    CU_ASSERT (json_decode ("n ull") == NULL);
    CU_ASSERT ((j = json_decode (test)) != NULL);
    CU_ASSERT (j->type == JSON_NULL);
    CU_ASSERT (j->s == NULL);
    CU_ASSERT (j->children.head == NULL);
    CU_ASSERT (j->children.tail == NULL);
    json_delete (j);
}

void
test_json_bool ()
{
    const char *test_false = "false";
    const char *test_true = "true";
    json *j;
    char *s;

    /* false */
    CU_ASSERT ((j = json_new (JSON_BOOL)) != NULL);
    j->b = false;
    CU_ASSERT ((s = json_encode(j)) != NULL);
    CU_ASSERT (strcmp (s, test_false) == 0);
    json_delete (j);
    free (s);
    CU_ASSERT (json_decode (" false") == NULL);
    CU_ASSERT (json_decode ("false ") == NULL);
    CU_ASSERT (json_decode ("False") == NULL);
    CU_ASSERT (json_decode ("fal5e") == NULL);
    CU_ASSERT (json_decode ("f alse") == NULL);
    CU_ASSERT ((j = json_decode (test_false)) != NULL);
    CU_ASSERT (j->type == JSON_BOOL);
    CU_ASSERT (j->b == false);
    json_delete (j);

    /* true */
    CU_ASSERT ((j = json_new (JSON_BOOL)) != NULL);
    j->b = true;
    CU_ASSERT ((s = json_encode(j)) != NULL);
    CU_ASSERT (strcmp (s, test_true) == 0);
    json_delete (j);
    free (s);
    CU_ASSERT (json_decode (" true") == NULL);
    CU_ASSERT (json_decode ("true ") == NULL);
    CU_ASSERT (json_decode ("True") == NULL);
    CU_ASSERT (json_decode ("tru8") == NULL);
    CU_ASSERT (json_decode ("t rue") == NULL);
    CU_ASSERT ((j = json_decode (test_true)) != NULL);
    CU_ASSERT (j->type == JSON_BOOL);
    CU_ASSERT (j->b == true);
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
    json_delete (j);
    free (s);
    CU_ASSERT ((j = json_decode ("99999")) != NULL);
    CU_ASSERT (j->type == JSON_INTEGER);
    CU_ASSERT (j->i == 99999);
    json_delete (j);

    CU_ASSERT ((j = json_new (JSON_INTEGER)) != NULL);
    j->i = -999;
    CU_ASSERT ((s = json_encode(j)) != NULL);
    CU_ASSERT (strcmp (s, "-999") == 0);
    json_delete (j);
    free (s);
    CU_ASSERT ((j = json_decode ("-999")) != NULL);
    CU_ASSERT (j->type == JSON_INTEGER);
    CU_ASSERT (j->i == -999);
    json_delete (j);

    CU_ASSERT ((j = json_new (JSON_INTEGER)) != NULL);
    j->i = 0;
    CU_ASSERT ((s = json_encode(j)) != NULL);
    CU_ASSERT (strcmp (s, "0") == 0);
    json_delete (j);
    free (s);
    CU_ASSERT ((j = json_decode ("0")) != NULL);
    CU_ASSERT (j->type == JSON_INTEGER);
    CU_ASSERT (j->i == 0);
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
    CU_ASSERT ((j = json_decode ("\"testing12345\"")) != NULL);
    CU_ASSERT (j->type == JSON_STRING);
    CU_ASSERT (strcmp (j->s, "testing12345") == 0);
    json_delete (j);
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
    CU_ASSERT ((parent = json_decode ("{\"key\":\"testing12345\"}")) != NULL);
    CU_ASSERT (parent->type == JSON_OBJECT);
    CU_ASSERT ((child = parent->children.head) != NULL);
    CU_ASSERT (child->type == JSON_STRING);
    CU_ASSERT (child->key && strcmp (child->key, "key") == 0);
    CU_ASSERT (strcmp (child->s, "testing12345") == 0);
    json_delete (parent);
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
    CU_ASSERT ((parent = json_decode ("[\"testing12345\",\"testing67890\"]")) != NULL);
    CU_ASSERT (parent->type == JSON_ARRAY);
    CU_ASSERT ((child1 = parent->children.head) != NULL);
    CU_ASSERT (child1->type == JSON_STRING);
    CU_ASSERT (strcmp (child1->s, "testing12345") == 0);
    CU_ASSERT ((child2 = parent->children.tail) != NULL);
    CU_ASSERT (child2->type == JSON_STRING);
    CU_ASSERT (strcmp (child2->s, "testing67890") == 0);
    json_delete (parent);
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
    CU_ASSERT ((parent2 = json_decode ("{\"parent2\":{\"parent1\":\"testing12345\"}}")) != NULL);
    CU_ASSERT (parent2->type == JSON_OBJECT);
    CU_ASSERT ((parent1 = parent2->children.head) != NULL);
    CU_ASSERT (parent1->type == JSON_OBJECT);
    CU_ASSERT (strcmp (parent1->key, "parent2") == 0);
    CU_ASSERT ((child = parent1->children.head) != NULL);
    CU_ASSERT (child->type == JSON_STRING);
    CU_ASSERT (strcmp (child->key, "parent1") == 0);
    CU_ASSERT (strcmp (child->s, "testing12345") == 0);
    json_delete (parent2);
}

void
test_json_2_children ()
{
    json *parent, *child1, *child2;
    char *s;

    CU_ASSERT ((child1 = json_new (JSON_STRING)) != NULL);
    child1->s = strdup ("testing12345");
    CU_ASSERT ((child2 = json_new (JSON_STRING)) != NULL);
    child2->s = strdup ("testing67890");
    CU_ASSERT ((parent = json_new (JSON_OBJECT)) != NULL);
    json_append (parent, strdup ("child1"), child1);
    json_append (parent, strdup ("child2"), child2);
    CU_ASSERT ((s = json_encode(parent)) != NULL);
    CU_ASSERT (strcmp (s, "{\"child1\":\"testing12345\",\"child2\":\"testing67890\"}") == 0);
    json_delete (parent);
    free (s);
    CU_ASSERT ((parent = json_decode ("{\"child1\":\"testing12345\",\"child2\":\"testing67890\"}")) != NULL);
//    CU_ASSERT (parent->type == JSON_OBJECT);
//    CU_ASSERT ((child1 = parent->children.head) != NULL);
//    CU_ASSERT (child1->type == JSON_STRING);
//    CU_ASSERT (strcmp (child1->key, "child1") == 0);
//    CU_ASSERT (strcmp (child1->s, "testing12345") == 0);
//    CU_ASSERT ((child2 = child1->next) != NULL);
//    CU_ASSERT (child2->type == JSON_STRING);
//    CU_ASSERT (strcmp (child2->key, "parent1") == 0);
//    CU_ASSERT (strcmp (child2->s, "testing67890") == 0);
    json_delete (parent);
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

void
test_json_import_single_node ()
{
    char *path = "/test/json";
    unsigned char *value = NULL;
    size_t size;

    db_init ();
    CU_ASSERT (import_json ("/test/", "{\"json\": \"test\"}"));
    CU_ASSERT (db_get (path, &value, &size));
    CU_ASSERT (value && strcmp ((char*)value, "test") == 0);
    free (value);
    db_delete (path);
    db_shutdown ();
}

void
test_json_import_delete_single_node ()
{
    char *path = "/test/json";
    unsigned char *value = NULL;
    size_t size;

    db_init ();
    db_add (path, (const unsigned char *) "test", strlen ("test") + 1);
    CU_ASSERT (import_json ("/test/", "{\"json\": \"\"}"));
    CU_ASSERT (db_get (path, &value, &size) == false);
    db_shutdown ();
}

void
test_json_import_complex_node ()
{
    char *path = "/test/json";
    unsigned char *value = NULL;
    size_t size;

    db_init ();
    CU_ASSERT (import_json ("/", "{\"test\":{\"json\":\"test\"}}"));
    CU_ASSERT (db_get (path, &value, &size));
    CU_ASSERT (value && strcmp ((char*)value, "test") == 0);
    free (value);
    db_delete (path);
    db_shutdown ();
}

void
test_json_import_delete_complex_node ()
{
    char *path = "/test/json";
    unsigned char *value = NULL;
    size_t size;

    db_init ();
    db_add (path, (const unsigned char *) "test", strlen ("test") + 1);
    CU_ASSERT (import_json ("/", "{\"test\":{\"json\":\"\"}}"));
    CU_ASSERT (db_get (path, &value, &size) == false);
    db_shutdown ();
}

void
test_json_import_invalid_path ()
{
    db_init ();
    CU_ASSERT (import_json ("", "{\"json\": \"test\"}") == false);
    CU_ASSERT (import_json (" ", "{\"json\": \"test\"}") == false);
    CU_ASSERT (import_json ("/test", "{\"json\": \"test\"}") == false);
    db_shutdown ();
}

void
test_json_import_2_nodes ()
{
    const char *path1 = "/test/path1";
    const char *path2 = "/test/path2";
    unsigned char *value = NULL;
    size_t size;

    db_init ();
    CU_ASSERT (import_json ("/test/", "{\"path1\":\"value1\",\"path2\":\"value2\"}"));
    CU_ASSERT (db_get (path1, &value, &size));
    CU_ASSERT (value && strcmp ((char*)value, "value1") == 0);
    free (value);
    db_delete (path1);
    CU_ASSERT (db_get (path2, &value, &size));
    CU_ASSERT (value && strcmp ((char*)value, "value2") == 0);
    free (value);
    db_delete (path2);
    db_shutdown ();
}

void
test_json_import_delete_2_nodes ()
{
    const char *path1 = "/test/path1";
    const char *path2 = "/test/path2";
    unsigned char *value = NULL;
    size_t size;

    db_init ();
    db_add (path1, (const unsigned char *) "value1", strlen ("value1") + 1);
    db_add (path2, (const unsigned char *) "value2", strlen ("value2") + 1);
    CU_ASSERT (import_json ("/test/", "{\"path1\":\"\",\"path2\":\"\"}"));
    CU_ASSERT (db_get (path1, &value, &size) == false);
    CU_ASSERT (db_get (path2, &value, &size) == false);
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
    { "2 children", test_json_2_children },
    { "export empty node", test_json_export_empty_node },
    { "export empty with children", test_json_export_empty_with_children },
    { "export single node", test_json_export_single_node },
    { "export long value", test_json_export_long_value },
    { "export long path", test_json_export_long_path },
    { "export complex node", test_json_export_complex_node },
    { "export 2 nodes", test_json_export_2_nodes },
    { "export 2 deep", test_json_export_2_deep },
    { "export parent has value", test_json_export_parent_value },
    { "import single node", test_json_import_single_node },
    { "import delete single node", test_json_import_delete_single_node },
    { "import complex node", test_json_import_complex_node },
    { "import delete complex node", test_json_import_delete_complex_node },
    { "import invalid path", test_json_import_invalid_path },
    { "import 2 nodes", test_json_import_2_nodes },
    { "import delete 2 nodes", test_json_import_delete_2_nodes },
    CU_TEST_INFO_NULL,
};
#endif
