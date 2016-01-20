/**
 * @file shell.c
 * Shell implementation for Apteryx.
 *
 * Copyright 2016, Allied Telesis Labs New Zealand, Ltd
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
#include "internal.h"
#include "apteryx.h"
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <setjmp.h>
#include <readline/readline.h>
#include <readline/history.h>

char prompt[] = "/"; /* Prompt */

typedef void handler_t(int);

sigjmp_buf ctrlc_buf;

static void
handle_signals (int signo)
{
    switch (signo)
    {
    case SIGINT:
        /* ctrl-c = clear current input */
        fprintf (stdout, "\n");
        siglongjmp (ctrlc_buf, 1);
        break;
    case SIGQUIT:
        /* ctrl-/ = Quit */
        fprintf (stdout, "\n");
        exit (1);
        break;
    }
}

void
parse_line (char **root, char **extra)
{
    *root = NULL;
    *extra = NULL;
    if (!rl_line_buffer || rl_end == 0)
        return;
    char *line = rl_copy_text (0, rl_end);
    char *slash = strrchr (line, '/');
    if (slash && slash < line + rl_end - 1)
    {
        *extra = strdup (slash + 1);
        *(slash + 1) = '\0';
    }
    *root = line;
    return;
}

GList *
search_matches (char *root, char *pattern)
{
    GList *paths = NULL;
    GList *results;
    GList *iter;

    /* Search for all paths at this root
     * Keep only the matching paths */
    results = apteryx_search (root);
    for (iter = results; iter; iter = g_list_next (iter))
    {
        char *path = (char *) (iter->data);
        if (pattern)
        {
            char *slash = strrchr (path, '/');
            if (strncmp (slash + 1, pattern, strlen (pattern)) == 0)
                paths = g_list_prepend (paths, strdup (path));
        }
        else
        {
            paths = g_list_prepend (paths, strdup (path));
        }
    }
    g_list_free_full (results, free);
    paths = g_list_sort (paths, (GCompareFunc) g_ascii_strcasecmp);
    return paths;
}

int
dump_options (void)
{
    char *root = NULL;
    char *extra = NULL;
    parse_line (&root, &extra);

    /* Display options */
    GList *paths = search_matches (root, extra);
    if (paths)
    {
        GList *iter;
        fprintf (rl_outstream, "\n");
        for (iter = paths; iter; iter = g_list_next (iter))
        {
            char *path = (char *) (iter->data);
            char *slash = strrchr (path, '/');
            fprintf (rl_outstream, " %s\n", slash + 1);
        }
        rl_forced_update_display ();
    }

    g_list_free_full (paths, free);
    free (root);
    free (extra);
    return 1;
}

bool tab_completed = false;
int
complete_line (void)
{
    char *root = NULL;
    char *extra = NULL;
    GList *paths = NULL;

    /* Default to not completed */
    tab_completed = false;

    /* Parse current line */
    parse_line (&root, &extra);

    /* Find any children */
    paths = search_matches (root ? root : "/", extra);

    /* We can tab complete if there are one or more options */
    if (paths)
    {
        char *path = (char *) (paths->data);
        char *slash = strrchr (path, '/');
        if (!root || (slash && extra && g_list_length (paths) == 1 && strcmp (slash + 1, extra) == 0))
        {
            rl_extend_line_buffer (rl_end + 1);
            rl_line_buffer[rl_end++] = '/';
            rl_line_buffer[rl_end] = '\0';
            rl_point = strlen (rl_line_buffer);
            tab_completed = true;
        }
        else if (g_list_length (paths) == 1)
        {
            rl_replace_line (path, 0);
            rl_point = strlen (rl_line_buffer);
            tab_completed = true;
        }

    }
    g_list_free_full (paths, free);
    free (root);
    free (extra);
    return 1;
}

int
handle_keys (int ignore, int key)
{
    static int last_key = -1;
    int ret = 1;

    switch (key)
    {
    case '\t':
        if (!tab_completed && last_key == '\t')
            ret = dump_options ();
        else
            ret = complete_line ();
        break;
    case '?':
        fprintf (rl_outstream, "\nctrl-\\ = quit, ctrl-c = clear, tab = complete\n");
        rl_forced_update_display ();
        break;
    default:
        break;
    }

    last_key = key;
    return ret;
}

void
eval (char *line)
{
    char *value = apteryx_get (line);
    if (value)
    {
        fprintf (rl_outstream, "%s\n", value);
        free (value);
    }
    return;
}

void
apteryx_shell (void)
{
    char shell_prompt[100] = "apteryx > ";
    char* input;

    /* Redirect stderr to stdout */
    dup2 (1, 2);

    /* Catch singals we care about */
    if (signal (SIGINT, handle_signals) == SIG_ERR ||
        signal (SIGQUIT, handle_signals) == SIG_ERR)
    {
        ERROR ("failed to register interrupts with kernel\n");
        exit (-1);
    }

    /* Bind keys we want to override */
    rl_bind_key ('\t', handle_keys);
    rl_bind_key ('?', handle_keys);

    /* Start with at least one entry in the history */
    add_history ("/");

    /* Execute the shell's read/eval loop */
    while (sigsetjmp( ctrlc_buf, 1) != 0);
    while (1)
    {
        /* Display prompt and read input */
        input = readline (shell_prompt);
        if (!input)
          break;

        /* Process the input */
        eval (input);

        /* Add input to history */
        add_history (input);

        /* Free input. */
        free (input);
    }
}
