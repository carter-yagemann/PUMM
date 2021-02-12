/*
 * Copyright 2021 Carter Yagemann
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#define _GNU_SOURCE

#include <ctype.h>
#include <dlfcn.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/queue.h>

#include "base64.h"

#ifdef DEBUG
    #define DEBUG_PRINT(...) fprintf(stderr, __VA_ARGS__)
#else
    #define DEBUG_PRINT(...) do {} while (0)
#endif

#define CONFIG_DIR "/.config/uaf-defense/"
#define MAX_POLICY_SIZE 1024

/* Hooks */
typedef void (*free_t)(void *ptr);
free_t real_free;
/* Hooks */


/* Quarantine List */
STAILQ_HEAD(free_head, pending_free) pending_frees =
        STAILQ_HEAD_INITIALIZER(pending_frees);

struct pending_free {
    void *ptr;
    STAILQ_ENTRY(pending_free) entries;
};

void queue_free(void *ptr) {
    struct pending_free *pending;

    if (!real_free)
        real_free = dlsym(RTLD_NEXT, "free");

    pending = malloc(sizeof(struct pending_free));

    if (!pending) {
        fprintf(stderr, "Failed to malloc, cannot queue free\n");
        real_free(ptr);
        return;
    }

    pending->ptr = ptr;

    DEBUG_PRINT("Queueing: %p\n", ptr);
    STAILQ_INSERT_TAIL(&pending_frees, pending, entries);
}

void flush_frees() {
    struct pending_free *pending;

    if (!real_free)
        real_free = dlsym(RTLD_NEXT, "free");

    while (!STAILQ_EMPTY(&pending_frees)) {
        pending = STAILQ_FIRST(&pending_frees);
        STAILQ_REMOVE_HEAD(&pending_frees, entries);

        DEBUG_PRINT("Freeing: %p\n", pending->ptr);
        real_free(pending->ptr);
        real_free(pending);
    }
}
/* Quarantine List */


/* Maps List */
STAILQ_HEAD(maps_head, maps_obj) maps =
        STAILQ_HEAD_INITIALIZER(maps);

struct maps_obj {
    char *name;
    void *offset;
    void *start_va;
    void *end_va;
    STAILQ_ENTRY(maps_obj) entries;
};

void add_maps_obj(char *name, void *offset, void *start_va, void *end_va) {
    char *name_dup = strdup(name);
    struct maps_obj *obj = malloc(sizeof(struct maps_obj));

    if (!obj) {
        fprintf(stderr, "Failed to malloc maps_obj\n");
        return;
    }

    obj->name = name_dup;
    obj->offset = offset;
    obj->start_va = start_va;
    obj->end_va = end_va;

    DEBUG_PRINT("Map: %p-%p %p %s\n", obj->start_va, obj->end_va,
            obj->offset, obj->name);
    STAILQ_INSERT_TAIL(&maps, obj, entries);
}

/*
 * Converts RVA to AVA based on object name.
 *
 * Returns AVA on success, otherwise NULL.
 */
void *rva2ava(char *name, void *rva) {
    struct maps_obj *obj;

    STAILQ_FOREACH(obj, &maps, entries) {
        if (!strcmp(name, obj->name))
            return obj->start_va - obj->offset + rva;
    }

    return NULL;
}
/* Maps List */


/* Profile Management */

void *safe_callers[MAX_POLICY_SIZE] = {NULL};

void rstrip(char *str) {
    char *end;

    end = str + strlen(str) - 1;
    while(end >= str && isspace((unsigned char)*end)) end--;
    end[1] = '\0';
}

/*
 * Loads maps.
 *
 * Returns 0 on success, otherwise 1.
 */
int load_maps() {
    char *line, *ptr_start;
    size_t size = 0;
    FILE *maps_fp;
    unsigned long start_va, end_va, offset;

    if (!real_free)
        real_free = dlsym(RTLD_NEXT, "free");

    maps_fp = fopen("/proc/self/maps", "r");

    if (!maps_fp) {
        DEBUG_PRINT("Failed to open maps\n");
        return 1;
    }

    while (getline(&line, &size, maps_fp) != -1) {
        // get start VA
        start_va = strtoul(line, NULL, 16);

        // get end VA
        ptr_start = strchr(line, '-');
        if (!ptr_start) {
            fprintf(stderr, "Failed to find ending VA: %s", line);
            continue;
        }
        end_va = strtoul(ptr_start + 1, NULL, 16);

        // get offset
        ptr_start = strchr(ptr_start + 1, ' ');
        ptr_start = strchr(ptr_start + 1, ' ');
        if (!ptr_start) {
            fprintf(stderr, "Failed to find offset: %s", line);
            continue;
        }
        offset = strtoul(ptr_start + 1, NULL, 16);

        // get name
        ptr_start = strrchr(ptr_start + 1, ' ');
        if (!ptr_start) {
            fprintf(stderr, "Failed to find name: %s", line);
            continue;
        }
        ptr_start++;
        rstrip(ptr_start);

        if (strlen(ptr_start) > 0)
            add_maps_obj(ptr_start, (void *) offset, (void *)
                    start_va, (void *) end_va);
    }

    if (line)
        real_free(line);

    return 0;
}

void load_profile() {
    char *exe_path, *line, *ptr, *profile_name;
    unsigned long rva;
    void *ava;
    int num_safe_callers = 0;
    char profile_path[PATH_MAX + 1];
    FILE *profile_fp;
    size_t size = 0;
    int base64_len;

    if (!real_free)
        real_free = dlsym(RTLD_NEXT, "free");

    // resolve main object's name
    exe_path = realpath("/proc/self/exe", NULL);
    if (!exe_path) {
        DEBUG_PRINT("Failed to resolve: /proc/self/exe\n");
        goto free_exe_path;
    }

    // resolve and attempt to open profile
    profile_name = base64(exe_path, strlen(exe_path), &base64_len);

    strncpy(profile_path, getenv("HOME"), PATH_MAX);
    strncat(profile_path, CONFIG_DIR, PATH_MAX);
    strncat(profile_path, profile_name, PATH_MAX);

    real_free(profile_name);

    profile_fp = fopen(profile_path, "r");
    if (!profile_fp) {
        DEBUG_PRINT("No Profile: %s\n", profile_path);
        goto free_exe_path;
    }

    DEBUG_PRINT("Loading: %s\n", profile_path);

    // create a maps list to convert between RVA and AVA
    if (load_maps()) {
        fprintf(stderr, "Failed to load maps\n");
        goto free_exe_path;
    }

    while (getline(&line, &size, profile_fp) != -1) {
        ptr = strrchr(line, ':');
        if (!ptr) {
            fprintf(stderr, "Failed to parse profile line: %s", line);
            continue;
        }

        *ptr = '\0';
        rva = strtoul(ptr + 1, NULL, 16);
        ava = rva2ava(line, (void *) rva);

        if (!ava) {
            fprintf(stderr, "Failed to convert RVA to AVA: %s %0lx\n",
                    line, rva);
            continue;
        }

        // insert caller into policy
        DEBUG_PRINT("Policy: %p\n", ava);
        safe_callers[num_safe_callers] = ava;
        num_safe_callers++;

        if (num_safe_callers >= MAX_POLICY_SIZE) {
            fprintf(stderr, "Reached policy size limit\n");
            break;
        }
    }

    if (line)
        real_free(line);

free_exe_path:
    real_free(exe_path);
}

/*
 * Returns 1 if pending_frees should be flushed, otherwise 0.
 */
int should_flush(void *caller) {
    int offset;

    // if no profile is loaded, revert to original behavior
    if (!safe_callers[0])
        return 1;

    for (offset = 0; offset < MAX_POLICY_SIZE; offset++) {
        if (caller == safe_callers[offset])
            return 1;
    }

    return 0;
}
/* Profile Management */


void setup() {
    // resolve hooks
    real_free = dlsym(RTLD_NEXT, "free");

    // initialize lists
    STAILQ_INIT(&pending_frees);
    STAILQ_INIT(&maps);

    load_profile();
}

void free(void *ptr) {
    void *caller = __builtin_extract_return_addr(__builtin_return_address(0));

    DEBUG_PRINT("Requested Free: %p, Caller: %p\n", ptr, caller);

    if (!real_free)
        setup();

    if (should_flush(caller)) {
        flush_frees();
        DEBUG_PRINT("Freeing (quick): %p\n", ptr);
        real_free(ptr);
    } else {
        queue_free(ptr);
    }
}