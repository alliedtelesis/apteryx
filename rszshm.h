/*
 * @file rszshm.h
 *
 * Re-sizeable shared memory support library
 *
 * Licensed under Apache License v2.0: http://www.apache.org/licenses/LICENSE-2.0
 * Copyright 2016 Dan Good <dan@dancancode.com>
 * Modified by Allied Telesis Labs, New Zealand
 *
 * Further info and original code: http://ccodearchive.net/info/rszshm.html
 */

#ifndef CCAN_RSZSHM_H
#define CCAN_RSZSHM_H

#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>

#define typeof __typeof__

/**
 * struct rszshm_scan - parameters for the free region search
 * @start: first address to test
 * @len: size of region to test
 * @hop: offset of the next test
 * @iter: number of attempts
 *
 * See rszshm_mk for search details.
 */
struct rszshm_scan
{
    void *start;
    size_t len;
    size_t hop;
    unsigned iter;
};

#define KiB (1024UL)
#define MiB (KiB*KiB)
#define GiB (MiB*KiB)
#ifdef __x86_64__
#define TiB (GiB*KiB)
#define RSZSHM_DFLT_SCAN (struct rszshm_scan) { (void *) (64*TiB), 4*GiB, 1*TiB, 10 }
#else
#define RSZSHM_DFLT_SCAN (struct rszshm_scan) { (void *) ((1024+512)*MiB), 256*MiB, 256*MiB, 10 }
#endif

/**
 * struct rszshm_hdr - header describing mapped memory
 * @flen: length of the shared file mapping
 * @max: length of the private mapping
 * @addr: address of the mapping
 *
 * The shared region is mapped over the private region.
 * max is the maximum size the shared region can be extended.
 * addr and max are set at creation time and do not change.
 * flen is updated each time the file and shared region is grown.
 */
struct rszshm_hdr
{
    size_t flen;
    size_t max;
    void *addr;
};

/**
 * struct rszshm - handle for a mapped region
 * @fd: file descriptor of the mapped file
 * @flen: length of the mapped shared file in this process
 * @fname: path of the mapped file
 * @hdr: pointer to the mapped region header
 * @dat: pointer to the usable space after the header
 * @cap: length of the usable space after the header
 *
 * flen is updated by rszshm_grow, or by rszshm_up.
 */
#define RSZSHM_PATH_MAX 128
struct rszshm
{
    int fd;
    size_t flen;
    char fname[RSZSHM_PATH_MAX];
    struct rszshm_hdr *hdr;
    void *dat;
    size_t cap;
};

void *rszshm_mk (struct rszshm *r, size_t flen, const char *fname, struct rszshm_scan scan);
#define __4args(a,b,c,d,...) a, b, c, d
#define rszshm_mk(...) rszshm_mk(__4args(__VA_ARGS__, RSZSHM_DFLT_SCAN))

void *rszshm_at (struct rszshm *r, const char *fname);
int rszshm_dt (struct rszshm *r);
int rszshm_up (struct rszshm *r);
int rszshm_grow (struct rszshm *r, size_t size);
int rszshm_unlink (struct rszshm *r);
int rszshm_rmdir (struct rszshm *r);
#endif
