/*
 * @file rszshm.c
 *
 * Re-sizeable shared memory support library
 *
 * Licensed under Apache License v2.0: http://www.apache.org/licenses/LICENSE-2.0
 * Copyright 2016 Dan Good <dan@dancancode.com>
 * Modified by Allied Telesis Labs, New Zealand
 *
 * Further info and original code: http://ccodearchive.net/info/rszshm.html
 */
#include "rszshm.h"

#define _XOPEN_SOURCE 700
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/file.h>
#include "syslog.h"

#define pgup(x, pgsz) (((x) + (pgsz) - 1) & ~((pgsz) - 1))

/**
 * Clean up after shared memory mapping failure
 * @mem: Pointer returned by mmap()
 * @rshm: Pointer to handle
 * @len: Length of the attempted mmap()
 * @err: errno
 * @return: The passed-in errno result
 */
static int
rszshm_cleanup (void *mem, struct rszshm *rshm, size_t len, int err)
{
    if (mem && mem != MAP_FAILED)
    {
        munmap (mem, len);
    }
    if (rshm->fd != -1)
    {
        close (rshm->fd);
        if (rshm->fname[0])
        {
            unlink (rshm->fname);
        }
    }
    rshm->dat = NULL;
    return err;
}

/**
 * Attempt to map virtual memory according to the scan parameters
 * @scan: The scan parameters to attempt
 * @return: Pointer to the mapped memory, or NULL on failure
 */
static void *
rszshm_scan_map (struct rszshm_scan *scan)
{
    int i;
    void *mem = NULL;
    void *tgt;

    for (i = 1, tgt = scan->start; i <= scan->iter; i++)
    {
        mem =
            mmap (tgt, scan->len, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANON | MAP_NORESERVE, -1, 0);
        if (mem == MAP_FAILED)
        {
            return NULL;
        }
        if (mem == tgt)
        {
            break;
        }
        munmap (mem, scan->len);
        mem = NULL;
        tgt += (i % 2 == 0 ? 1 : -1) * i * scan->hop;
    }
    return mem;
}

/**
 * Validate a scan structure
 * @scan: The parameter to validate
 * @flen: Size of the memory to be requested
 * @return TRUE on validation failure
 */
static int
rszshm_scan_validate (struct rszshm_scan *scan, size_t flen)
{
    return (scan->len < flen + sizeof (struct rszshm_hdr) ||
            !scan->start || scan->len == 0 || scan->hop == 0 || scan->iter == 0);
}

/**
 * Validate a header structure
 * @len: Size of the header read from shared memory file
 * @hdr: The header to validate
 * @return TRUE on validation failure
 */
static int
rszshm_hdr_validate (int len, struct rszshm_hdr *hdr)
{
    return (len != sizeof (struct rszshm_hdr) || !hdr->addr || hdr->flen == 0 ||
            hdr->max == 0);

}

/**
 * rszshm_mk - make and mmap a shareable region
 * @rshm: pointer to handle
 * @flen: initial length of shared mapping
 * @fname: path to file to be created, may be NULL or contain template
 * @scan: struct specifying search parameters
 *
 * The handle pointed to by r is populated by rszshm_mk. flen is increased
 * by the size of struct rszshm_hdr and rounded up to the next multiple of
 * page size.
 *
 * If rszshm_mk is called with only three arguments, a default scan struct
 * is used. To supply a struct via compound literal, wrap the argument in
 * parenthesis to avoid macro failure.
 *
 * rszshm_mk attempts to mmap a region of scan.len size at scan.start address.
 * This is a private anonymous noreserve map used to claim an address space.
 * If the mapping returns a different address, the region is unmapped, and
 * another attempt is made at scan.start - scan.hop. If necessary, the next
 * address tried is scan.start + scan.hop, then scan.start - (2 * scan.hop),
 * and so on for at most scan.iter iterations. The pattern can be visualized
 * as a counterclockwise spiral. If no match is found, NULL is returned and
 * errno is set to ENOSPC.
 *
 * When an mmap returns an address matching the requested address, that region
 * is used. If fname contains a template, mkdtemp(3) is called. A file is
 * created, and extended to flen bytes. It must not already exist. This file
 * is mmap'd over the region using MAP_FIXED. The mapping may later be extended
 * by rszshm_grow consuming more of the claimed address space.
 *
 * The initial portion of the mapped file is populated with a struct rszshm_hdr,
 * and msync called to write out the header.
 *
 * Example:
 *  struct rszshm r, s, t;
 *
 *  if (!rszshm_mk(&r, 4*MiB, NULL))
 *      err(1, "rszshm_mk");
 *  // map at 0x400000000000
 *
 *  if (!rszshm_mk(&s, 4*MiB, "/var/tmp/dat"))
 *      err(1, "rszshm_mk");
 *  // map at 0x3f0000000000
 *
 *  if (!rszshm_mk(&t, 4*MiB, NULL, ((struct rszshm_scan) { (void *) (48*TiB), 4*GiB, 1*TiB, 10 })))
 *      err(1, "rszshm_mk");
 *  // map at 0x300000000000
 *
 * Returns: rshm->dat address on success, NULL on error
 */
void *
rszshm_mk (struct rszshm *rshm, size_t flen, const char *fname, struct rszshm_scan scan)
{
    long pgsz = sysconf (_SC_PAGE_SIZE);
    char *mem;

    if (!rshm || !fname || !fname[0] || rszshm_scan_validate (&scan, flen))
    {
        errno = EINVAL;
        return NULL;
    }

    *rshm = (typeof (*rshm))
    {
    -1, 0, "", NULL, 0 };
    strcpy (rshm->fname, fname);

    flen = pgup (flen + sizeof (*rshm->hdr), pgsz);
    scan.len = pgup (scan.len, pgsz);

    mem = rszshm_scan_map (&scan);
    if (!mem)
    {
        errno = ENOSPC;
        return NULL;
    }

    if ((rshm->fd = open (rshm->fname, O_CREAT | O_EXCL | O_RDWR, 0666)) == -1)
    {
        errno = rszshm_cleanup (mem, rshm, scan.len, errno);
        return NULL;
    }
    if (ftruncate (rshm->fd, flen) == -1)
    {
        errno = rszshm_cleanup (mem, rshm, scan.len, errno);
        return NULL;
    }
    if (mmap (mem, flen, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, rshm->fd, 0) ==
        MAP_FAILED)
    {
        errno = rszshm_cleanup (mem, rshm, scan.len, errno);
        return NULL;
    }
    *(rshm->hdr = (typeof (rshm->hdr)) mem) = (typeof (*rshm->hdr))
    {
    flen, scan.len, mem };

    if (msync (mem, sizeof (*rshm->hdr), MS_SYNC) == -1)
    {
        errno = rszshm_cleanup (mem, rshm, scan.len, errno);
        return NULL;
    }
    rshm->flen = flen;
    rshm->cap = flen - sizeof (*rshm->hdr);
    rshm->dat = mem + sizeof (*rshm->hdr);

    return rshm->dat;
}

/**
 * rszshm_at - mmap ("attach") an existing shared region
 * @rshm: pointer to handle
 * @fname: path to file
 *
 * rszshm_at lets unrelated processes attach an existing shared region.
 * fname must name a file previously created by rszshm_mk in another process.
 * Note, fork'd children of the creating process inherit the mapping and
 * should *not* call rszshm_at.
 *
 * rszshm_at opens and reads the header from the file. It makes a private
 * anonymous noreserve mapping at the address recorded in the header.
 * If mmap returns an address other than the requested one, munmap
 * is called, errno is set to ENOSPC, and NULL is returned.
 *
 * Once the address space is claimed, the file is mmap'd over the region
 * using MAP_FIXED. The remaining claimed address space will be used by
 * later calls to rszshm_grow. Finally, the handle is populated and r->dat
 * returned.
 *
 * Example:
 *  struct rszshm r;
 *
 *  if (!rszshm_at(&r, "/dev/shm/rszshm_LAsEvt/0"))
 *      err(1, "rszshm_at");
 *
 * Returns: rshm->dat address on success, NULL on error
 */
void *
rszshm_at (struct rszshm *rshm, const char *fname)
{
    struct rszshm_hdr hdr;
    int fd = -1;
    int ret;
    void *mem = NULL;

    if (!rshm || !fname || !fname[0])
    {
        errno = EINVAL;
        return NULL;
    }

    if ((fd = open (fname, O_RDWR)) == -1)
    {
        return NULL;
    }
    rshm->fd = fd;
    rshm->fname[0] = '\0';
    ret = read (fd, &hdr, sizeof (hdr));
    if (rszshm_hdr_validate (ret, &hdr))
    {
        errno = rszshm_cleanup (mem, rshm, hdr.max, ENODATA);
        return NULL;
    }

    mem =
        mmap (hdr.addr, hdr.max, PROT_READ | PROT_WRITE,
              MAP_PRIVATE | MAP_ANON | MAP_NORESERVE, -1, 0);
    if (mem == MAP_FAILED)
    {
        errno = rszshm_cleanup (mem, rshm, hdr.max, errno);
        return NULL;
    }
    if (mem == hdr.addr &&
        mmap (mem, hdr.flen, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd, 0) !=
        MAP_FAILED)
    {
        *rshm = (typeof (*rshm))
        {
        .fd = fd,.flen = hdr.flen,.hdr = (typeof (rshm->hdr)) mem,.dat =
                mem + sizeof (hdr),.cap = hdr.flen - sizeof (hdr) };
        strcpy (rshm->fname, fname);
    }
    else
    {
        errno = rszshm_cleanup (mem, rshm, hdr.max, ENOSPC);
    }
    return rshm->dat;
}

/**
 * rszshm_up - update mapping of shared region
 * @rshm: pointer to handle
 *
 * Check if flen from the region header matches flen from the handle.
 * They will diverge when another process runs rszshm_grow.
 * If they are different, call mmap with the header flen and MAP_FIXED,
 * and update handle.
 *
 * Returns: -1 if mmap fails, 0 for no change, 1 is mapping updated
 */
int
rszshm_up (struct rszshm *rshm)
{
    size_t flen;

    assert (rshm);

    flen = rshm->hdr->flen;
    if (rshm->flen == flen)
    {
        return 0;
    }
    if (mmap (rshm->hdr, flen, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, rshm->fd, 0)
        == MAP_FAILED)
    {
        return -1;
    }
    rshm->flen = flen;
    rshm->cap = flen - sizeof (*rshm->hdr);
    return 1;
}


/**
 * rszshm_grow - grow the shared region, conditionally
 * @rshm: pointer to handle
 * @size: amount to grow
 *
 * If the region is already at capacity, set errno to ENOMEM, and return -1.
 *
 * rszshm_up is called, to see if another process has already grown the region.
 * If not, a lock is acquired and the check repeated, to avoid races.
 * The file is extended, and mmap called with MAP_FIXED. The header and handle
 * are updated.
 *
 * Returns: 1 on success, -1 on error
 */
int
rszshm_grow (struct rszshm *rshm, size_t size)
{
    int ret;
    size_t newsize;
    assert (rshm);
    off_t flen;

    if ((ret = rszshm_up (rshm)) != 0)
    {
        return ret;
    }
    if (rshm->flen == rshm->hdr->max)
    {
        errno = ENOMEM;
        return -1;
    }

    if ((ret = flock (rshm->fd, LOCK_EX) == 0))
    {
        if ((ret = rszshm_up (rshm)) == 0)
        {
            newsize = rshm->hdr->flen + size;
            flen = newsize < rshm->hdr->max ? newsize : rshm->hdr->max;

            if ((ret = ftruncate (rshm->fd, flen)) == 0 &&
                mmap (rshm->hdr, flen, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED,
                      rshm->fd, 0) != MAP_FAILED)
            {
                rshm->flen = rshm->hdr->flen = flen;
                rshm->cap = flen - sizeof (*rshm->hdr);
                ret = 1;
            }
        }
        flock (rshm->fd, LOCK_UN);
    }
    return ret;
}

/**
 * rszshm_dt - unmap ("detach") shared region
 * @rshm: pointer to handle
 *
 * Calls msync, munmap, and close. Resets handle values except fname.
 * (fname is used by rszshm_rm*.)
 *
 * Returns: 0 on success, -1 if any call failed
 */
int
rszshm_dt (struct rszshm *rshm)
{
    int ret[3];
    assert (rshm);

    /* ok to call twice, since free macro calls this */
    if (rshm->fd == -1)
    {
        return 0;
    }

    ret[0] = msync (rshm->hdr, rshm->flen, MS_SYNC);
    ret[1] = munmap (rshm->hdr, rshm->hdr->max);
    ret[2] = close (rshm->fd);

    rshm->fd = -1;
    rshm->flen = 0;
    rshm->hdr = NULL;
    rshm->dat = NULL;
    rshm->cap = 0;

    return ret[0] == 0 && ret[1] == 0 && ret[2] == 0 ? 0 : -1;
}

/**
 * rszshm_unlink - unlink shared file
 * @rshm: pointer to handle
 *
 * Returns: result of unlink
 */
int
rszshm_unlink (struct rszshm *rshm)
{
    assert (rshm);
    return unlink (rshm->fname);
}

/**
 * rszshm_rmdir - rmdir of fname directory
 * @rshm: pointer to handle
 *
 * Returns: result of rmdir
 */
int
rszshm_rmdir (struct rszshm *rshm)
{
    int ret;
    char *ptr;

    assert (rshm);

    if ((ptr = strrchr (rshm->fname, '/')) == NULL)
    {
        errno = ENOTDIR;
        return -1;
    }

    *ptr = '\0';
    ret = rmdir (rshm->fname);
    *ptr = '/';
    return ret;
}
