/*
**  Copyright (c) 2007-2009 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009-2017, The Trusted Domain Project.  All rights reserved.
*/

#include "build-config.h"

/* for Solaris */
#ifndef _REENTRANT
#define _REENTRANT
#endif /* _REENTRANT */

/* system includes */
#include <assert.h>
#include <ctype.h>
#include <limits.h>
#include <regex.h>
#include <stdbool.h>
#include <string.h>
#include <sys/param.h>
#include <sys/types.h>
#include <unistd.h>

/* libopenarc includes */
#include "arc-canon.h"
#include "arc-internal.h"
#include "arc-tables.h"
#include "arc-types.h"
#include "arc-util.h"

#include "arc-dstring.h"

/* libbsd if found */
#ifdef USE_BSD_H
#include <bsd/string.h>
#endif /* USE_BSD_H */

/* libstrl if needed */
#ifdef USE_STRL_H
#include <strl.h>
#endif /* USE_STRL_H */

/* definitions */
#define CRLF          "\r\n"
#define SP            " "

/* macros */
#define ARC_ISWSP(x)  ((x) == 011 || (x) == 040)
#define ARC_ISLWSP(x) ((x) == 011 || (x) == 012 || (x) == 015 || (x) == 040)

/* prototypes */
extern void arc_error(ARC_MESSAGE *, const char *, ...);

/* ========================= PRIVATE SECTION ========================= */

/*
**  ARC_CANON_FREE -- destroy a canonicalization
**
**  Parameters:
**  	msg -- ARC message handle
**  	canon -- canonicalization to destroy
**
**  Return value:
**  	None.
*/

static void
arc_canon_free(ARC_MESSAGE *msg, ARC_CANON *canon)
{
    assert(msg != NULL);
    if (canon == NULL)
    {
        return;
    }

    if (canon->canon_hash != NULL)
    {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        EVP_MD_CTX_destroy(canon->canon_hash->hash_ctx);
#else
        EVP_MD_CTX_free(canon->canon_hash->hash_ctx);
#endif /* OpenSSL < 1.1.0 */
        BIO_free(canon->canon_hash->hash_tmpbio);
        ARC_FREE(canon->canon_hash);
    }

    ARC_FREE(canon->canon_hashbuf);
    arc_dstring_free(canon->canon_buf);
    ARC_FREE(canon);
}

/*
**  ARC_CANON_WRITE -- write data to canonicalization stream(s)
**
**  Parameters:
**  	canon -- ARC_CANON handle
**  	buf -- buffer containing canonicalized data
**  	buflen -- number of bytes to consume
**
**  Return value:
**  	None.
*/

static void
arc_canon_write(ARC_CANON *canon, const char *buf, size_t buflen)
{
    assert(canon != NULL);

    if (canon->canon_remain != (ssize_t) -1)
    {
        buflen = MIN(buflen, canon->canon_remain);
    }

    canon->canon_wrote += buflen;

    if (buf == NULL || buflen == 0)
    {
        return;
    }

    assert(canon->canon_hash != NULL);

    EVP_DigestUpdate(canon->canon_hash->hash_ctx, buf, buflen);
    if (canon->canon_hash->hash_tmpbio != NULL)
    {
        BIO_write(canon->canon_hash->hash_tmpbio, buf, buflen);
    }

    if (canon->canon_remain != (ssize_t) -1)
    {
        canon->canon_remain -= buflen;
    }
}

/*
**  ARC_CANON_BUFFER -- buffer for arc_canon_write()
**
**  Parameters:
**  	canon -- ARC_CANON handle
**  	buf -- buffer containing canonicalized data
**  	buflen -- number of bytes to consume
**
**  Return value:
**  	None.
*/

static void
arc_canon_buffer(ARC_CANON *canon, const char *buf, size_t buflen)
{
    assert(canon != NULL);

    /* NULL buffer or 0 length means flush */
    if (buf == NULL || buflen == 0)
    {
        if (canon->canon_hashbuflen > 0)
        {
            arc_canon_write(canon, canon->canon_hashbuf,
                            canon->canon_hashbuflen);
            canon->canon_hashbuflen = 0;
        }
        return;
    }

    /* not enough buffer space; write the buffer out */
    if (canon->canon_hashbuflen + buflen > canon->canon_hashbufsize)
    {
        arc_canon_write(canon, canon->canon_hashbuf, canon->canon_hashbuflen);
        canon->canon_hashbuflen = 0;
    }

    /*
    **  Now, if the input is bigger than the buffer, write it too;
    **  otherwise cache it.
    */

    if (buflen >= canon->canon_hashbufsize)
    {
        arc_canon_write(canon, buf, buflen);
    }
    else
    {
        memcpy(&canon->canon_hashbuf[canon->canon_hashbuflen], buf, buflen);
        canon->canon_hashbuflen += buflen;
    }
}

/*
**  ARC_CANON_HEADER_STRING -- canonicalize a header field
**
**  Parameters:
**  	dstr -- arc_dstring to use for output
**  	canon -- arc_canon_t
**  	hdr -- header field input
**  	hdrlen -- bytes to process at "hdr"
**  	crlf -- write a CRLF at the end?
**
**  Return value:
**  	A ARC_STAT constant.
*/

ARC_STAT
arc_canon_header_string(struct arc_dstring *dstr,
                        arc_canon_t         canon,
                        const char         *hdr,
                        size_t              hdrlen,
                        bool                crlf)
{
    bool        space;
    const char *p;
    char       *tmp;
    char       *end;
    char        tmpbuf[BUFRSZ];
    assert(dstr != NULL);
    assert(hdr != NULL);

    tmp = tmpbuf;
    end = tmpbuf + sizeof tmpbuf - 1;

    switch (canon)
    {
    case ARC_CANON_SIMPLE:
        if (!arc_dstring_catn(dstr, hdr, hdrlen) ||
            (crlf && !arc_dstring_catn(dstr, CRLF, 2)))
        {
            return ARC_STAT_NORESOURCE;
        }
        break;

    case ARC_CANON_RELAXED:
        /* process header field name (before colon) first */
        for (p = hdr; p < hdr + hdrlen; p++)
        {
            /*
            **  Discard spaces before the colon or before the end
            **  of the first word.
            */

            if (isascii(*p))
            {
                /* discard spaces */
                if (ARC_ISLWSP(*p))
                {
                    continue;
                }

                /* convert to lowercase */
                if (isupper(*p))
                {
                    *tmp++ = tolower(*p);
                }
                else
                {
                    *tmp++ = *p;
                }
            }
            else
            {
                *tmp++ = *p;
            }

            /* reaching the end of the cache buffer, flush it */
            if (tmp == end)
            {
                *tmp = '\0';

                if (!arc_dstring_catn(dstr, tmpbuf, tmp - tmpbuf))
                {
                    return ARC_STAT_NORESOURCE;
                }

                tmp = tmpbuf;
            }

            if (*p == ':')
            {
                p++;
                break;
            }
        }

        /* skip all spaces before first word */
        while (*p != '\0' && ARC_ISLWSP(*p))
        {
            p++;
        }

        space = false; /* just saw a space */

        for (; *p != '\0'; p++)
        {
            if (isascii(*p) && isspace(*p))
            {
                /* mark that there was a space and continue */
                space = true;

                continue;
            }

            /*
            **  Any non-space marks the beginning of a word.
            **  If there's a stored space, use it up.
            */

            if (space)
            {
                *tmp++ = ' ';

                /* flush buffer? */
                if (tmp == end)
                {
                    *tmp = '\0';

                    if (!arc_dstring_catn(dstr, tmpbuf, tmp - tmpbuf))
                    {
                        return ARC_STAT_NORESOURCE;
                    }

                    tmp = tmpbuf;
                }

                space = false;
            }

            /* copy the byte */
            *tmp++ = *p;

            /* flush buffer? */
            if (tmp == end)
            {
                *tmp = '\0';

                if (!arc_dstring_catn(dstr, tmpbuf, tmp - tmpbuf))
                {
                    return ARC_STAT_NORESOURCE;
                }

                tmp = tmpbuf;
            }
        }

        /* flush any cached data */
        if (tmp != tmpbuf)
        {
            *tmp = '\0';

            if (!arc_dstring_catn(dstr, tmpbuf, tmp - tmpbuf))
            {
                return ARC_STAT_NORESOURCE;
            }
        }

        if (crlf && !arc_dstring_catn(dstr, CRLF, 2))
        {
            return ARC_STAT_NORESOURCE;
        }

        break;
    }

    return ARC_STAT_OK;
}

/*
**  ARC_CANON_HEADER -- canonicalize a header and write it
**
**  Parameters:
**  	msg -- ARC message handle
**  	canon -- ARC_CANON handle
**  	hdr -- header handle
**  	crlf -- write a CRLF at the end?
**
**  Return value:
**  	A ARC_STAT constant.
*/

static ARC_STAT
arc_canon_header(ARC_MESSAGE         *msg,
                 ARC_CANON           *canon,
                 struct arc_hdrfield *hdr,
                 bool                 crlf)
{
    ARC_STAT status;

    assert(msg != NULL);
    assert(canon != NULL);
    assert(hdr != NULL);

    if (msg->arc_canonbuf == NULL)
    {
        msg->arc_canonbuf = arc_dstring_new(hdr->hdr_textlen, 0, msg,
                                            &arc_error_cb);
        if (msg->arc_canonbuf == NULL)
        {
            return ARC_STAT_NORESOURCE;
        }
    }
    else
    {
        arc_dstring_blank(msg->arc_canonbuf);
    }

    arc_canon_buffer(canon, NULL, 0);

    status = arc_canon_header_string(msg->arc_canonbuf, canon->canon_canon,
                                     hdr->hdr_text, hdr->hdr_textlen, crlf);

    if (status != ARC_STAT_OK)
    {
        return status;
    }

    arc_canon_buffer(canon, arc_dstring_get(msg->arc_canonbuf),
                     arc_dstring_len(msg->arc_canonbuf));

    return ARC_STAT_OK;
}

/*
**  ARC_CANON_FLUSHBLANKS -- use accumulated blank lines in canonicalization
**
**  Parameters:
**  	canon -- ARC_CANON handle
**
**  Return value:
**  	None.
*/

static void
arc_canon_flushblanks(ARC_CANON *canon)
{
    int c;

    assert(canon != NULL);

    for (c = 0; c < canon->canon_blanks; c++)
    {
        arc_canon_buffer(canon, CRLF, 2);
    }
    canon->canon_blanks = 0;
}

/*
**  ARC_CANON_FIXCRLF -- rebuffer a body chunk, fixing "naked" CRs and LFs
**
**  Parameters:
**  	msg -- ARC message handle
**  	canon -- canonicalization being handled
**  	buf -- buffer to be fixed
**  	buflen -- number of bytes at "buf"
**
**  Return value:
**  	A ARC_STAT_* constant.
**
**  Side effects:
**  	msg->arc_canonbuf will be initialized and used.
*/

static ARC_STAT
arc_canon_fixcrlf(ARC_MESSAGE *msg,
                  ARC_CANON   *canon,
                  const char  *buf,
                  size_t       buflen)
{
    char        prev;
    const char *p;
    const char *eob;

    assert(msg != NULL);
    assert(canon != NULL);
    assert(buf != NULL);

    if (msg->arc_canonbuf == NULL)
    {
        msg->arc_canonbuf = arc_dstring_new(buflen, 0, msg, &arc_error_cb);
        if (msg->arc_canonbuf == NULL)
        {
            return ARC_STAT_NORESOURCE;
        }
    }
    else
    {
        arc_dstring_blank(msg->arc_canonbuf);
    }

    eob = buf + buflen - 1;

    prev = canon->canon_lastchar;

    for (p = buf; p <= eob; p++)
    {
        if (*p == '\n' && prev != '\r')
        {
            /* fix a solitary LF */
            arc_dstring_catn(msg->arc_canonbuf, CRLF, 2);
        }
        else if (*p == '\r')
        {
            if (p < eob && *(p + 1) != '\n')
            {
                /* fix a solitary CR */
                arc_dstring_catn(msg->arc_canonbuf, CRLF, 2);
            }
            else
            {
                /* CR at EOL, or CR followed by a LF */
                arc_dstring_cat1(msg->arc_canonbuf, *p);
            }
        }
        else
        {
            /* something else */
            arc_dstring_cat1(msg->arc_canonbuf, *p);
        }

        prev = *p;
    }

    return ARC_STAT_OK;
}

/* ========================= PUBLIC SECTION ========================= */

/*
**  ARC_CANON_INIT -- initialize all canonicalizations
**
**  Parameters:
**  	msg -- ARC message handle
**  	tmp -- make temp files?
**  	keep -- keep temp files?
**
**  Return value:
**  	A ARC_STAT_* constant.
*/

ARC_STAT
arc_canon_init(ARC_MESSAGE *msg, bool tmp, bool keep)
{
    int        fd;
    int        rc;
    ARC_STAT   status;
    ARC_CANON *cur;

    assert(msg != NULL);

    for (cur = msg->arc_canonhead; cur != NULL; cur = cur->canon_next)
    {
        if (cur->canon_hashbuf != NULL)
        {
            /* already initialized, nothing to do */
            continue;
        }
        cur->canon_hashbuf = ARC_MALLOC(ARC_HASHBUFSIZE);
        if (cur->canon_hashbuf == NULL)
        {
            arc_error(msg, "unable to allocate %d byte(s)", ARC_HASHBUFSIZE);
            return ARC_STAT_NORESOURCE;
        }
        cur->canon_hashbufsize = ARC_HASHBUFSIZE;
        cur->canon_hashbuflen = 0;
        cur->canon_buf = arc_dstring_new(BUFRSZ, BUFRSZ, msg, &arc_error_cb);
        if (cur->canon_buf == NULL)
        {
            return ARC_STAT_NORESOURCE;
        }

        cur->canon_hash = ARC_CALLOC(1, sizeof(struct arc_hash));
        if (cur->canon_hash == NULL)
        {
            arc_error(msg, "unable to allocate %d bytes",
                      sizeof(struct arc_hash));
            return ARC_STAT_NORESOURCE;
        }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
        cur->canon_hash->hash_ctx = EVP_MD_CTX_create();
#else
        cur->canon_hash->hash_ctx = EVP_MD_CTX_new();
#endif /* OpenSSL < 1.1.0 */
        if (cur->canon_hash->hash_ctx == NULL)
        {
            arc_error(msg, "EVP_MD_CTX_new() failed");
            return ARC_STAT_NORESOURCE;
        }
        if (cur->canon_hashtype == ARC_HASHTYPE_SHA1)
        {
            rc = EVP_DigestInit_ex(cur->canon_hash->hash_ctx, EVP_sha1(), NULL);
        }
        else
        {
            rc = EVP_DigestInit_ex(cur->canon_hash->hash_ctx, EVP_sha256(),
                                   NULL);
        }

        if (rc <= 0)
        {
            arc_error(msg, "EVP_DigestInit_ex() failed");
            return ARC_STAT_INTERNAL;
        }

        if (tmp)
        {
            status = arc_tmpfile(msg, &fd, keep);
            if (status != ARC_STAT_OK)
            {
                return status;
            }

            cur->canon_hash->hash_tmpfd = fd;
            cur->canon_hash->hash_tmpbio = BIO_new_fd(fd, 1);
        }
    }

    return ARC_STAT_OK;
}

/*
**  ARC_CANON_CLEANUP -- discard canonicalizations
**
**  Parameters:
**  	msg -- ARC message handle
**
**  Return value:
**  	None.
*/

void
arc_canon_cleanup(ARC_MESSAGE *msg)
{
    ARC_CANON *cur;
    ARC_CANON *next;

    assert(msg != NULL);

    cur = msg->arc_canonhead;
    while (cur != NULL)
    {
        next = cur->canon_next;

        arc_canon_free(msg, cur);

        cur = next;
    }

    msg->arc_canonhead = NULL;
    arc_dstring_free(msg->arc_canonbuf);
    msg->arc_canonbuf = NULL;
}

/*
**  ARC_ADD_CANON -- add a new canonicalization handle if needed
**
**  Parameters:
**  	msg -- verification handle
**  	type -- an ARC_CANONTYPE_* constant
**  	canon -- arc_canon_t
**  	hashtype -- hash type
**  	hdrlist -- for header canonicalization, the header list
**  	sighdr -- pointer to header being verified (NULL for signing)
**  	length -- for body canonicalization, the length limit (-1 == all)
**  	cout -- ARC_CANON handle (returned)
**
**  Return value:
**  	A ARC_STAT_* constant.
*/

ARC_STAT
arc_add_canon(ARC_MESSAGE         *msg,
              int                  type,
              arc_canon_t          canon,
              int                  hashtype,
              const char          *hdrlist,
              struct arc_hdrfield *sighdr,
              ssize_t              length,
              ARC_CANON          **cout)
{
    ARC_CANON *cur;
    ARC_CANON *new;

    assert(msg != NULL);
    assert(canon == ARC_CANON_SIMPLE || canon == ARC_CANON_RELAXED);

    assert(hashtype == ARC_HASHTYPE_SHA1 || hashtype == ARC_HASHTYPE_SHA256);

    /* Body canons can be shared if the parameters match. Header canons could
     * theoretically be partially shared if the `h` tags match, but it would be
     * complex so we don't currently do it. */
    if (type == ARC_CANONTYPE_BODY)
    {
        for (cur = msg->arc_canonhead; cur != NULL; cur = cur->canon_next)
        {
            if (cur->canon_type != ARC_CANONTYPE_BODY ||
                cur->canon_canon != canon || cur->canon_hashtype != hashtype ||
                cur->canon_length != length)
            {
                continue;
            }

            if (cout != NULL)
            {
                *cout = cur;
            }

            return ARC_STAT_OK;
        }
    }

    new = ARC_MALLOC(sizeof *new);
    if (new == NULL)
    {
        arc_error(msg, "unable to allocate %d byte(s)", sizeof *new);
        return ARC_STAT_NORESOURCE;
    }

    new->canon_done = false;
    new->canon_type = type;
    new->canon_hashtype = hashtype;
    new->canon_hash = NULL;
    new->canon_wrote = 0;
    new->canon_canon = canon;
    if (type != ARC_CANONTYPE_BODY)
    {
        new->canon_length = (ssize_t) -1;
        new->canon_remain = (ssize_t) -1;
    }
    else
    {
        new->canon_length = length;
        new->canon_remain = length;
    }
    new->canon_sigheader = sighdr;
    new->canon_hdrlist = hdrlist;
    new->canon_buf = NULL;
    new->canon_next = NULL;
    new->canon_blankline = true;
    new->canon_blanks = 0;
    new->canon_bodystate = 0;
    new->canon_hashbuflen = 0;
    new->canon_hashbufsize = 0;
    new->canon_hashbuf = NULL;
    new->canon_lastchar = '\0';

    if (msg->arc_canonhead == NULL)
    {
        msg->arc_canontail = new;
        msg->arc_canonhead = new;
    }
    else
    {
        msg->arc_canontail->canon_next = new;
        msg->arc_canontail = new;
    }

    if (cout != NULL)
    {
        *cout = new;
    }

    return ARC_STAT_OK;
}

/*
**  ARC_CANON_SELECTHDRS -- choose headers to be included in canonicalization
**
**  Parameters:
**  	msg -- ARC message context in which this is performed
**  	hdrlist -- string containing headers that should be marked, separated
**  	           by the ":" character
**  	ptrs -- array of header pointers (modified)
**  	nptr -- number of pointers available at "ptrs"
**
**  Return value:
**  	Count of headers added to "ptrs", or -1 on error.
**
**  Notes:
**  	Selects header fields to be passed to canonicalization and the order in
**  	which this is done.  "ptrs" is populated by pointers to header fields
**  	in the order in which they should be fed to canonicalization.
**
**  	If any of the returned pointers is NULL, then a header field named by
**  	"hdrlist" was not found.
*/

int
arc_canon_selecthdrs(ARC_MESSAGE          *msg,
                     const char           *hdrlist,
                     struct arc_hdrfield **ptrs,
                     int                   nptrs)
{
    int                   c;
    int                   n;
    int                   m;
    int                   shcnt;
    size_t                len;
    char                 *bar;
    char                 *ctx;
    char                 *colon;
    struct arc_hdrfield  *hdr;
    struct arc_hdrfield **lhdrs;
    char                **hdrs;

    assert(msg != NULL);
    assert(ptrs != NULL);
    assert(nptrs != 0);

    /* if there are no header fields named, use them all */
    if (hdrlist == NULL)
    {
        n = 0;

        for (hdr = msg->arc_hhead; hdr != NULL; hdr = hdr->hdr_next)
        {
            if (n >= nptrs)
            {
                arc_error(msg, "too many header fields (max %d)", nptrs);
                return -1;
            }
            ptrs[n] = hdr;
            n++;
        }

        return n;
    }

    if (msg->arc_hdrlist == NULL)
    {
        msg->arc_hdrlist = ARC_MALLOC(ARC_MAXHEADER);
        if (msg->arc_hdrlist == NULL)
        {
            arc_error(msg, "unable to allocate %d bytes(s)", ARC_MAXHEADER);
            return -1;
        }
    }

    strlcpy(msg->arc_hdrlist, hdrlist, ARC_MAXHEADER);

    /* mark all headers as not used */
    for (hdr = msg->arc_hhead; hdr != NULL; hdr = hdr->hdr_next)
    {
        hdr->hdr_flags &= ~ARC_HDR_SIGNED;
    }

    lhdrs = ARC_CALLOC(msg->arc_hdrcnt, sizeof(struct arc_hdrfield *));
    if (lhdrs == NULL)
    {
        return -1;
    }

    shcnt = 1;
    for (colon = msg->arc_hdrlist; *colon != '\0'; colon++)
    {
        if (*colon == ':')
        {
            shcnt++;
        }
    }
    hdrs = ARC_CALLOC(shcnt, sizeof(char *));
    if (hdrs == NULL)
    {
        ARC_FREE(lhdrs);
        return -1;
    }

    n = 0;

    /* make a split-out copy of hdrlist */
    for (bar = strtok_r(msg->arc_hdrlist, ":", &ctx); bar != NULL;
         bar = strtok_r(NULL, ":", &ctx))
    {
        hdrs[n] = bar;
        n++;
    }

    /* for each named header, find the last unused one and use it up */
    shcnt = 0;
    for (c = 0; c < n; c++)
    {
        lhdrs[shcnt] = NULL;

        len = MIN(ARC_MAXHEADER, strlen(hdrs[c]));
        while (len > 0 && ARC_ISWSP(hdrs[c][len - 1]))
        {
            len--;
        }

        for (hdr = msg->arc_hhead; hdr != NULL; hdr = hdr->hdr_next)
        {
            if (hdr->hdr_flags & ARC_HDR_SIGNED)
            {
                continue;
            }

            if (len == hdr->hdr_namelen &&
                strncasecmp(hdr->hdr_text, hdrs[c], len) == 0)
            {
                lhdrs[shcnt] = hdr;
            }
        }

        if (lhdrs[shcnt] != NULL)
        {
            lhdrs[shcnt]->hdr_flags |= ARC_HDR_SIGNED;
            shcnt++;
        }
    }

    /* bounds check */
    if (shcnt > nptrs)
    {
        arc_error(msg, "too many headers (found %d, max %d)", shcnt, nptrs);

        ARC_FREE(lhdrs);
        ARC_FREE(hdrs);

        return -1;
    }

    /* copy to the caller's buffers */
    m = 0;
    for (c = 0; c < shcnt; c++)
    {
        if (lhdrs[c] != NULL)
        {
            ptrs[m] = lhdrs[c];
            m++;
        }
    }

    ARC_FREE(lhdrs);
    ARC_FREE(hdrs);

    return m;
}

/*
**  ARC_CANON_STRIP_B -- strip "b=" value from a header field
**
**  Parameters:
**  	msg -- ARC_MESSAGE handle
**  	text -- string containing header field to strip
**
**  Return value:
**  	An ARC_STAT_* constant.
**
**  Side effects:
**  	The stripped header field is left in msg->arc_hdrbuf.
*/

static ARC_STAT
arc_canon_strip_b(ARC_MESSAGE *msg, char *text)
{
    char  in = '\0';
    char  last = '\0';
    char *p;
    char *tmp;
    char *end;
    char  tmpbuf[BUFRSZ];

    assert(msg != NULL);
    assert(text != NULL);

    arc_dstring_blank(msg->arc_hdrbuf);

    tmp = tmpbuf;
    end = tmpbuf + sizeof tmpbuf - 1;

    /* Strictly speaking this is wrong, RFC 8617 allows CFWS around i=
     * and cv= so this code could be confused by interestingly-shaped
     * comments, but that part of the syntax is different from all other
     * tag-lists so we're going to pretend it says FWS.
     */
    for (p = text; *p != '\0'; p++)
    {
        /* if we've found a separator, we're not in a tag */
        if (*p == ';')
        {
            in = '\0';
        }

        /* if we're in the b tag, don't save this character */
        if (in == 'b')
        {
            continue;
        }

        /* if we've found an = and don't already know what tag we're in,
         * the previous character is the tag name */
        if (in == '\0' && *p == '=')
        {
            in = last;
        }

        *tmp++ = *p;

        /* flush buffer? */
        if (tmp == end)
        {
            *tmp = '\0';

            if (!arc_dstring_catn(msg->arc_hdrbuf, tmpbuf, tmp - tmpbuf))
            {
                return ARC_STAT_NORESOURCE;
            }

            tmp = tmpbuf;
        }

        if (!isspace(*p))
        {
            last = *p;
        }
    }

    /* flush anything cached */
    if (tmp != tmpbuf)
    {
        *tmp = '\0';

        if (!arc_dstring_catn(msg->arc_hdrbuf, tmpbuf, tmp - tmpbuf))
        {
            return ARC_STAT_NORESOURCE;
        }
    }

    return ARC_STAT_OK;
}

/*
**  ARC_CANON_FINALIZE -- finalize a canonicalization
**
**  Parameters:
**  	canon -- canonicalization to finalize
**
**  Return value:
**  	None.
*/

static void
arc_canon_finalize(ARC_CANON *canon)
{
    assert(canon != NULL);

    EVP_DigestFinal(canon->canon_hash->hash_ctx, canon->canon_hash->hash_out,
                    &canon->canon_hash->hash_outlen);

    if (canon->canon_hash->hash_tmpbio != NULL)
    {
        BIO_flush(canon->canon_hash->hash_tmpbio);
    }
}

/*
**  ARC_CANON_RUNHEADERS_SEAL -- run the ARC-specific header fields through
**                               seal canonicalization(s)
**
**  Parameters:
**  	msg -- ARC_MESSAGE handle
**
**  Return value:
**  	An ARC_STAT_* constant.
**
**  For each ARC set number N, apply it to seal canonicalization handles 0
**  through N-1.  That way the first one is only set 1, the second one is
**  sets 1 and 2, etc.  For the final one in each set, strip "b=".  Then
**  also do one more complete one so that can be used for re-sealing.
*/

ARC_STAT
arc_canon_runheaders_seal(ARC_MESSAGE *msg)
{
    ARC_STAT     status;
    unsigned int m;
    unsigned int n;
    ARC_CANON   *cur;

    assert(msg != NULL);

    for (n = 0; n < msg->arc_nsets; n++)
    {
        cur = msg->arc_sealcanons[n];

        if (cur->canon_done)
        {
            continue;
        }

        /* build up the canonicalized seals for verification */
        for (m = 0; m <= n; m++)
        {
            status = arc_canon_header(msg, cur, msg->arc_sets[m].arcset_aar,
                                      true);
            if (status != ARC_STAT_OK)
            {
                return status;
            }

            status = arc_canon_header(msg, cur, msg->arc_sets[m].arcset_ams,
                                      true);
            if (status != ARC_STAT_OK)
            {
                return status;
            }

            if (m != n)
            {
                status = arc_canon_header(msg, cur, msg->arc_sets[m].arcset_as,
                                          true);
            }
            else
            {
                struct arc_hdrfield tmphdr;
                arc_canon_strip_b(msg, msg->arc_sets[m].arcset_as->hdr_text);

                tmphdr.hdr_text = arc_dstring_get(msg->arc_hdrbuf);
                tmphdr.hdr_namelen = cur->canon_sigheader->hdr_namelen;
                tmphdr.hdr_textlen = arc_dstring_len(msg->arc_hdrbuf);
                tmphdr.hdr_flags = 0;
                tmphdr.hdr_next = NULL;

                status = arc_canon_header(msg, cur, &tmphdr, false);
                arc_canon_buffer(cur, NULL, 0);
            }

            if (status != ARC_STAT_OK)
            {
                return status;
            }
        }

        arc_canon_finalize(cur);
        cur->canon_done = true;

        cur = msg->arc_sealcanon;

        if (cur == NULL || cur->canon_done)
        {
            continue;
        }

        /* write all the ARC sets once more for re-sealing */
        status = arc_canon_header(msg, cur, msg->arc_sets[n].arcset_aar, true);
        if (status != ARC_STAT_OK)
        {
            return status;
        }

        status = arc_canon_header(msg, cur, msg->arc_sets[n].arcset_ams, true);
        if (status != ARC_STAT_OK)
        {
            return status;
        }

        status = arc_canon_header(msg, cur, msg->arc_sets[n].arcset_as, true);
        if (status != ARC_STAT_OK)
        {
            return status;
        }
    }

    return ARC_STAT_OK;
}

/*
**  ARC_CANON_RUNHEADERS -- run the headers through all header and seal
**                          canonicalizations
**
**  Parameters:
**  	msg -- ARC message handle
**
**  Return value:
**  	A ARC_STAT_* constant.
**
**  Note:
**  	Header canonicalizations are finalized by this function when
**  	verifying.  In signing mode, header canonicalizations are finalized
**  	by a subsequent call to arc_canon_signature().
*/

ARC_STAT
arc_canon_runheaders(ARC_MESSAGE *msg)
{
    bool                  signing;
    unsigned char         savechar;
    int                   c;
    size_t                n;
    int                   nhdrs = 0;
    ARC_STAT              status;
    ARC_CANON            *cur;
    struct arc_hdrfield  *hdr;
    struct arc_hdrfield **hdrset;
    struct arc_hdrfield   tmphdr;

    assert(msg != NULL);

    if (msg->arc_hdrcnt == 0)
    {
        return ARC_STAT_OK;
    }

    n = msg->arc_hdrcnt * sizeof(struct arc_hdrfield *);
    hdrset = ARC_CALLOC(msg->arc_hdrcnt, sizeof(struct arc_hdrfield *));
    if (hdrset == NULL)
    {
        return ARC_STAT_NORESOURCE;
    }

    if (msg->arc_hdrbuf == NULL)
    {
        msg->arc_hdrbuf = arc_dstring_new(ARC_MAXHEADER, 0, msg, &arc_error_cb);
        if (msg->arc_hdrbuf == NULL)
        {
            ARC_FREE(hdrset);
            return ARC_STAT_NORESOURCE;
        }
    }
    else
    {
        arc_dstring_blank(msg->arc_hdrbuf);
    }

    for (cur = msg->arc_canonhead; cur != NULL; cur = cur->canon_next)
    {
        arc_dstring_blank(msg->arc_hdrbuf);

        /* skip done hashes and those which are of the wrong type */
        if (cur->canon_done || (cur->canon_type != ARC_CANONTYPE_HEADER &&
                                cur->canon_type != ARC_CANONTYPE_AMS))
        {
            continue;
        }

        signing = (cur->canon_sigheader == NULL);

        /* clear header selection flags if verifying */
        if (!signing)
        {
            if (cur->canon_hdrlist == NULL)
            {
                for (hdr = msg->arc_hhead; hdr != NULL; hdr = hdr->hdr_next)
                {
                    hdr->hdr_flags |= ARC_HDR_SIGNED;
                }
            }
            else
            {
                for (hdr = msg->arc_hhead; hdr != NULL; hdr = hdr->hdr_next)
                {
                    hdr->hdr_flags &= ~ARC_HDR_SIGNED;
                }

                memset(hdrset, '\0', n);

                /* do header selection */
                nhdrs = arc_canon_selecthdrs(msg, cur->canon_hdrlist, hdrset,
                                             msg->arc_hdrcnt);

                if (nhdrs == -1)
                {
                    arc_error(
                        msg,
                        "arc_canon_selecthdrs() failed during canonicalization");
                    ARC_FREE(hdrset);
                    return ARC_STAT_INTERNAL;
                }
            }
        }
        else
        {
            ARC_LIB *lib;
            regex_t *hdrtest;

            lib = msg->arc_library;
            hdrtest = &lib->arcl_hdrre;

            memset(hdrset, '\0', sizeof *hdrset);

            /* tag all header fields to be signed */
            for (hdr = msg->arc_hhead; hdr != NULL; hdr = hdr->hdr_next)
            {
                /* RFC 8617 4.1.2
                 * Authentication-Results header fields MUST NOT
                 * be included in AMS signatures as they are
                 * likely to be deleted by downstream ADMDs
                 * (per [RFC8601], Section 5).
                 *
                 * ARC-related header fields
                 * (ARC-Authentication-Results,
                 * ARC-Message-Signature, and ARC-Seal) MUST NOT
                 * be included in the list of header fields
                 * covered by the signature of the AMS header
                 * field.
                 */
                if (strncasecmp(ARC_EXT_AR_HDRNAME, hdr->hdr_text,
                                hdr->hdr_namelen) == 0 ||
                    strncasecmp(ARC_SEAL_HDRNAME, hdr->hdr_text,
                                hdr->hdr_namelen) == 0 ||
                    strncasecmp(ARC_AR_HDRNAME, hdr->hdr_text,
                                hdr->hdr_namelen) == 0 ||
                    strncasecmp(ARC_MSGSIG_HDRNAME, hdr->hdr_text,
                                hdr->hdr_namelen) == 0)
                {
                    continue;
                }

                if (!lib->arcl_signre)
                {
                    /*
                    **  No header list configured, so
                    **  sign everything.
                    */

                    if (arc_dstring_len(msg->arc_hdrbuf) > 0)
                    {
                        if (!arc_dstring_cat1(msg->arc_hdrbuf, ':'))
                        {
                            ARC_FREE(hdrset);
                            return ARC_STAT_NORESOURCE;
                        }
                    }

                    if (!arc_dstring_catn(msg->arc_hdrbuf, hdr->hdr_text,
                                          hdr->hdr_namelen))
                    {
                        ARC_FREE(hdrset);
                        return ARC_STAT_NORESOURCE;
                    }
                    continue;
                }

                /*
                **  A list of header field names to sign was
                **  given, so just do those.
                */

                /* could be space, could be colon ... */
                savechar = hdr->hdr_text[hdr->hdr_namelen];

                /* terminate the header field name and test */
                hdr->hdr_text[hdr->hdr_namelen] = '\0';
                status = regexec(hdrtest, hdr->hdr_text, 0, NULL, 0);

                /* restore the character */
                hdr->hdr_text[hdr->hdr_namelen] = savechar;

                if (status == 0)
                {
                    if (arc_dstring_len(msg->arc_hdrbuf) > 0)
                    {
                        if (!arc_dstring_cat1(msg->arc_hdrbuf, ':'))
                        {
                            ARC_FREE(hdrset);
                            return ARC_STAT_NORESOURCE;
                        }
                    }

                    if (!arc_dstring_catn(msg->arc_hdrbuf, hdr->hdr_text,
                                          hdr->hdr_namelen))
                    {
                        ARC_FREE(hdrset);
                        return ARC_STAT_NORESOURCE;
                    }
                }
                else
                {
                    assert(status == REG_NOMATCH);
                }
            }

            memset(hdrset, '\0', n);

            /* do header selection */
            nhdrs = arc_canon_selecthdrs(msg, arc_dstring_get(msg->arc_hdrbuf),
                                         hdrset, msg->arc_hdrcnt);

            if (nhdrs == -1)
            {
                arc_error(
                    msg,
                    "arc_canon_selecthdrs() failed during canonicalization");
                ARC_FREE(hdrset);
                return ARC_STAT_INTERNAL;
            }
        }

        /* canonicalize each marked header */
        for (c = 0; c < nhdrs; c++)
        {
            if (hdrset[c] != NULL &&
                (hdrset[c]->hdr_flags & ARC_HDR_SIGNED) != 0)
            {
                status = arc_canon_header(msg, cur, hdrset[c], true);
                if (status != ARC_STAT_OK)
                {
                    ARC_FREE(hdrset);
                    return status;
                }
            }
        }

        /* if signing, we can't do the rest of this yet */
        if (cur->canon_sigheader == NULL)
        {
            continue;
        }

        /*
        **  We need to copy the ARC-Message-Signature: field being
        **  verified, minus the contents of the "b=" part, and include
        **  it in the canonicalization.  However, skip this if no
        **  hashing was done.
        */

        status = arc_canon_strip_b(msg, cur->canon_sigheader->hdr_text);
        if (status != ARC_STAT_OK)
        {
            ARC_FREE(hdrset);
            return status;
        }

        /* canonicalize */
        tmphdr.hdr_text = arc_dstring_get(msg->arc_hdrbuf);
        tmphdr.hdr_namelen = cur->canon_sigheader->hdr_namelen;
        tmphdr.hdr_textlen = arc_dstring_len(msg->arc_hdrbuf);
        tmphdr.hdr_flags = 0;
        tmphdr.hdr_next = NULL;

        (void) arc_canon_header(msg, cur, &tmphdr, false);
        arc_canon_buffer(cur, NULL, 0);

        /* finalize */
        arc_canon_finalize(cur);

        cur->canon_done = true;
    }

    ARC_FREE(hdrset);

    return ARC_STAT_OK;
}

/*
**  ARC_CANON_SIGNATURE -- append a signature header when signing
**
**  Parameters:
**  	msg -- ARC message handle
**  	hdr -- header
**  	type -- an ARC_CANONTYPE_*
**
**  Return value:
**  	A ARC_STAT_* constant.
**
**  Notes:
**  	Header canonicalizations are finalized by this function.
*/

ARC_STAT
arc_canon_signature(ARC_MESSAGE *msg, struct arc_hdrfield *hdr, int type)
{
    ARC_STAT            status;
    ARC_CANON          *cur;
    struct arc_hdrfield tmphdr;

    assert(msg != NULL);
    assert(hdr != NULL);

    if (msg->arc_hdrbuf == NULL)
    {
        msg->arc_hdrbuf = arc_dstring_new(ARC_MAXHEADER, 0, msg, &arc_error_cb);
        if (msg->arc_hdrbuf == NULL)
        {
            return ARC_STAT_NORESOURCE;
        }
    }
    else
    {
        arc_dstring_blank(msg->arc_hdrbuf);
    }

    for (cur = msg->arc_canonhead; cur != NULL; cur = cur->canon_next)
    {
        /* skip done hashes and those which are of the wrong type */
        if (cur->canon_done)
        {
            continue;
        }
        if (type != cur->canon_type)
        {
            continue;
        }

        /* prepare the data */
        if (!arc_dstring_copy(msg->arc_hdrbuf, hdr->hdr_text))
        {
            return ARC_STAT_NORESOURCE;
        }
        tmphdr.hdr_text = arc_dstring_get(msg->arc_hdrbuf);
        tmphdr.hdr_namelen = hdr->hdr_namelen;
        tmphdr.hdr_textlen = arc_dstring_len(msg->arc_hdrbuf);
        tmphdr.hdr_flags = 0;
        tmphdr.hdr_next = NULL;

        /* canonicalize the signature */
        status = arc_canon_header(msg, cur, &tmphdr, false);
        if (status != ARC_STAT_OK)
        {
            return status;
        }
        arc_canon_buffer(cur, NULL, 0);

        /* now close it */
        arc_canon_finalize(cur);

        cur->canon_done = true;
    }

    return ARC_STAT_OK;
}

/*
**  ARC_CANON_MINBODY -- return number of bytes required to satisfy all
**                       canonicalizations
**
**  Parameters:
**  	msg -- ARC message handle
**
**  Return value:
**  	0 -- all canonicalizations satisfied
**  	ULONG_MAX -- at least one canonicalization wants the whole message
**  	other -- bytes required to satisfy all canonicalizations
*/

unsigned long
arc_canon_minbody(ARC_MESSAGE *msg)
{
    unsigned long minbody = 0;
    ARC_CANON    *cur;

    assert(msg != NULL);

    for (cur = msg->arc_canonhead; cur != NULL; cur = cur->canon_next)
    {
        /* skip done hashes and those which are of the wrong type */
        if (cur->canon_done || cur->canon_type != ARC_CANONTYPE_BODY)
        {
            continue;
        }

        /* if this one wants the whole message, short-circuit */
        if (cur->canon_remain == (ssize_t) -1)
        {
            return ULONG_MAX;
        }

        /* compare to current minimum */
        minbody = MAX(minbody, (unsigned long) cur->canon_remain);
    }

    return minbody;
}

/*
**  ARC_CANON_BODYCHUNK -- run a body chunk through all body
**                          canonicalizations
**
**  Parameters:
**  	msg -- ARC message handle
**  	buf -- pointer to bytes to canonicalize
**  	buflen -- number of bytes to canonicalize
**
**  Return value:
**  	A ARC_STAT_* constant.
*/

ARC_STAT
arc_canon_bodychunk(ARC_MESSAGE *msg, const char *buf, size_t buflen)
{
    bool         fixcrlf;
    ARC_STAT     status;
    unsigned int wlen;
    ARC_CANON   *cur;
    size_t       plen;
    const char  *p;
    const char  *wrote;
    const char  *eob;
    const char  *start;

    assert(msg != NULL);

    msg->arc_bodylen += buflen;

    fixcrlf = (msg->arc_library->arcl_flags & ARC_LIBFLAGS_FIXCRLF);

    for (cur = msg->arc_canonhead; cur != NULL; cur = cur->canon_next)
    {
        /* skip done hashes and those which are of the wrong type */
        if (cur->canon_done || cur->canon_type != ARC_CANONTYPE_BODY)
        {
            continue;
        }

        start = buf;
        plen = buflen;

        if (fixcrlf)
        {
            status = arc_canon_fixcrlf(msg, cur, buf, buflen);
            if (status != ARC_STAT_OK)
            {
                return status;
            }

            start = arc_dstring_get(msg->arc_canonbuf);
            plen = arc_dstring_len(msg->arc_canonbuf);
        }

        eob = start + plen - 1;
        wrote = start;
        wlen = 0;

        switch (cur->canon_canon)
        {
        case ARC_CANON_SIMPLE:
            for (p = start; p <= eob; p++)
            {
                if (*p == '\n')
                {
                    if (cur->canon_lastchar == '\r')
                    {
                        if (cur->canon_blankline)
                        {
                            cur->canon_blanks++;
                        }
                        else if (wlen == 1 || p == start)
                        {
                            arc_canon_buffer(cur, CRLF, 2);
                        }
                        else
                        {
                            arc_canon_buffer(cur, wrote, wlen + 1);
                        }

                        wrote = p + 1;
                        wlen = 0;
                        cur->canon_blankline = true;
                    }
                }
                else
                {
                    if (p == start && cur->canon_lastchar == '\r')
                    {
                        if (fixcrlf)
                        {
                            arc_canon_buffer(cur, CRLF, 2);
                            cur->canon_lastchar = '\n';
                            cur->canon_blankline = true;
                        }
                        else
                        {
                            arc_canon_buffer(cur, "\r", 1);
                        }
                    }

                    if (*p != '\r')
                    {
                        if (cur->canon_blanks > 0)
                        {
                            arc_canon_flushblanks(cur);
                        }
                        cur->canon_blankline = false;
                    }

                    wlen++;
                }

                cur->canon_lastchar = *p;
            }

            if (wlen > 0 && wrote[wlen - 1] == '\r')
            {
                wlen--;
            }

            arc_canon_buffer(cur, wrote, wlen);

            break;

        case ARC_CANON_RELAXED:
            for (p = start; p <= eob; p++)
            {
                switch (cur->canon_bodystate)
                {
                case 0:
                    if (ARC_ISWSP(*p))
                    {
                        cur->canon_bodystate = 1;
                    }
                    else if (*p == '\r')
                    {
                        cur->canon_bodystate = 2;
                    }
                    else
                    {
                        cur->canon_blankline = false;
                        arc_dstring_cat1(cur->canon_buf, *p);
                        cur->canon_bodystate = 3;
                    }
                    break;

                case 1:
                    if (ARC_ISWSP(*p))
                    {
                        break;
                    }
                    else if (*p == '\r')
                    {
                        cur->canon_bodystate = 2;
                    }
                    else
                    {
                        arc_canon_flushblanks(cur);
                        arc_canon_buffer(cur, SP, 1);
                        cur->canon_blankline = false;
                        arc_dstring_cat1(cur->canon_buf, *p);
                        cur->canon_bodystate = 3;
                    }
                    break;

                case 2:
                    if (fixcrlf || *p == '\n')
                    {
                        if (cur->canon_blankline)
                        {
                            cur->canon_blanks++;
                            cur->canon_bodystate = 0;
                        }
                        else
                        {
                            arc_canon_flushblanks(cur);
                            arc_canon_buffer(cur,
                                             arc_dstring_get(cur->canon_buf),
                                             arc_dstring_len(cur->canon_buf));
                            arc_canon_buffer(cur, CRLF, 2);
                            arc_dstring_blank(cur->canon_buf);

                            if (*p == '\n')
                            {
                                cur->canon_blankline = true;
                                cur->canon_bodystate = 0;
                            }
                            else if (*p == '\r')
                            {
                                cur->canon_blankline = true;
                            }
                            else
                            {
                                if (ARC_ISWSP(*p))
                                {
                                    cur->canon_bodystate = 1;
                                }
                                else
                                {
                                    arc_dstring_cat1(cur->canon_buf, *p);
                                    cur->canon_bodystate = 3;
                                }
                            }
                        }
                    }
                    else if (*p == '\r')
                    {
                        cur->canon_blankline = false;
                        arc_dstring_cat1(cur->canon_buf, *p);
                    }
                    else if (ARC_ISWSP(*p))
                    {
                        arc_canon_flushblanks(cur);
                        arc_canon_buffer(cur, arc_dstring_get(cur->canon_buf),
                                         arc_dstring_len(cur->canon_buf));
                        arc_dstring_blank(cur->canon_buf);
                        cur->canon_bodystate = 1;
                    }
                    else
                    {
                        cur->canon_blankline = false;
                        arc_dstring_cat1(cur->canon_buf, *p);
                        cur->canon_bodystate = 3;
                    }
                    break;

                case 3:
                    if (ARC_ISWSP(*p))
                    {
                        arc_canon_flushblanks(cur);
                        arc_canon_buffer(cur, arc_dstring_get(cur->canon_buf),
                                         arc_dstring_len(cur->canon_buf));
                        arc_dstring_blank(cur->canon_buf);
                        cur->canon_bodystate = 1;
                    }
                    else if (*p == '\r')
                    {
                        cur->canon_bodystate = 2;
                    }
                    else
                    {
                        arc_dstring_cat1(cur->canon_buf, *p);
                    }
                    break;
                }

                cur->canon_lastchar = *p;
            }

            arc_canon_buffer(cur, NULL, 0);

            break;

        default:
            assert(0);
            /* NOTREACHED */
        }

        arc_canon_buffer(cur, NULL, 0);
    }

    return ARC_STAT_OK;
}

/*
**  ARC_CANON_CLOSEBODY -- close all body canonicalizations
**
**  Parameters:
**  	msg -- ARC message handle
**
**  Return value:
**  	A ARC_STAT_* constant.
*/

ARC_STAT
arc_canon_closebody(ARC_MESSAGE *msg)
{
    ARC_CANON *cur;

    assert(msg != NULL);

    for (cur = msg->arc_canonhead; cur != NULL; cur = cur->canon_next)
    {
        /* skip done hashes or header canonicalizations */
        if (cur->canon_done || cur->canon_type != ARC_CANONTYPE_BODY)
        {
            continue;
        }

        /* handle unprocessed content */
        if (arc_dstring_len(cur->canon_buf) > 0)
        {
            if ((msg->arc_library->arcl_flags & ARC_LIBFLAGS_FIXCRLF) != 0)
            {
                arc_canon_buffer(cur, arc_dstring_get(cur->canon_buf),
                                 arc_dstring_len(cur->canon_buf));
                arc_canon_buffer(cur, CRLF, 2);
            }
            else
            {
                arc_error(msg, "CRLF at end of body missing");
                return ARC_STAT_SYNTAX;
            }
        }

        arc_canon_buffer(cur, NULL, 0);

        if (cur->canon_remain > 0)
        {
            arc_error(msg, "body length in signature longer than actual body");
            return ARC_STAT_SYNTAX;
        }

        /* finalize */
        arc_canon_finalize(cur);

        cur->canon_done = true;
    }

    return ARC_STAT_OK;
}

/*
**  ARC_CANON_GETFINAL -- retrieve final digest
**
**  Parameters:
**  	canon -- ARC_CANON handle
**  	digest -- pointer to the digest (returned)
**  	dlen -- digest length (returned)
**
**  Return value:
**  	A ARC_STAT_* constant.
*/

ARC_STAT
arc_canon_getfinal(ARC_CANON *canon, unsigned char **digest, size_t *dlen)
{
    assert(canon != NULL);
    assert(digest != NULL);
    assert(dlen != NULL);

    if (!canon->canon_done)
    {
        return ARC_STAT_INVALID;
    }

    *digest = canon->canon_hash->hash_out;
    *dlen = canon->canon_hash->hash_outlen;

    return ARC_STAT_OK;
}

/*
**  ARC_CANON_GETSEALHASHES -- retrieve a seal hash
**
**  Parameters:
**  	msg -- ARC message from which to get completed hashes
**  	setnum -- which seal's hash to get
**  	sh -- pointer to seal hash buffer (returned)
**  	shlen -- bytes used at sh (returned)
**
**  Return value:
**  	ARC_STAT_OK -- successful completion
**  	ARC_STAT_INVALID -- hashing hasn't been completed
*/

ARC_STAT
arc_canon_getsealhash(ARC_MESSAGE *msg, int setnum, void **sh, size_t *shlen)
{
    ARC_STAT          status;
    struct arc_canon *sdc;
    unsigned char    *sd;
    size_t            sdlen;

    assert(msg != NULL);
    assert(setnum <= msg->arc_nsets);

    sdc = msg->arc_sealcanons[setnum - 1];

    status = arc_canon_getfinal(sdc, &sd, &sdlen);
    if (status != ARC_STAT_OK)
    {
        return status;
    }
    *sh = sd;
    *shlen = sdlen;

    return ARC_STAT_OK;
}

/*
**  ARC_CANON_GETHASHES -- retrieve hashes
**
**  Parameters:
**  	msg -- ARC message from which to get completed hashes
**      setnum -- which seal's hashes to get
**  	hh -- pointer to header hash buffer (returned)
**  	hhlen -- bytes used at hh (returned)
**  	bh -- pointer to body hash buffer (returned)
**  	bhlen -- bytes used at bh (returned)
**
**  Return value:
**  	ARC_STAT_OK -- successful completion
**  	ARC_STAT_INVALID -- hashing hasn't been completed
*/

ARC_STAT
arc_canon_gethashes(ARC_MESSAGE *msg,
                    int          setnum,
                    void       **hh,
                    size_t      *hhlen,
                    void       **bh,
                    size_t      *bhlen)
{
    ARC_STAT          status;
    struct arc_canon *hdc;
    struct arc_canon *bdc;
    unsigned char    *hd;
    unsigned char    *bd;
    size_t            hdlen;
    size_t            bdlen;

    hdc = msg->arc_hdrcanons[setnum - 1];
    bdc = msg->arc_bodycanons[setnum - 1];

    status = arc_canon_getfinal(hdc, &hd, &hdlen);
    if (status != ARC_STAT_OK)
    {
        return status;
    }
    *hh = hd;
    *hhlen = hdlen;

    status = arc_canon_getfinal(bdc, &bd, &bdlen);
    if (status != ARC_STAT_OK)
    {
        return status;
    }
    *bh = bd;
    *bhlen = bdlen;

    return ARC_STAT_OK;
}

/*
**  ARC_CANON_ADD_TO_SEAL -- canonicalize partial seal
**
**  Parameters:
**  	msg -- ARC message to update
**
**  Return value:
**  	ARC_STAT_OK -- successful completion
*/

ARC_STAT
arc_canon_add_to_seal(ARC_MESSAGE *msg)
{
    ARC_STAT             status;
    struct arc_hdrfield *hdr;

    for (hdr = msg->arc_sealhead; hdr != NULL; hdr = hdr->hdr_next)
    {
        status = arc_canon_header(msg, msg->arc_sealcanon, hdr, true);
        if (status != ARC_STAT_OK)
        {
            return status;
        }
    }

    return ARC_STAT_OK;
}

/*
**  ARC_PARSE_CANON_T -- parse a c= tag
**
**  Parameters:
**    tag        -- c=
**    hdr_canon  -- the header canon output
**    body_canon -- the body canon output
**
**  Return value:
**    ARC_STAT_OK -- successful completion
*/

ARC_STAT
arc_parse_canon_t(char *tag, arc_canon_t *hdr_canon, arc_canon_t *body_canon)
{
    char *token = NULL;
    int   code = 0;
    char *last = NULL;

    assert(tag != NULL);
    assert(hdr_canon != NULL);
    assert(body_canon != NULL);

    if (tag[0] == '\0')
    {
        return ARC_STAT_INVALID;
    }

    token = strtok_r(tag, "/", &last);
    code = arc_name_to_code(canonicalizations, token);

    if (code == -1)
    {
        return ARC_STAT_INVALID;
    }

    *hdr_canon = (arc_canon_t) code;

    token = strtok_r(NULL, "/", &last);

    if (token == NULL)
    {
        /* Per RFC 6376, if no body canonicalization is provided the
         * default is simple. */
        *body_canon = ARC_CANON_SIMPLE;
    }
    else
    {
        code = arc_name_to_code(canonicalizations, token);

        if (code == -1)
        {
            return ARC_STAT_INVALID;
        }
        *body_canon = (arc_canon_t) code;
    }

    return ARC_STAT_OK;
}
