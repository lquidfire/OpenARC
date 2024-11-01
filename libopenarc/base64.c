/* Copyright 2024 OpenARC contributors.
 * See LICENSE.
 */

#include <assert.h>
#include <string.h>
#include <sys/types.h>

#include <openssl/bio.h>
#include <openssl/evp.h>

#include "base64.h"

/**
 *  Decode a base64 blob.
 *
 *  Parameters:
 *      str: string to decode
 *      buf: output buffer
 *      buflen: bytes available in the output buffer
 *
 *  Returns:
 *      Length of the decoded data on success, -2 if there is insufficient
 *      space in the output buffer or an internal error occurred, or -1 if
 *      decoding failed because the input was bad.
 */

int
arc_base64_decode(const unsigned char *str, unsigned char *buf, size_t buflen)
{
    int    retval = -2;
    size_t len;
    BIO   *bmem;
    BIO   *b64;

    assert(str != NULL);
    assert(buf != NULL);

    /* check to make sure there's room */
    len = strlen((const char *) str);
    if (len % 4 > 0)
    {
        return -1;
    }

    if (len / 4 * 3 > buflen)
    {
        return -2;
    }

    bmem = BIO_new_mem_buf(str, -1);
    if (bmem == NULL)
    {
        return retval;
    }
    b64 = BIO_push(BIO_new(BIO_f_base64()), bmem);
    if (b64 == bmem)
    {
        goto error;
    }
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    retval = BIO_read(b64, buf, buflen);

error:
    BIO_free_all(b64);
    return retval;
}

/**
 *  Encode data as base64.
 *
 *  Parameters:
 *      data: data to encode
 *      datalen: length of data to encode
 *      buf: output buffer
 *      buflen: bytes available in the output buffer
 *
 *  Returns:
 *      Length of the encoded data, or -1 if an error occurred.
 */

int
arc_base64_encode(const unsigned char *data,
                  size_t               datalen,
                  unsigned char       *buf,
                  size_t               buflen)
{
    int  retval = -1;
    BIO *bmem;
    BIO *b64;

    assert(data != NULL);
    assert(buf != NULL);

    bmem = BIO_new(BIO_s_mem());
    if (bmem == NULL)
    {
        return retval;
    }
    b64 = BIO_push(BIO_new(BIO_f_base64()), bmem);
    if (b64 == bmem)
    {
        goto error;
    }
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64, data, datalen);
    BIO_flush(b64);
    retval = BIO_read(bmem, buf, buflen);

    if (retval > 0 && BIO_eof(bmem) != 1)
    {
        retval = -1;
    }

error:
    BIO_free_all(b64);
    return retval;
}
