/* Copyright 2024 OpenARC contributors.
 * See LICENSE.
 */

#ifndef ARC_BASE64_H
#define ARC_BASE64_H

#include <sys/types.h>

extern int arc_base64_decode(const unsigned char *, unsigned char *, size_t);
extern int arc_base64_encode(const unsigned char *,
                             size_t,
                             unsigned char *,
                             size_t);

#endif /* ARC_BASE64_H */
