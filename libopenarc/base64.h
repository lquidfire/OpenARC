/*
**  Copyright (c) 2016, The Trusted Domain Project.  All rights reserved.
*/

#ifndef ARC_BASE64_H_
#define ARC_BASE64_H_

/* system includes */
#include <sys/types.h>

/* prototypes */
extern int arc_base64_decode(const unsigned char *str, unsigned char *buf,
                             size_t buflen);
extern int arc_base64_encode(const unsigned char *data, size_t datalen,
                             unsigned char *buf, size_t buflen);

#endif /* ! ARC_BASE64_H_ */
