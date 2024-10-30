/*
**  Copyright (c) 2016, 2017, The Trusted Domain Project.  All rights reserved.
*/

#ifndef _ARC_UTIL_H_
#define _ARC_UTIL_H_

#include "build-config.h"

/* system includes */
#include <stdbool.h>
#include <sys/param.h>
#include <sys/types.h>

/* libopenarc includes */
#include "arc.h"

extern int      arc_check_dns_reply(unsigned char *ansbuf,
                                    size_t         anslen,
                                    int            xclass,
                                    int            xtype);

extern bool     arc_hdrlist(char *, size_t, char **, bool);

extern void     arc_min_timeval(struct timeval *,
                                struct timeval *,
                                struct timeval *,
                                struct timeval **);

extern ARC_STAT arc_tmpfile(ARC_MESSAGE *, int *, bool);

#endif /* _ARC_UTIL_H_ */
