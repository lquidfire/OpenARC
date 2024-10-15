/*
**  Copyright (c) 2016, 2017, The Trusted Domain Project.  All rights reserved.
*/

#ifndef _ARC_UTIL_H_
#define _ARC_UTIL_H_

#include "build-config.h"

/* system includes */
#include <sys/types.h>
#include <sys/param.h>
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#endif /* HAVE_STDBOOL_H */

/* libopenarc includes */
#include "arc.h"

extern int arc_check_dns_reply __P((unsigned char *ansbuf, size_t anslen,
                                    int xclass, int xtype));

extern _Bool arc_hdrlist __P((u_char *, size_t, u_char **, _Bool));

extern void arc_min_timeval __P((struct timeval *, struct timeval *,
                                 struct timeval *, struct timeval **));

extern ARC_STAT arc_tmpfile __P((ARC_MESSAGE *, int *, _Bool));

#endif /* _ARC_UTIL_H_ */
