/*
**  Copyright (c) 2007 Sendmail, Inc. and its suppliers.
**	All rights reserved.
**
**  Copyright (c) 2009-2012, The Trusted Domain Project.  All rights reserved.
**
*/

#ifndef _TEST_H_
#define _TEST_H_

/* system includes */
#include <sys/param.h>
#include <sys/types.h>

/* libmilter includes */
#include <libmilter/mfapi.h>

/* libopenarc includes */
#include "arc.h"

/* PROTOTYPES */
extern int   arcf_testfiles(ARC_LIB *, char *, int);

extern int   arcf_test_addheader(void *, char *, char *);
extern int   arcf_test_addrcpt(void *, char *);
extern int   arcf_test_chgheader(void *, char *, int, char *);
extern int   arcf_test_delrcpt(void *, char *);
extern void *arcf_test_getpriv(void *);
extern char *arcf_test_getsymval(void *, char *);
extern int   arcf_test_insheader(void *, int, char *, char *);
extern int   arcf_test_progress(void *);
extern int   arcf_test_quarantine(void *, char *);
extern int   arcf_test_setpriv(void *, void *);
extern int   arcf_test_setreply(void *, char *, char *, char *);

#endif /* _TEST_H_ */
