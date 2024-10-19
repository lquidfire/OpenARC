/*
**  Copyright (c) 2005, 2007 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009, 2012, The Trusted Domain Project.  All rights reserved.
*/

#ifndef ARC_ARC_KEYS_H_
#define ARC_ARC_KEYS_H_

/* libopenarc includes */
#include "arc.h"

/* prototypes */
extern ARC_STAT arc_get_key_dns(ARC_MESSAGE *, char *, size_t);
extern ARC_STAT arc_get_key_file(ARC_MESSAGE *, char *, size_t);

#endif /* ! ARC_ARC_KEYS_H_ */
