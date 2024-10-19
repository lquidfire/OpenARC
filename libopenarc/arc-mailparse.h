/*
**  Copyright (c) 2004 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009, 2010, 2012, 2014, 2019, The Trusted Domain Project.
**    All rights reserved.
*/

#ifndef ARC_ARC_MAILPARSE_H_
#define ARC_ARC_MAILPARSE_H_

/* prototypes */
extern int arc_mail_parse(unsigned char *line, unsigned char **user_out,
                          unsigned char **domain_out);
extern int arc_mail_parse_multi(unsigned char *line, unsigned char ***users_out,
                                unsigned char ***domains_out);
#endif /* ! ARC_ARC_MAILPARSE_H_ */
