/*
**  Copyright (c) 2005-2008 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009, 2010, 2012, 2014-2016, The Trusted Domain Project.
**    All rights reserved.
*/

#ifndef ARC_ARC_TABLES_H_
#define ARC_ARC_TABLES_H_

/* structures */
struct nametable
{
    const char *tbl_name; /* name */
    const int   tbl_code; /* code */
};

/* tables */
extern struct nametable *algorithms;
extern struct nametable *archdrnames;
extern struct nametable *canonicalizations;
extern struct nametable *chainstatus;
extern struct nametable *hashes;
extern struct nametable *keyflags;
extern struct nametable *keytypes;
extern struct nametable *settypes;
extern struct nametable *sigerrors;

/* prototypes */
extern const char *arc_code_to_name(struct nametable *tbl, const int code);
extern const int   arc_name_to_code(struct nametable *tbl, const char *name);

#endif /* ARC_ARC_TABLES_H_ */
