/*
 *  Copyright 2024 OpenARC contributors.
 *  See LICENSE.
 */

#ifndef ARC_ARC_NAMETABLE_H
#define ARC_ARC_NAMETABLE_H

struct nametable
{
    const char *nt_name;
    const int   nt_code;
};

extern const char *arc_code_to_name(struct nametable *, int);
extern int         arc_name_to_code(struct nametable *, const char *);

#endif /* ARC_ARC_NAMETABLE_H */
