/*
**  Copyright (c) 2005-2009 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009-2012, 2014-2016, The Trusted Domain Project.
**  	All rights reserved.
*/

#include "build-config.h"

/* system includes */
#include <assert.h>
#include <string.h>
#include <sys/types.h>

/* libopenarc includes */
#include "arc-internal.h"
#include "arc-tables.h"

/* lookup tables */
static struct nametable prv_algorithms[] = /* signing algorithms */
    {
        {"rsa-sha1",   ARC_SIGN_RSASHA1  },
        {"rsa-sha256", ARC_SIGN_RSASHA256},
        {NULL,         -1                },
};
struct nametable       *algorithms = prv_algorithms;

static struct nametable prv_archdrnames[] = /* header field names:types */
    {
        {ARC_AR_HDRNAME,     ARC_KVSETTYPE_AR       },
        {ARC_SEAL_HDRNAME,   ARC_KVSETTYPE_SEAL     },
        {ARC_MSGSIG_HDRNAME, ARC_KVSETTYPE_SIGNATURE},
        {NULL,               -1                     },
};
struct nametable       *archdrnames = prv_archdrnames;

static struct nametable prv_canonicalizations[] = /* canonicalizations */
    {
        {"simple",  ARC_CANON_SIMPLE },
        {"relaxed", ARC_CANON_RELAXED},
        {NULL,      -1               },
};
struct nametable       *canonicalizations = prv_canonicalizations;

static struct nametable prv_hashes[] = /* hashes */
    {
        {"sha1",   ARC_HASHTYPE_SHA1  },
        {"sha256", ARC_HASHTYPE_SHA256},
        {NULL,     -1                 },
};
struct nametable       *hashes = prv_hashes;

static struct nametable prv_keyflags[] = /* key flags */
    {
        {"y",  ARC_KEYFLAG_TESTKEY    },
        {"s",  ARC_KEYFLAG_NOSUBDOMAIN},
        {NULL, -1                     }
};
struct nametable       *keyflags = prv_keyflags;

static struct nametable prv_keytypes[] = /* key types */
    {
        {"rsa", ARC_KEYTYPE_RSA},
        {NULL,  -1             },
};
struct nametable       *keytypes = prv_keytypes;

static struct nametable prv_querytypes[] = /* query types */
    {
        {"dns", ARC_QUERY_DNS},
        {NULL,  -1           },
};
struct nametable       *querytypes = prv_querytypes;

static struct nametable prv_chainstatus[] = /* chain status */
    {
        {"none",    ARC_CHAIN_NONE   },
        {"fail",    ARC_CHAIN_FAIL   },
        {"pass",    ARC_CHAIN_PASS   },
        {"unknown", ARC_CHAIN_UNKNOWN},
        {NULL,      -1               },
};
struct nametable       *chainstatus = prv_chainstatus;

static struct nametable prv_results[] = /* result codes */
    {
        {"Success",              ARC_STAT_OK          },
        {"Bad signature",        ARC_STAT_BADSIG      },
        {"No signature",         ARC_STAT_NOSIG       },
        {"No key",               ARC_STAT_NOKEY       },
        {"Unable to verify",     ARC_STAT_CANTVRFY    },
        {"Syntax error",         ARC_STAT_SYNTAX      },
        {"Resource unavailable", ARC_STAT_NORESOURCE  },
        {"Internal error",       ARC_STAT_INTERNAL    },
        {"Revoked key",          ARC_STAT_REVOKED     },
        {"Invalid parameter",    ARC_STAT_INVALID     },
        {"Not implemented",      ARC_STAT_NOTIMPLEMENT},
        {"Key retrieval failed", ARC_STAT_KEYFAIL     },
        {NULL,                   -1                   },
};
struct nametable       *results = prv_results;

static struct nametable prv_settypes[] = /* set types */
    {
        {"key",           ARC_KVSETTYPE_KEY      },
        {"ARC signature", ARC_KVSETTYPE_SIGNATURE},
        {"ARC seal",      ARC_KVSETTYPE_SEAL     },
        {"ARC results",   ARC_KVSETTYPE_AR       },
        {NULL,            -1                     },
};
struct nametable *settypes = prv_settypes;
