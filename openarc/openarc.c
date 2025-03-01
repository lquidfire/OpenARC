/*
**  Copyright (c) 2009-2017, The Trusted Domain Project.  All rights reserved.
*/

#include "build-config.h"

#ifndef _POSIX_PTHREAD_SEMANTICS
#define _POSIX_PTHREAD_SEMANTICS
#endif /* ! _POSIX_PTHREAD_SEMANTICS */

/* system includes */
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#ifdef HAVE_ISO_LIMITS_ISO_H
#include <iso/limits_iso.h>
#endif /* HAVE_ISO_LIMITS_ISO_H */
#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif /* HAVE_LIMITS_H */
#ifdef __linux__
#include <sys/prctl.h>
#endif /* __linux__ */
#include <sys/queue.h>
#ifdef AF_INET6
#include <arpa/inet.h>
#endif /* AF_INET6 */
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <math.h>
#include <netdb.h>
#include <pthread.h>
#include <pwd.h>
#include <regex.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <syslog.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/sha.h>

#ifdef HAVE_PATHS_H
#include <paths.h>
#endif /* HAVE_PATHS_H */
#ifndef _PATH_DEVNULL
#define _PATH_DEVNULL "/dev/null"
#endif /* ! _PATH_DEVNULL */

/* libmilter includes */
#include "libmilter/mfapi.h"

/* libopenarc includes */
#include "arc.h"

/* libbsd if found */
#ifdef USE_BSD_H
#include <bsd/string.h>
#endif /* USE_BSD_H */

/* libstrl if needed */
#ifdef USE_STRL_H
#include <strl.h>
#endif /* USE_STRL_H */

/* openarc includes */
#include "arc-dstring.h"
#include "arc-nametable.h"
#include "config.h"
#include "openarc-ar.h"
#include "openarc-config.h"
#include "openarc-crypto.h"
#include "openarc-test.h"
#include "openarc.h"
#include "util.h"

/* macros */
#define CMDLINEOPTS "Ac:fhlnp:P:r:t:u:vV"

/*
**  CONFIGVALUE -- a list of configuration values
*/

struct configvalue
{
    char *value;
    LIST_ENTRY(configvalue) entries;
};
LIST_HEAD(conflist, configvalue);

/*
**  CONFIG -- configuration data
*/

struct arcf_config
{
    bool            conf_dolog;             /* syslog interesting stuff? */
    bool            conf_milterv2;          /* using milter v2? */
    bool            conf_disablecryptoinit; /* disable crypto lib init */
    bool            conf_enablecores;       /* enable coredumps */
    bool            conf_reqhdrs;           /* enforce RFC5322 */
    bool            conf_addswhdr;          /* add software header field */
    bool            conf_safekeys;          /* require safe keys */
    bool            conf_keeptmpfiles;      /* keep temp files */
    bool            conf_finalreceiver;     /* act as final receiver */
    bool            conf_overridecv;        /* allow A-R to override CV */
    bool            conf_authresip;         /* include remote IP in A-R */
    unsigned int    conf_refcnt;            /* reference count */
    unsigned int    conf_mode;              /* mode flags */
    arc_canon_t     conf_canonhdr;          /* canonicalization for header */
    arc_canon_t     conf_canonbody;         /* canonicalization for body */
    arc_alg_t       conf_signalg;           /* signing algorithm */
    uint64_t        conf_fixedtime;         /* fixed timestamp */
    char           *conf_selector;          /* signing selector */
    char           *conf_keyfile;           /* key file */
    char           *conf_testkeys;          /* keys for non-DNS lookup */
    char           *conf_tmpdir;            /* temp file directory */
    char           *conf_authservid;        /* ID for A-R fields */
    char           *conf_peerfile;          /* peer hosts table */
    char           *conf_domain;            /* domain */
    char           *conf_signhdrs_raw;      /* headers to sign (raw) */
    const char    **conf_signhdrs;          /* headers to sign (array) */
    char           *conf_oversignhdrs_raw;  /* fields to over-sign (raw) */
    const char    **conf_oversignhdrs;      /* fields to over-sign (array) */
    unsigned char  *conf_keydata;           /* binary key data */
    size_t          conf_keylen;            /* key length */
    int             conf_maxhdrsz;          /* max. header size */
    int             conf_minkeysz;          /* min. key size */
    int             conf_sigttl;            /* signature TTL */
    int             conf_ret_disabled;      /* configured not to process */
    int             conf_ret_unable;        /* internal error */
    int             conf_ret_unwilling;     /* badly formed message */
    struct config  *conf_data;              /* configuration data */
    ARC_LIB        *conf_libopenarc;        /* shared library instance */
    struct conflist conf_peers;             /* peers hosts */
    struct conflist conf_internal;          /* internal hosts */
    struct conflist conf_sealheaderchecks;  /* header checks for sealing */
};

/*
**  MSGCTX -- message context, containing transaction-specific data
*/

typedef struct msgctx *msgctx;
struct msgctx
{
    bool                mctx_peer;     /* peer source? */
    ssize_t             mctx_hdrbytes; /* count of header bytes */
    unsigned char      *mctx_jobid;    /* job ID */
    struct Header      *mctx_hqhead;   /* header queue head */
    struct Header      *mctx_hqtail;   /* header queue tail */
    ARC_MESSAGE        *mctx_arcmsg;   /* libopenarc message */
    struct arc_dstring *mctx_tmpstr;   /* temporary string */
};

/*
**  CONNCTX -- connection context, containing thread-specific data
*/

typedef struct connctx *connctx;
struct connctx
{
    bool         cctx_milterv2;  /* milter v2 available */
    bool         cctx_noleadspc; /* no leading spaces */
    unsigned int cctx_mode;      /* operating mode */
    char         cctx_host[ARC_MAXHOSTNAMELEN + 1];
    /* hostname */
    struct sockaddr_storage cctx_ip;     /* IP info */
    struct arcf_config     *cctx_config; /* configuration in use */
    struct msgctx          *cctx_msg;    /* message context */
};

/*
**  LOOKUP -- generic lookup table
*/

struct nametable log_facilities[] = {
    {"auth",     LOG_AUTH  },
    {"cron",     LOG_CRON  },
    {"daemon",   LOG_DAEMON},
    {"kern",     LOG_KERN  },
    {"lpr",      LOG_LPR   },
    {"mail",     LOG_MAIL  },
    {"news",     LOG_NEWS  },
    {"security", LOG_AUTH  }, /* DEPRECATED */
    {"syslog",   LOG_SYSLOG},
    {"user",     LOG_USER  },
    {"uucp",     LOG_UUCP  },
    {"local0",   LOG_LOCAL0},
    {"local1",   LOG_LOCAL1},
    {"local2",   LOG_LOCAL2},
    {"local3",   LOG_LOCAL3},
    {"local4",   LOG_LOCAL4},
    {"local5",   LOG_LOCAL5},
    {"local6",   LOG_LOCAL6},
    {"local7",   LOG_LOCAL7},
    {NULL,       -1        }
};

struct nametable arcf_canonicalizations[] = {
    {"simple",  ARC_CANON_SIMPLE },
    {"relaxed", ARC_CANON_RELAXED},
    {NULL,      -1               }
};

struct nametable arcf_signalgorithms[] = {
    {"rsa-sha1",   ARC_SIGN_RSASHA1  },
    {"rsa-sha256", ARC_SIGN_RSASHA256},
    {NULL,         -1                }
};

struct nametable arcf_chainstates[] = {
    {"none", ARC_CHAIN_NONE},
    {"pass", ARC_CHAIN_PASS},
    {"fail", ARC_CHAIN_FAIL},
    {NULL,   -1            }
};

struct nametable arcf_responses[] = {
    {"accept",   SMFIS_ACCEPT  },
    {"discard",  SMFIS_DISCARD },
    {"reject",   SMFIS_REJECT  },
    {"tempfail", SMFIS_TEMPFAIL},
    {NULL,       -1            }
};

/* PROTOTYPES */
sfsistat      mlfi_abort(SMFICTX *);
sfsistat      mlfi_close(SMFICTX *);
sfsistat      mlfi_connect(SMFICTX *, char *, _SOCK_ADDR *);
sfsistat      mlfi_envfrom(SMFICTX *, char **);
sfsistat      mlfi_eoh(SMFICTX *);
sfsistat      mlfi_body(SMFICTX *, unsigned char *, size_t);
sfsistat      mlfi_eom(SMFICTX *);
sfsistat      mlfi_header(SMFICTX *, char *, char *);
sfsistat      mlfi_negotiate(SMFICTX *,
                             unsigned long,
                             unsigned long,
                             unsigned long,
                             unsigned long,
                             unsigned long *,
                             unsigned long *,
                             unsigned long *,
                             unsigned long *);

static Header arcf_findheader(msgctx, char *, int);

/* GLOBALS */
bool                dolog;      /* logging? (exported) */
bool                reload;     /* reload requested */
bool                no_i_whine; /* noted ${i} is undefined */
bool                die;        /* global "die" flag */
bool                testmode;   /* test mode */
int                 diesig;     /* signal to distribute */
char               *progname;   /* program name */
char               *sock;       /* listening socket */
char               *conffile;   /* configuration file */
struct arcf_config *curconf;    /* current configuration */
pthread_mutex_t     conf_lock;  /* config lock */
pthread_mutex_t     pwdb_lock;  /* passwd/group lock */
char                myhostname[MAXHOSTNAMELEN + 1]; /* local host's name */

/* Other useful definitions */
#define CRLF           "\r\n" /* CRLF */
#define SUPERUSER      "root" /* superuser name */

/* MACROS */
#define BITSET(b, s)   (((b) & (s)) == (b))
#define JOBID(x)       ((x) == NULL ? JOBIDUNKNOWN : (char *) (x))
#define ARCF_EOHMACROS "i {daemon_name} {auth_type}"

/*
**  ==================================================================
**  BEGIN private section
*/

#ifndef HAVE_SMFI_INSHEADER
/*
**  SMFI_INSHEADER -- stub for smfi_insheader() which didn't exist before
**                    sendmail 8.13.0
**
**  Parameters:
**  	ctx -- milter context
**  	idx -- insertion index
**  	hname -- header name
**  	hvalue -- header value
**
**  Return value:
**  	An sfsistat.
*/

sfsistat
smfi_insheader(SMFICTX *ctx, int idx, char *hname, char *hvalue)
{
    assert(ctx != NULL);
    assert(hname != NULL);
    assert(hvalue != NULL);

    return smfi_addheader(ctx, hname, hvalue);
}
#endif /* ! HAVE_SMFI_INSHEADER */

/*
**  ARCF_GETPRIV -- wrapper for smfi_getpriv()
**
**  Parameters:
**  	ctx -- milter (or test) context
**
**  Return value:
**  	The stored private pointer, or NULL.
*/

void *
arcf_getpriv(SMFICTX *ctx)
{
    assert(ctx != NULL);

    if (testmode)
    {
        return arcf_test_getpriv((void *) ctx);
    }
    else
    {
        return smfi_getpriv(ctx);
    }
}

/*
**  ARCF_SETPRIV -- wrapper for smfi_setpriv()
**
**  Parameters:
**  	ctx -- milter (or test) context
**
**  Return value:
**  	An sfsistat.
*/

sfsistat
arcf_setpriv(SMFICTX *ctx, void *ptr)
{
    assert(ctx != NULL);

    if (testmode)
    {
        return arcf_test_setpriv((void *) ctx, ptr);
    }
    else
    {
        return smfi_setpriv(ctx, ptr);
    }
}

/*
**  ARCF_INSHEADER -- wrapper for smfi_insheader()
**
**  Parameters:
**  	ctx -- milter (or test) context
**  	idx -- index at which to insert
**  	hname -- header name
**  	hvalue -- header value
**
**  Return value:
**  	An sfsistat.
*/

sfsistat
arcf_insheader(SMFICTX *ctx, int idx, char *hname, char *hvalue)
{
    assert(ctx != NULL);
    assert(hname != NULL);
    assert(hvalue != NULL);

    if (testmode)
    {
        return arcf_test_insheader(ctx, idx, hname, hvalue);
    }
    else
#ifdef HAVE_SMFI_INSHEADER
        return smfi_insheader(ctx, idx, hname, hvalue);
#else  /* HAVE_SMFI_INSHEADER */
        return smfi_addheader(ctx, hname, hvalue);
#endif /* HAVE_SMFI_INSHEADER */
}

/*
**  ARCF_CHGHEADER -- wrapper for smfi_chgheader()
**
**  Parameters:
**  	ctx -- milter (or test) context
**  	hname -- header name
**  	idx -- index of header to be changed
**  	hvalue -- header value
**
**  Return value:
**  	An sfsistat.
*/

sfsistat
arcf_chgheader(SMFICTX *ctx, char *hname, int idx, char *hvalue)
{
    assert(ctx != NULL);
    assert(hname != NULL);

    if (testmode)
    {
        return arcf_test_chgheader(ctx, hname, idx, hvalue);
    }
    else
    {
        return smfi_chgheader(ctx, hname, idx, hvalue);
    }
}

/*
**  ARCF_ADDHEADER -- wrapper for smfi_addheader()
**
**  Parameters:
**  	ctx -- milter (or test) context
**  	hname -- header name
**  	hvalue -- header value
**
**  Return value:
**  	An sfsistat.
*/

sfsistat
arcf_addheader(SMFICTX *ctx, char *hname, char *hvalue)
{
    assert(ctx != NULL);
    assert(hname != NULL);
    assert(hvalue != NULL);

    if (testmode)
    {
        return arcf_test_addheader(ctx, hname, hvalue);
    }
    else
    {
        return smfi_addheader(ctx, hname, hvalue);
    }
}

/*
**  ARCF_ADDRCPT -- wrapper for smfi_addrcpt()
**
**  Parameters:
**  	ctx -- milter (or test) context
**  	addr -- address to add
**
**  Return value:
**  	An sfsistat.
*/

sfsistat
arcf_addrcpt(SMFICTX *ctx, char *addr)
{
    assert(ctx != NULL);
    assert(addr != NULL);

    if (testmode)
    {
        return arcf_test_addrcpt(ctx, addr);
    }
    else
    {
        return smfi_addrcpt(ctx, addr);
    }
}

/*
**  ARCF_DELRCPT -- wrapper for smfi_delrcpt()
**
**  Parameters:
**  	ctx -- milter (or test) context
**  	addr -- address to delete
**
**  Return value:
**  	An sfsistat.
*/

sfsistat
arcf_delrcpt(SMFICTX *ctx, char *addr)
{
    assert(ctx != NULL);
    assert(addr != NULL);

    if (testmode)
    {
        return arcf_test_delrcpt(ctx, addr);
    }
    else
    {
        return smfi_delrcpt(ctx, addr);
    }
}

/*
**  ARCF_SETREPLY -- wrapper for smfi_setreply()
**
**  Parameters:
**  	ctx -- milter (or test) context
**  	rcode -- SMTP reply code
**  	xcode -- SMTP enhanced status code
**  	replytxt -- reply text
**
**  Return value:
**  	An sfsistat.
*/

sfsistat
arcf_setreply(SMFICTX *ctx, char *rcode, char *xcode, char *replytxt)
{
    assert(ctx != NULL);

    if (testmode)
    {
        return arcf_test_setreply(ctx, rcode, xcode, replytxt);
    }
    else
    {
        return smfi_setreply(ctx, rcode, xcode, replytxt);
    }
}

/*
**  ARCF_GETSYMVAL -- wrapper for smfi_getsymval()
**
**  Parameters:
**  	ctx -- milter (or test) context
**  	sym -- symbol to retrieve
**
**  Return value:
**  	Pointer to the value of the requested MTA symbol.
*/

char *
arcf_getsymval(SMFICTX *ctx, char *sym)
{
    assert(ctx != NULL);
    assert(sym != NULL);

    if (testmode)
    {
        return arcf_test_getsymval(ctx, sym);
    }
    else
    {
        return smfi_getsymval(ctx, sym);
    }
}

/*
**  ARCF_INIT_SYSLOG -- initialize syslog()
**
**  Parameters:
**  	facility -- name of the syslog facility to use when logging;
**  	            can be NULL to request the default
**
**  Return value:
**  	None.
*/

static void
arcf_init_syslog(char *facility)
{
#ifdef LOG_MAIL
    int code = -1;

    closelog();

    if (facility)
    {
        code = arc_name_to_code(log_facilities, facility);
    }
    if (code == -1)
    {
        code = LOG_MAIL;
    }

    openlog(progname, LOG_PID, code);
#else  /* LOG_MAIL */
    closelog();

    openlog(progname, LOG_PID);
#endif /* LOG_MAIL */
}

/*
**  ARCF_RESTART_CHECK -- initialize/check restart rate information
**
**  Parameters:
**  	n -- size of restart rate array to initialize/enforce
**  	t -- maximum time range for restarts (0 == init)
**
**  Return value:
**  	true -- OK to continue
**  	false -- error
*/

static bool
arcf_restart_check(int n, time_t t)
{
    static int     idx = 0;  /* last filled slot */
    static int     alen = 0; /* allocated length */
    static time_t *list = NULL;

    if (t == 0)
    {
        list = ARC_CALLOC(n, sizeof(time_t));

        if (list == NULL)
        {
            return false;
        }

        alen = n;
        return true;
    }

    if (alen == 0 || list == NULL)
    {
        return false;
    }

    int    which;
    time_t now;

    (void) time(&now);

    which = (idx - 1) % alen;
    if (which == -1)
    {
        which = alen - 1;
    }

    if (list[which] != 0 && list[which] + t > now)
    {
        return false;
    }

    list[which] = now;
    idx++;

    return true;
}

/*
**  ARCF_CHECKFSNODE -- check a filesystem node for safety
**
**  Parameters:
**  	path -- path of the node to check
**  	myuid -- executing user's effective uid
**  	myname -- executing user's login
**  	ino -- evaluated inode (returned)
**  	err -- error buffer
**  	errlen -- error buffer length
**
**  Return value:
**  	1 -- node is safe to use
**  	0 -- node is not safe to use
**  	-1 -- error (check errno)
**
**  Notes:
**  	"Safe" here means the target file cannot be read or written by anyone
**  	other than the executing user and the superuser.  The entire directory
**  	tree is checked from the root down after resolution of symlinks and
**  	references to "." and ".." looking for errant "write" bits on
**   	directories and the file itself.
**
**  	To prevent attacks through symbolic links, this function also returns
**  	the inode of the object it evaluated if that object was a file.  Thus,
**  	if the caller first opens the file but doesn't read from it, then the
**  	returned inode can be compared to the inode of the opened descriptor
**  	to ensure that what was opened was safe at the time open() was called.
**  	An inode of -1 is reported if some directory above the target was
**  	sufficiently locked down that the inode comparison isn't necessary.
**
**  	This still isn't bulletproof; there's a race between the time of the
**  	open() call and the result returned by this function.  I'm not sure if
**	that can be improved.
*/

static int
arcf_checkfsnode(const char *path,
                 uid_t       myuid,
                 char       *myname,
                 ino_t      *ino,
                 char       *err,
                 size_t      errlen)
{
    int            status;
    struct passwd *pw;
    struct group  *gr;
    struct stat    s;

    assert(path != NULL);
    assert(myname != NULL);
    assert(ino != NULL);

    status = stat(path, &s);
    if (status != 0)
    {
        return -1;
    }

    if (S_ISREG(s.st_mode))
    {

        /* owned by root or by me */
        if (s.st_uid != 0 && s.st_uid != myuid)
        {
            if (err != NULL)
            {
                snprintf(err, errlen,
                         "%s is not owned by the executing uid (%d)%s", path,
                         myuid, myuid != 0 ? " or the superuser" : "");
            }
            return 0;
        }

        /* if group read/write, the group is only me and/or root */
        if ((s.st_mode & (S_IRGRP | S_IWGRP)) != 0)
        {
            int c;

            /* check if anyone else has this file's gid */
            pthread_mutex_lock(&pwdb_lock);
            setpwent();
            for (pw = getpwent(); pw != NULL; pw = getpwent())
            {
                if (pw->pw_uid != myuid && pw->pw_uid != 0 &&
                    s.st_gid == pw->pw_gid)
                {
                    if (err != NULL)
                    {
                        snprintf(
                            err, errlen,
                            "%s is in group %u which has multiple users (e.g. \"%s\")",
                            path, s.st_gid, pw->pw_name);
                    }
                    pthread_mutex_unlock(&pwdb_lock);
                    return 0;
                }
            }
            endpwent();

            /* check if this group contains anyone else */
            gr = getgrgid(s.st_gid);
            if (gr == NULL)
            {
                pthread_mutex_unlock(&pwdb_lock);
                return -1;
            }

            for (c = 0; gr->gr_mem[c] != NULL; c++)
            {
                if (strcmp(gr->gr_mem[c], myname) != 0 &&
                    strcmp(gr->gr_mem[c], SUPERUSER) != 0)
                {
                    if (err != NULL)
                    {
                        snprintf(
                            err, errlen,
                            "%s is in group %u which has multiple users (e.g., \"%s\")",
                            path, s.st_gid, gr->gr_mem[c]);
                    }
                    pthread_mutex_unlock(&pwdb_lock);
                    return 0;
                }
            }

            pthread_mutex_unlock(&pwdb_lock);
        }

        /* not read/write by others */
        if ((s.st_mode & (S_IROTH | S_IWOTH)) != 0)
        {
            if (err != NULL)
            {
                snprintf(err, errlen,
                         "%s can be read or written by other users", path);
            }

            return 0;
        }

        *ino = s.st_ino;
    }
    else if (S_ISDIR(s.st_mode))
    {
        /* other write needs to be off */
        if ((s.st_mode & S_IWOTH) != 0)
        {
            if (err != NULL)
            {
                snprintf(err, errlen,
                         "%s can be read or written by other users", path);
            }
            return 0;
        }

        /* group write needs to be super-user or me only */
        if ((s.st_mode & S_IWGRP) != 0)
        {
            int c;

            /* check if anyone else has this file's gid */
            pthread_mutex_lock(&pwdb_lock);
            setpwent();
            for (pw = getpwent(); pw != NULL; pw = getpwent())
            {
                if (pw->pw_uid != myuid && pw->pw_uid != 0 &&
                    s.st_gid == pw->pw_gid)
                {
                    if (err != NULL)
                    {
                        snprintf(
                            err, errlen,
                            "%s is in group %u which has multiple users (e.g., \"%s\")",
                            myname, s.st_gid, pw->pw_name);
                    }

                    pthread_mutex_unlock(&pwdb_lock);
                    return 0;
                }
            }

            /* check if this group contains anyone else */
            gr = getgrgid(s.st_gid);
            if (gr == NULL)
            {
                pthread_mutex_unlock(&pwdb_lock);
                return -1;
            }

            for (c = 0; gr->gr_mem[c] != NULL; c++)
            {
                if (strcmp(gr->gr_mem[c], myname) != 0 &&
                    strcmp(gr->gr_mem[c], SUPERUSER) != 0)
                {
                    if (err != NULL)
                    {
                        snprintf(
                            err, errlen,
                            "%s is in group %u which has multiple users (e.g., \"%s\")",
                            myname, s.st_gid, gr->gr_mem[c]);
                    }

                    pthread_mutex_unlock(&pwdb_lock);
                    return 0;
                }
            }

            pthread_mutex_unlock(&pwdb_lock);
        }

        /* owner write needs to be super-user or me only */
        if ((s.st_mode & S_IWUSR) != 0 && (s.st_uid != 0 && s.st_uid != myuid))
        {
            if (err != NULL)
            {
                snprintf(
                    err, errlen,
                    "%s is writeable and owned by uid %u which is not the executing uid (%u)%s",
                    path, s.st_uid, myuid,
                    myuid != 0 ? " or the superuser" : "");
            }

            return 0;
        }

        /* if nobody else can execute below here, that's good enough */
        if ((s.st_mode & (S_IXGRP | S_IXOTH)) == 0)
        {
            *ino = (ino_t) -1;
            return 1;
        }
    }

    return 1;
}

/*
**  ARCF_SECUREFILE -- determine whether a file at a specific path is "safe"
**
**  Parameters:
**  	path -- path to evaluate
**  	ino -- inode of evaluated object
** 	myuid -- user to impersonate (-1 means "me")
**  	err -- error buffer
**  	errlen -- bytes available at "err"
**
**  Return value:
**  	As for arcf_checkfsnode().
**
**  Notes:
**  	If realpath() is available, this function checks the entire resolved
**  	filesystem tree from the root to the target file to ensure there are no
**  	permissions that would allow someone else on the system to either read
**  	or replace the file being evaluated.  (It's designed to check private
**  	key files.)  Without realpath(), only the target filename is checked.
*/

int
arcf_securefile(
    const char *path, ino_t *ino, uid_t myuid, char *err, size_t errlen)
{
    int            status;
    struct passwd *pw;
#ifdef HAVE_REALPATH
    char *p;
    char *q;
    char  real[MAXPATHLEN + 1];
    char  partial[MAXPATHLEN + 1];
    char  myname[BUFRSZ + 1];
#endif /* HAVE_REALPATH */

    assert(path != NULL);
    assert(ino != NULL);

    /* figure out who I am */
    pthread_mutex_lock(&pwdb_lock);

    if (myuid == (uid_t) -1)
    {
        pw = getpwuid(geteuid());
    }
    else
    {
        pw = getpwuid(myuid);
    }

    if (pw == NULL)
    {
        pthread_mutex_unlock(&pwdb_lock);
        return -1;
    }

    if (myuid == (uid_t) -1)
    {
        myuid = pw->pw_uid;
    }

    pthread_mutex_unlock(&pwdb_lock);

#ifdef HAVE_REALPATH
    strlcpy(myname, pw->pw_name, sizeof myname);

    p = realpath(path, real);
    if (p == NULL)
    {
        return -1;
    }

    /*
    **  Check each node in the tree to ensure that:
    **  1) The file itself is read-write only by the executing user and the
    **  	super-user;
    **  2) No directory above the file is writeable by anyone other than
    **  	the executing user and the super-user.
    */

    partial[0] = '/';
    partial[1] = '\0';

#ifdef HAVE_STRSEP
    q = real;
    while ((p = strsep(&q, "/")) != NULL)
#else  /* HAVE_STRSEP */
    q = NULL;
    for (p = strtok_r(real, "/", &q); p != NULL; p = strtok_r(NULL, "/", &q))
#endif /* HAVE_STRSEP */
    {
        strlcat(partial, p, sizeof partial);
        status = arcf_checkfsnode((const char *) partial, myuid, myname, ino,
                                  err, errlen);
        if (status != 1)
        {
            return status;
        }

        if (partial[1] != '\0')
        {
            strlcat(partial, "/", sizeof partial);
        }
    }

    return 1;
#else  /* HAVE_REALPATH */
    struct stat s;

    status = stat(path, &s);
    if (status != 0)
    {
        return -1;
    }

    /* we don't own it and neither does the super-user; bad */
    if (s.st_uid != myuid && s.st_uid != 0)
    {
        return 0;
    }

    /* world readable/writeable; bad */
    if ((s.st_node & (S_IROTH | S_IWOTH)) != 0)
    {
        return 0;
    }

    /* group read/write is bad if others are in that group */
    if ((s.st_mode & (S_IRGRP | S_IWGRP)) != 0)
    {
        int           c;
        struct group *gr;

        /* get the file's group entry */
        pthread_mutex_lock(&pwdb_lock);
        gr = getgrgid(s.st_gid);
        if (gr == NULL)
        {
            pthread_mutex_unlock(&pwdb_lock);
            return -1;
        }

        for (c = 0; gr->gr_mem[c] != NULL; c++)
        {
            if (strcmp(gr->gr_mem[c], pw->pw_name) != 0)
            {
                pthread_mutex_unlock(&pwdb_lock);
                return 0;
            }
        }

        setpwent();
        while (pw = getpwent(); pw != NULL; pw = getpwent())
        {
            if (pw->pw_uid != myuid && pw->pw_gid == s.st_gid)
            {
                pthread_mutex_unlock(&pwdb_lock);
                return 0;
            }
        }
        endpwent();

        pthread_mutex_unlock(&pwdb_lock);
    }

    /* guess we're okay... */
    *ino = s.st_ino;
    return 1;
#endif /* HAVE_REALPATH */
}

/*
**  ARCF_SIGHANDLER -- signal handler
**
**  Parameters:
**  	sig -- signal received
**
**  Return value:
**  	None.
*/

static void
arcf_sighandler(int sig)
{
    if (sig == SIGINT || sig == SIGTERM || sig == SIGHUP)
    {
        diesig = sig;
        die = true;
    }
    else if (sig == SIGUSR1 && !die)
    {
        if (conffile != NULL)
        {
            reload = true;
        }
    }
}

/*
**  ARCF_RELOADER -- reload signal thread
**
**  Parameters:
**  	vp -- void pointer required by thread API but not used
**
**  Return value:
**  	NULL.
*/

static void *
arcf_reloader(/* UNUSED */ void *vp)
{
    int      sig;
    sigset_t mask;

    (void) pthread_detach(pthread_self());

    sigemptyset(&mask);
    sigaddset(&mask, SIGUSR1);

    while (!die)
    {
        (void) sigwait(&mask, &sig);

        if (conffile != NULL)
        {
            reload = true;
        }
    }

    return NULL;
}

/*
**  ARCF_KILLCHILD -- kill child process
**
**  Parameters:
**  	pid -- process ID to signal
**  	sig -- signal to use
**  	dolog -- log it?
**
**  Return value:
**  	None.
*/

static void
arcf_killchild(pid_t pid, int sig, bool dolog)
{
    if (kill(pid, sig) == -1 && dolog)
    {
        syslog(LOG_ERR, "kill(%d, %d): %s", pid, sig, strerror(errno));
    }
}

/*
**  ARCF_CONFIG_NEW -- get a new configuration handle
**
**  Parameters:
**  	None.
**
**  Return value:
**  	A new configuration handle, or NULL on error.
*/

static struct arcf_config *
arcf_config_new(void)
{
    struct arcf_config *new;

    new = ARC_CALLOC(1, sizeof(struct arcf_config));
    if (new == NULL)
    {
        return NULL;
    }

    new->conf_maxhdrsz = DEFMAXHDRSZ;
    new->conf_safekeys = true;
    new->conf_authresip = true;

    new->conf_ret_disabled = SMFIS_ACCEPT;
    new->conf_ret_unable = SMFIS_TEMPFAIL;
    new->conf_ret_unwilling = SMFIS_REJECT;

    LIST_INIT(&new->conf_peers);
    LIST_INIT(&new->conf_internal);

    return new;
}

/*
**  ARCF_LIST_LOAD -- load a list
**
**  Parameters:
**  	f -- input file
**  	list -- list to update
**  	err -- error string (returned)
**
**  Return value:
**  	true iff the operation succeeded.
*/

bool
arcf_list_load(struct conflist *list, char *path, char **err)
{
    FILE               *f;
    char               *p;
    struct configvalue *v;
    char                buf[BUFRSZ + 1];

    f = fopen(path, "r");
    if (f == NULL)
    {
        *err = strerror(errno);
        return false;
    }

    memset(buf, '\0', sizeof buf);
    while (fgets(buf, sizeof buf - 1, f) != NULL)
    {
        for (p = buf; *p != '\0'; p++)
        {
            if (*p == '\n')
            {
                *p = '\0';
                break;
            }
        }

        v = ARC_MALLOC(sizeof(struct configvalue));
        if (v == NULL)
        {
            *err = strerror(errno);
            fclose(f);
            return false;
        }
        v->value = ARC_STRDUP(buf);
        if (v->value == NULL)
        {
            *err = strerror(errno);
            fclose(f);
            ARC_FREE(v);
            return false;
        }

        LIST_INSERT_HEAD(list, v, entries);
    }

    fclose(f);
    return true;
}

/*
**  ARCF_ADDLIST -- add an entry to a list
**
**  Parameters:
**  	list -- list to update
**  	str -- string to add
**  	err -- error string (returned)
**
**  Return value:
**  	true iff the operation succeeded.
*/

bool
arcf_addlist(struct conflist *list, char *str, char **err)
{
    struct configvalue *v;

    v = ARC_MALLOC(sizeof(struct configvalue));
    if (v == NULL)
    {
        *err = strerror(errno);
        return false;
    }
    v->value = ARC_STRDUP(str);

    LIST_INSERT_HEAD(list, v, entries);
    return true;
}

/*
**  ARCF_LIST_DESTROY -- destroy a list
**
**  Parameters:
**  	list -- LIST to be destroyed
**
**  Return value:
**  	None.
*/

void
arcf_list_destroy(struct conflist *list)
{
    while (!LIST_EMPTY(list))
    {
        struct configvalue *n;

        n = LIST_FIRST(list);
        LIST_REMOVE(n, entries);
        ARC_FREE(n->value);
        ARC_FREE(n);
    }
}

/*
**  ARCF_CONFIG_FREE -- destroy a configuration handle
**
**  Parameters:
**  	conf -- pointer to the configuration handle to be destroyed
**
**  Return value:
**  	None.
*/

static void
arcf_config_free(struct arcf_config *conf)
{
    if (conf == NULL)
    {
        return;
    }

    if (conf->conf_libopenarc != NULL)
    {
        arc_close(conf->conf_libopenarc);
    }

    if (conf->conf_authservid != NULL)
    {
        ARC_FREE(conf->conf_authservid);
    }

    if (!LIST_EMPTY(&conf->conf_peers))
    {
        arcf_list_destroy(&conf->conf_peers);
    }

    if (!LIST_EMPTY(&conf->conf_internal))
    {
        arcf_list_destroy(&conf->conf_internal);
    }

    if (conf->conf_data != NULL)
    {
        config_free(conf->conf_data);
    }

    if (conf->conf_signhdrs != NULL)
    {
        ARC_FREE(conf->conf_signhdrs);
    }

    if (conf->conf_oversignhdrs != NULL)
    {
        ARC_FREE(conf->conf_oversignhdrs);
    }

    if (!LIST_EMPTY(&conf->conf_sealheaderchecks))
    {
        arcf_list_destroy(&conf->conf_sealheaderchecks);
    }

    ARC_FREE(conf);
}

/*
**  ARCF_CONFIG_LOAD -- load a configuration handle based on file content
**
**  Parameters:
**  	data -- configuration data loaded from config file
**  	conf -- configuration structure to load
**  	err -- where to write errors
**  	errlen -- bytes available at "err"
**  	become -- pretend we're the named user (can be NULL)
**
**  Return value:
**  	0 -- success
**  	!0 -- error
**
**  Side effects:
**  	openlog() may be called by this function
*/

static int
arcf_config_load(struct config      *data,
                 struct arcf_config *conf,
                 char               *err,
                 size_t              errlen,
                 char               *become)
{
    char *str;
    char  basedir[MAXPATHLEN + 1];

    assert(conf != NULL);
    assert(err != NULL);

    memset(basedir, '\0', sizeof basedir);

    str = NULL;
    if (data != NULL)
    {
        (void) config_get(data, "AuthservID", &str, sizeof str);
    }
    if (str == NULL || strcmp(str, "HOSTNAME") == 0)
    {
        conf->conf_authservid = ARC_STRDUP(myhostname);
    }
    else
    {
        conf->conf_authservid = ARC_STRDUP(str);
    }

    if (data != NULL)
    {
        str = NULL;
        (void) config_get(data, "Mode", &str, sizeof str);
        if (str != NULL)
        {
            if (strchr(str, 's') != NULL)
            {
                conf->conf_mode |= ARC_MODE_SIGN;
            }
            if (strchr(str, 'v') != NULL)
            {
                conf->conf_mode |= ARC_MODE_VERIFY;
            }
        }

        str = NULL;
        (void) config_get(data, "BaseDirectory", &str, sizeof str);
        if (str != NULL)
        {
            strlcpy(basedir, str, sizeof basedir);
        }

        str = NULL;
        (void) config_get(data, "Canonicalization", &str, sizeof str);
        if (str == NULL)
        {
            conf->conf_canonhdr = ARC_CANON_RELAXED;
            conf->conf_canonbody = ARC_CANON_SIMPLE;
        }
        else
        {
            char *copy;
            char *mode;
            char *ctx;

            copy = ARC_STRDUP(str);
            mode = strtok_r(copy, "/", &ctx);
            conf->conf_canonhdr = arc_name_to_code(arcf_canonicalizations,
                                                   mode);
            mode = strtok_r(NULL, "/", &ctx);
            if (mode != NULL)
            {
                conf->conf_canonbody = arc_name_to_code(arcf_canonicalizations,
                                                        mode);
            }
            else
            {
                conf->conf_canonbody = ARC_CANON_SIMPLE;
            }

            ARC_FREE(copy);

            if (conf->conf_canonhdr == -1 || conf->conf_canonbody == -1)
            {
                strlcpy(err, "unknown canonicalization", errlen);
                return -1;
            }
        }

        str = NULL;
        (void) config_get(data, "SignatureAlgorithm", &str, sizeof str);
        if (str != NULL)
        {
            conf->conf_signalg = arc_name_to_code(arcf_signalgorithms, str);
        }
        else
        {
            conf->conf_signalg = ARC_SIGN_RSASHA256;
        }

        /* No explicit mode means we might need to sign, so these are
         * still required.
         */
        if ((!conf->conf_mode) || (conf->conf_mode & ARC_MODE_SIGN))
        {
            if (config_get(data, "Domain", &conf->conf_domain,
                           sizeof conf->conf_domain) < 1)
            {
                strlcpy(err, "parameter \"Domain\" required when signing",
                        errlen);
                return -1;
            }

            if (config_get(data, "Selector", &conf->conf_selector,
                           sizeof conf->conf_selector) < 1)
            {
                strlcpy(err, "parameter \"Selector\" required when signing",
                        errlen);
                return -1;
            }

            if (config_get(data, "KeyFile", &conf->conf_keyfile,
                           sizeof conf->conf_keyfile) < 1)
            {
                strlcpy(err, "parameter \"KeyFile\" required when signing",
                        errlen);
                return -1;
            }
        }

        config_get(data, "RequireSafeKeys", &conf->conf_safekeys,
                   sizeof conf->conf_safekeys);

        (void) config_get(data, "EnableCoredumps", &conf->conf_enablecores,
                          sizeof conf->conf_enablecores);

        (void) config_get(data, "FinalReceiver", &conf->conf_finalreceiver,
                          sizeof conf->conf_finalreceiver);

        (void) config_get(data, "PermitAuthenticationOverrides",
                          &conf->conf_overridecv, sizeof conf->conf_overridecv);

        config_get(data, "AuthResIP", &conf->conf_authresip,
                   sizeof conf->conf_authresip);

        (void) config_get(data, "TemporaryDirectory", &conf->conf_tmpdir,
                          sizeof conf->conf_tmpdir);

        (void) config_get(data, "KeepTemporaryFiles", &conf->conf_keeptmpfiles,
                          sizeof conf->conf_keeptmpfiles);

        (void) config_get(data, "MaximumHeaders", &conf->conf_maxhdrsz,
                          sizeof conf->conf_maxhdrsz);

        config_get(data, "MinimumKeySizeRSA", &conf->conf_minkeysz,
                   sizeof conf->conf_minkeysz);

        (void) config_get(data, "SignHeaders", &conf->conf_signhdrs_raw,
                          sizeof conf->conf_signhdrs_raw);

        (void) config_get(data, "OverSignHeaders", &conf->conf_oversignhdrs_raw,
                          sizeof conf->conf_oversignhdrs_raw);

        str = NULL;
        (void) config_get(data, "SealHeaderChecks", &str, sizeof str);
        if (str != NULL)
        {
            bool  status;
            char *dberr = NULL;

            status = arcf_list_load(&conf->conf_sealheaderchecks, str, &dberr);
            if (!status)
            {
                snprintf(err, errlen, "%s: arcf_list_load(): %s", str, dberr);
                return -1;
            }
        }

        str = NULL;
        (void) config_get(data, "FixedTimestamp", &str, sizeof str);
        if (str != NULL)
        {
            char *end;

            conf->conf_fixedtime = strtoul(str, &end, 10);
        }

        config_get(data, "SignatureTTL", &conf->conf_sigttl,
                   sizeof conf->conf_sigttl);

        str = NULL;
        config_get(data, "ResponseDisabled", &str, sizeof str);
        if (str)
        {
            int resp = arc_name_to_code(arcf_responses, str);
            if (resp == -1)
            {
                snprintf(err, errlen, "%s: invalid response value", str);
            }
            else
            {
                conf->conf_ret_disabled = arc_name_to_code(arcf_responses, str);
            }
        }

        str = NULL;
        config_get(data, "ResponseUnable", &str, sizeof str);
        if (str)
        {
            int resp = arc_name_to_code(arcf_responses, str);
            if (resp == -1)
            {
                snprintf(err, errlen, "%s: invalid response value", str);
            }
            else
            {
                conf->conf_ret_unable = arc_name_to_code(arcf_responses, str);
            }
        }

        str = NULL;
        config_get(data, "ResponseUnwilling", &str, sizeof str);
        if (str)
        {
            int resp = arc_name_to_code(arcf_responses, str);
            if (resp == -1)
            {
                snprintf(err, errlen, "%s: invalid response value", str);
            }
            else
            {
                conf->conf_ret_unwilling = arc_name_to_code(arcf_responses,
                                                            str);
            }
        }

        (void) config_get(data, "TestKeys", &conf->conf_testkeys,
                          sizeof conf->conf_testkeys);

        if (!conf->conf_dolog)
        {
            (void) config_get(data, "Syslog", &conf->conf_dolog,
                              sizeof conf->conf_dolog);
        }

        (void) config_get(data, "DisableCryptoInit",
                          &conf->conf_disablecryptoinit,
                          sizeof conf->conf_disablecryptoinit);

        if (!conf->conf_addswhdr)
        {
            (void) config_get(data, "SoftwareHeader", &conf->conf_addswhdr,
                              sizeof conf->conf_addswhdr);
        }

        if (become == NULL)
        {
            (void) config_get(data, "Userid", &become, sizeof become);
        }
    }

    if (basedir[0] != '\0')
    {
        if (chdir(basedir) != 0)
        {
            snprintf(err, errlen, "%s: chdir(): %s", basedir, strerror(errno));
            return -1;
        }
    }

    str = NULL;
    if (data != NULL)
    {
        (void) config_get(data, "PeerList", &str, sizeof str);
    }
    if (str != NULL)
    {
        bool  status;
        char *dberr = NULL;

        status = arcf_list_load(&conf->conf_peers, str, &dberr);
        if (!status)
        {
            snprintf(err, errlen, "%s: arcf_list_load(): %s", str, dberr);
            return -1;
        }
    }

    str = NULL;
    if (data != NULL)
    {
        (void) config_get(data, "InternalHosts", &str, sizeof str);
    }
    if (str != NULL)
    {
        bool  status;
        char *dberr = NULL;

        status = arcf_list_load(&conf->conf_internal, str, &dberr);
        if (!status)
        {
            snprintf(err, errlen, "%s: arcf_list_load(): %s", str, dberr);
            return -1;
        }
    }
    else if (!testmode)
    {
        bool  status;
        char *dberr = NULL;

        str = LOCALHOST;
        status = arcf_addlist(&conf->conf_internal, str, &dberr);
        if (!status)
        {
            snprintf(err, errlen, "%s: arcf_addlist(): %s", str, dberr);
            return -1;
        }

        str = LOCALHOST6;
        status = arcf_addlist(&conf->conf_internal, str, &dberr);
        if (!status)
        {
            snprintf(err, errlen, "%s: arcf_addlist(): %s", str, dberr);
            return -1;
        }
    }

    /* load the secret key, if one was specified */
    if (conf->conf_keyfile != NULL)
    {
        int            status;
        int            fd;
        ssize_t        rlen;
        ino_t          ino = -1;
        uid_t          asuser = (uid_t) -1;
        unsigned char *s33krit;
        struct stat    s;

        fd = open(conf->conf_keyfile, O_RDONLY, 0);
        if (fd < 0)
        {
            if (conf->conf_dolog)
            {
                int saveerrno;

                saveerrno = errno;

                syslog(LOG_ERR, "%s: open(): %s", conf->conf_keyfile,
                       strerror(errno));

                errno = saveerrno;
            }

            snprintf(err, errlen, "%s: open(): %s", conf->conf_keyfile,
                     strerror(errno));
            return -1;
        }

        status = fstat(fd, &s);
        if (status != 0)
        {
            if (conf->conf_dolog)
            {
                int saveerrno;

                saveerrno = errno;

                syslog(LOG_ERR, "%s: stat(): %s", conf->conf_keyfile,
                       strerror(errno));

                errno = saveerrno;
            }

            snprintf(err, errlen, "%s: stat(): %s", conf->conf_keyfile,
                     strerror(errno));
            close(fd);
            return -1;
        }
        else if (!S_ISREG(s.st_mode))
        {
            snprintf(err, errlen, "%s: open(): Not a regular file",
                     conf->conf_keyfile);
            close(fd);
            return -1;
        }

        if (become != NULL)
        {
            struct passwd *pw;
            char          *p;
            char           tmp[BUFRSZ + 1];

            strlcpy(tmp, become, sizeof tmp);

            p = strchr(tmp, ':');
            if (p != NULL)
            {
                *p = '\0';
            }

            pw = getpwnam(tmp);
            if (pw == NULL)
            {
                snprintf(err, errlen, "%s: no such user", tmp);
                close(fd);
                return -1;
            }

            asuser = pw->pw_uid;
        }

        if (!arcf_securefile(conf->conf_keyfile, &ino, asuser, err, errlen) ||
            (ino != (ino_t) -1 && ino != s.st_ino))
        {
            if (conf->conf_dolog)
            {
                int sev;

                sev = (conf->conf_safekeys ? LOG_ERR : LOG_WARNING);

                syslog(sev, "%s: key data is not secure: %s",
                       conf->conf_keyfile, err);
            }

            if (conf->conf_safekeys)
            {
                return -1;
            }
        }

        s33krit = ARC_MALLOC(s.st_size + 1);
        if (s33krit == NULL)
        {
            if (conf->conf_dolog)
            {
                int saveerrno;

                saveerrno = errno;

                syslog(LOG_ERR, "malloc(): %s", strerror(errno));

                errno = saveerrno;
            }

            snprintf(err, errlen, "malloc(): %s", strerror(errno));
            return -1;
        }

        conf->conf_keylen = s.st_size + 1;

        rlen = read(fd, s33krit, s.st_size + 1);
        if (rlen == (ssize_t) -1)
        {
            if (conf->conf_dolog)
            {
                int saveerrno;

                saveerrno = errno;

                syslog(LOG_ERR, "%s: read(): %s", conf->conf_keyfile,
                       strerror(errno));

                errno = saveerrno;
            }

            snprintf(err, errlen, "%s: read(): %s", conf->conf_keyfile,
                     strerror(errno));
            close(fd);
            ARC_FREE(s33krit);
            return -1;
        }
        else if (rlen != s.st_size)
        {
            if (conf->conf_dolog)
            {
                syslog(LOG_ERR, "%s: read() wrong size (%lu)",
                       conf->conf_keyfile, (unsigned long) rlen);
            }

            snprintf(err, errlen, "%s: read() wrong size (%lu)",
                     conf->conf_keyfile, (unsigned long) rlen);
            close(fd);
            ARC_FREE(s33krit);
            return -1;
        }

        close(fd);
        s33krit[s.st_size] = '\0';
        conf->conf_keydata = s33krit;
    }

    /* activate logging if requested */
    if (conf->conf_dolog)
    {
        char *log_facility = NULL;

        if (data != NULL)
        {
            (void) config_get(data, "SyslogFacility", &log_facility,
                              sizeof log_facility);
        }

        arcf_init_syslog(log_facility);
    }

    return 0;
}

/*
**  ARCF_CONFIG_SETLIB -- set library options based on configuration file
**
**  Parameters:
**  	conf -- ARC filter configuration data
**  	err -- error string (returned; may be NULL)
**
**  Return value:
**  	true on success, false otherwise.
*/

static bool
arcf_config_setlib(struct arcf_config *conf, char **err)
{
    ARC_STAT     status;
    unsigned int opts;
    ARC_LIB     *lib;
    assert(conf != NULL);

    lib = conf->conf_libopenarc;
    if (lib == NULL)
    {
        lib = arc_init();
        if (lib == NULL)
        {
            if (err != NULL)
            {
                *err = "failed to initialize ARC library";
            }
            return false;
        }

        conf->conf_libopenarc = lib;
    }

    status = ARC_STAT_OK;

    if (conf->conf_tmpdir != NULL)
    {
        status = arc_options(conf->conf_libopenarc, ARC_OP_SETOPT,
                             ARC_OPTS_TMPDIR, (void *) conf->conf_tmpdir,
                             sizeof conf->conf_tmpdir);
    }

    if (status == ARC_STAT_OK)
    {
        opts = ARC_LIBFLAGS_NONE;

        if (conf->conf_keeptmpfiles)
        {
            opts |= ARC_LIBFLAGS_KEEPFILES;
        }

        status = arc_options(conf->conf_libopenarc, ARC_OP_SETOPT,
                             ARC_OPTS_FLAGS, &opts, sizeof opts);
    }

    if (conf->conf_fixedtime != 0)
    {
        arc_options(conf->conf_libopenarc, ARC_OP_SETOPT, ARC_OPTS_FIXEDTIME,
                    &conf->conf_fixedtime, sizeof conf->conf_fixedtime);
    }

    if (status != ARC_STAT_OK)
    {
        if (err != NULL)
        {
            *err = "failed to set ARC library options";
        }
        return false;
    }

    if (conf->conf_sigttl != 0)
    {
        arc_options(conf->conf_libopenarc, ARC_OP_SETOPT,
                    ARC_OPTS_SIGNATURE_TTL, &conf->conf_sigttl,
                    sizeof conf->conf_sigttl);
    }

    if (status != ARC_STAT_OK)
    {
        if (err != NULL)
        {
            *err = "failed to set ARC library options";
        }
        return false;
    }

    if (conf->conf_minkeysz > 0)
    {
        status = arc_options(conf->conf_libopenarc, ARC_OP_SETOPT,
                             ARC_OPTS_MINKEYSIZE, &conf->conf_minkeysz,
                             sizeof conf->conf_minkeysz);
    }

    if (status != ARC_STAT_OK)
    {
        if (err != NULL)
        {
            *err = "failed to set ARC library options";
        }
        return false;
    }

    if (conf->conf_testkeys)
    {
        status = arc_options(conf->conf_libopenarc, ARC_OP_SETOPT,
                             ARC_OPTS_TESTKEYS, conf->conf_testkeys,
                             sizeof conf->conf_testkeys);

        if (status != ARC_STAT_OK)
        {
            if (err != NULL)
            {
                *err = "failed to set ARC library options";
            }
            return false;
        }
    }

    if (conf->conf_signhdrs_raw != NULL)
    {
        conf->conf_signhdrs = arcf_mkarray(conf->conf_signhdrs_raw);
        status = arc_options(conf->conf_libopenarc, ARC_OP_SETOPT,
                             ARC_OPTS_SIGNHDRS, conf->conf_signhdrs,
                             sizeof conf->conf_signhdrs);

        if (status != ARC_STAT_OK)
        {
            if (err != NULL)
            {
                *err = "failed to set ARC library options";
            }
            return false;
        }
    }

    if (conf->conf_oversignhdrs_raw != NULL)
    {
        conf->conf_oversignhdrs = arcf_mkarray(conf->conf_oversignhdrs_raw);
        status = arc_options(conf->conf_libopenarc, ARC_OP_SETOPT,
                             ARC_OPTS_OVERSIGNHDRS, conf->conf_oversignhdrs,
                             sizeof conf->conf_oversignhdrs);

        if (status != ARC_STAT_OK)
        {
            if (err != NULL)
            {
                *err = "failed to set ARC library options";
            }
            return false;
        }
    }

    return true;
}

/*
**  ARCF_CONFIG_RELOAD -- reload configuration if requested
**
**  Parameters:
**   	None.
**
**  Return value:
**  	None.
**
**  Side effects:
**  	If a reload was requested and is successful, "curconf" now points
**  	to a new configuration handle.
*/

static void
arcf_config_reload(void)
{
    struct arcf_config *new;
    char errbuf[BUFRSZ + 1];

    pthread_mutex_lock(&conf_lock);

    if (!reload)
    {
        pthread_mutex_unlock(&conf_lock);
        return;
    }

    if (conffile == NULL)
    {
        if (curconf->conf_dolog)
        {
            syslog(LOG_ERR, "ignoring reload signal");
        }

        reload = false;

        pthread_mutex_unlock(&conf_lock);
        return;
    }

    new = arcf_config_new();
    if (new == NULL)
    {
        if (curconf->conf_dolog)
        {
            syslog(LOG_ERR, "malloc(): %s", strerror(errno));
        }
    }
    else
    {
        bool           err = false;
        unsigned int   line;
        struct config *cfg;
        char          *missing;
        char          *errstr = NULL;
        char          *deprecated = NULL;
        char           path[MAXPATHLEN + 1];

        strlcpy(path, conffile, sizeof path);

        cfg = config_load(conffile, arcf_config, &line, path, sizeof path,
                          &deprecated);

        if (cfg == NULL)
        {
            if (curconf->conf_dolog)
            {
                syslog(LOG_ERR, "%s: configuration error at line %u: %s", path,
                       line, config_error());
            }
            err = true;
        }

        if (deprecated != NULL)
        {
            if (curconf->conf_dolog)
            {
                syslog(
                    LOG_WARNING,
                    "%s: settings found for deprecated value(s): %s; aborting",
                    path, deprecated);
            }
            err = true;
        }

        if (!err)
        {
            missing = config_check(cfg, arcf_config);
            if (missing != NULL)
            {
                if (curconf->conf_dolog)
                {
                    syslog(LOG_ERR, "%s: required parameter \"%s\" missing",
                           conffile, missing);
                }
                err = true;
            }
        }

        if (!err &&
            arcf_config_load(cfg, new, errbuf, sizeof errbuf, NULL) != 0)
        {
            if (curconf->conf_dolog)
            {
                syslog(LOG_ERR, "%s: %s", conffile, errbuf);
            }
            err = true;
        }

        if (!err && !arcf_config_setlib(new, &errstr))
        {
            if (curconf->conf_dolog)
            {
                syslog(LOG_WARNING,
                       "can't configure ARC library: %s; continuing", errstr);
            }
            err = true;
        }

        if (err)
        {
            config_free(cfg);
            arcf_config_free(new);
        }
        else
        {
            if (curconf->conf_refcnt == 0)
            {
                arcf_config_free(curconf);
            }

            dolog = new->conf_dolog;
            curconf = new;
            new->conf_data = cfg;

            if (new->conf_dolog)
            {
                syslog(LOG_INFO, "configuration reloaded from %s", conffile);
            }
        }
    }

    reload = false;

    pthread_mutex_unlock(&conf_lock);

    return;
}

/*
**  ARCF_STDIO -- set up the base descriptors to go nowhere
**
**  Parameters:
**  	None.
**
**  Return value:
**  	None.
*/

static void
arcf_stdio(void)
{
    int devnull;

    /* this only fails silently, but that's OK */
    devnull = open(_PATH_DEVNULL, O_RDWR, 0);
    if (devnull != -1)
    {
        (void) dup2(devnull, 0);
        (void) dup2(devnull, 1);
        (void) dup2(devnull, 2);
        if (devnull > 2)
        {
            (void) close(devnull);
        }
    }

    (void) setsid();
}

/*
**  ARCF_INITCONTEXT -- initialize filter context
**
**  Parameters:
**  	conf -- pointer to the configuration for this connection
**
**  Return value:
**  	A pointer to an allocated and initialized filter context, or NULL
**  	on failure.
**
**  Side effects:
**  	Crop circles near Birmingham.
*/

static msgctx
arcf_initcontext(struct arcf_config *conf)
{
    msgctx ctx;

    assert(conf != NULL);

    ctx = ARC_CALLOC(1, sizeof(struct msgctx));
    if (ctx == NULL)
    {
        return NULL;
    }

    return ctx;
}

/*
**  ARCF_CLEANUP -- release local resources related to a message
**
**  Parameters:
**  	ctx -- milter context
**
**  Return value:
**  	None.
*/

static void
arcf_cleanup(SMFICTX *ctx)
{
    msgctx  afc;
    connctx cc;

    assert(ctx != NULL);

    cc = (connctx) arcf_getpriv(ctx);

    if (cc == NULL)
    {
        return;
    }

    afc = cc->cctx_msg;

    /* release memory, reset state */
    if (afc != NULL)
    {
        if (afc->mctx_hqhead != NULL)
        {
            Header hdr;
            Header prev;

            hdr = afc->mctx_hqhead;
            while (hdr != NULL)
            {
                ARC_FREE(hdr->hdr_hdr);
                ARC_FREE(hdr->hdr_val);
                prev = hdr;
                hdr = hdr->hdr_next;
                ARC_FREE(prev);
            }
        }

        if (afc->mctx_arcmsg != NULL)
        {
            arc_free(afc->mctx_arcmsg);
        }

        if (afc->mctx_tmpstr != NULL)
        {
            arc_dstring_free(afc->mctx_tmpstr);
        }

        ARC_FREE(afc);
        cc->cctx_msg = NULL;
    }
}

/*
**  ARCF_GETARC -- retrieve ARC handle in use
**
**  Parameters:
**  	vp -- opaque pointer (from test.c)
**
**  Return value:
**  	ARC handle in use, or NULL.
*/

ARC_MESSAGE *
arcf_getarc(void *vp)
{
    struct connctx *cc;

    assert(vp != NULL);

    cc = vp;
    if (cc->cctx_msg != NULL)
    {
        return cc->cctx_msg->mctx_arcmsg;
    }
    else
    {
        return NULL;
    }
}

/*
**  ARCF_FINDHEADER -- find a header
**
**  Parameters:
**  	afc -- filter context
**  	hname -- name of the header of interest
**  	instance -- which instance is wanted (0 = first)
**
**  Return value:
**  	Header handle, or NULL if not found.
**
**  Notes:
**  	Negative values of "instance" search backwards from the end.
*/

static Header
arcf_findheader(msgctx afc, char *hname, int instance)
{
    Header hdr;

    assert(afc != NULL);
    assert(hname != NULL);

    if (instance < 0)
    {
        hdr = afc->mctx_hqtail;
    }
    else
    {
        hdr = afc->mctx_hqhead;
    }

    while (hdr != NULL)
    {
        if (strcasecmp(hdr->hdr_hdr, hname) == 0)
        {
            if (instance == 0 || instance == -1)
            {
                return hdr;
            }
            else if (instance > 0)
            {
                instance--;
            }
            else
            {
                instance++;
            }
        }

        if (instance < 0)
        {
            hdr = hdr->hdr_prev;
        }
        else
        {
            hdr = hdr->hdr_next;
        }
    }

    return NULL;
}

/*
**  ARCF_CHECKHOST -- check the peerlist for a host and its wildcards
**
**  Parameters:
**  	list -- list to check
**  	host -- hostname to find
**
**  Return value:
**  	true if there's a match, false otherwise.
*/

bool
arcf_checkhost(struct conflist *list, char *host)
{
    char               *p;
    struct configvalue *node;
    char                buf[BUFRSZ + 1];

    assert(host != NULL);

    /* short circuits */
    if (list == NULL || host[0] == '\0')
    {
        return false;
    }

    /* iterate over the possibilities */
    for (p = host; p != NULL; p = strchr(p + 1, '.'))
    {
        /* try the negative case */
        snprintf(buf, sizeof buf, "!%s", p);
        LIST_FOREACH(node, list, entries)
        if (strcmp(node->value, buf) == 0)
        {
            return false;
        }

        /* ...and now the positive case */
        LIST_FOREACH(node, list, entries)
        if (strcmp(node->value, &buf[1]) == 0)
        {
            return true;
        }
    }

    return false;
}

/*
**  ARCF_CHECKIP -- check a peerlist table for an IP address or its matching
**                 wildcards
**
**  Parameters:
**  	list -- list to check
**  	ip -- IP address to find
**
**  Return value:
**  	true if there's a match, false otherwise.
*/

bool
arcf_checkip(struct conflist *list, struct sockaddr *ip)
{
    char ipbuf[ARC_MAXHOSTNAMELEN + 1];

    assert(ip != NULL);

    /* short circuit */
    if (list == NULL)
    {
        return false;
    }

#if AF_INET6
    if (ip->sa_family == AF_INET6)
    {
        int                 bits;
        size_t              dst_len;
        size_t              iplen;
        char               *dst;
        struct configvalue *node;
        struct sockaddr_in6 sin6;
        struct in6_addr     addr;

        memcpy(&sin6, ip, sizeof sin6);

        memcpy(&addr, &sin6.sin6_addr, sizeof addr);

        memset(ipbuf, '\0', sizeof ipbuf);
        ipbuf[0] = '!';

        dst = &ipbuf[1];
        dst_len = sizeof ipbuf - 1;

        inet_ntop(AF_INET6, &addr, dst, dst_len);
        arc_lowercase(dst);
        iplen = strlen(dst);

        LIST_FOREACH(node, list, entries)
        if (strcmp(ipbuf, node->value) == 0)
        {
            return false;
        }
        LIST_FOREACH(node, list, entries)
        if (strcmp(&ipbuf[1], node->value) == 0)
        {
            return true;
        }

        /* try it with square brackets */
        memmove(&ipbuf[2], &ipbuf[1], iplen + 1);
        ipbuf[1] = '[';
        ipbuf[iplen + 2] = ']';

        LIST_FOREACH(node, list, entries)
        if (strcmp(ipbuf, node->value) == 0)
        {
            return false;
        }
        LIST_FOREACH(node, list, entries)
        if (strcmp(&ipbuf[1], node->value) == 0)
        {
            return true;
        }

        /* iterate over possible bitwise expressions */
        for (bits = 0; bits <= 128; bits++)
        {
            size_t sz;

            /* try this one */
            memset(ipbuf, '\0', sizeof ipbuf);
            ipbuf[0] = '!';

            dst = &ipbuf[1];
            dst_len = sizeof ipbuf - 1;

            inet_ntop(AF_INET6, &addr, dst, dst_len);
            arc_lowercase(dst);
            iplen = strlen(dst);

            sz = strlcat(ipbuf, "/", sizeof ipbuf);
            if (sz >= sizeof ipbuf)
            {
                return false;
            }

            dst = &ipbuf[sz];
            dst_len = sizeof ipbuf - sz;

            sz = snprintf(dst, dst_len, "%d", 128 - bits);
            if (sz >= sizeof ipbuf)
            {
                return false;
            }

            LIST_FOREACH(node, list, entries)
            if (strcmp(ipbuf, node->value) == 0)
            {
                return false;
            }
            LIST_FOREACH(node, list, entries)
            if (strcmp(&ipbuf[1], node->value) == 0)
            {
                return true;
            }

            /* try it with square brackets */
            memmove(&ipbuf[2], &ipbuf[1], iplen + 1);
            ipbuf[1] = '[';
            ipbuf[iplen + 2] = ']';
            ipbuf[iplen + 3] = '\0';

            sz = strlcat(ipbuf, "/", sizeof ipbuf);
            if (sz >= sizeof ipbuf)
            {
                return false;
            }

            dst = &ipbuf[sz];
            dst_len = sizeof ipbuf - sz;

            sz = snprintf(dst, dst_len, "%d", 128 - bits);
            if (sz >= sizeof ipbuf)
            {
                return false;
            }

            LIST_FOREACH(node, list, entries)
            if (strcmp(ipbuf, node->value) == 0)
            {
                return false;
            }
            LIST_FOREACH(node, list, entries)
            if (strcmp(&ipbuf[1], node->value) == 0)
            {
                return true;
            }

            /* flip off a bit */
            if (bits != 128)
            {
                int idx;
                int bit;

                idx = 15 - (bits / 8);
                bit = bits % 8;
                addr.s6_addr[idx] &= ~(1 << bit);
            }
        }
    }
#endif /* AF_INET6 */

    if (ip->sa_family == AF_INET)
    {
        int                 c;
        int                 bits;
        size_t              iplen;
        struct configvalue *node;
        struct in_addr      addr;
        struct in_addr      mask;
        struct sockaddr_in  sin;

        memcpy(&sin, ip, sizeof sin);
        memcpy(&addr.s_addr, &sin.sin_addr, sizeof addr.s_addr);

        ipbuf[0] = '!';
        (void) arcf_inet_ntoa(addr, &ipbuf[1], sizeof ipbuf - 1);
        LIST_FOREACH(node, list, entries)
        if (strcmp(ipbuf, node->value) == 0)
        {
            return false;
        }
        LIST_FOREACH(node, list, entries)
        if (strcmp(&ipbuf[1], node->value) == 0)
        {
            return true;
        }

        /* try it with square brackets */
        memmove(&ipbuf[2], &ipbuf[1], strlen(&ipbuf[1]) + 1);
        ipbuf[1] = '[';
        ipbuf[strlen(ipbuf)] = ']';

        LIST_FOREACH(node, list, entries)
        if (strcmp(ipbuf, node->value) == 0)
        {
            return false;
        }
        LIST_FOREACH(node, list, entries)
        if (strcmp(&ipbuf[1], node->value) == 0)
        {
            return true;
        }

        /* iterate over possible bitwise expressions */
        for (bits = 32; bits >= 0; bits--)
        {
            if (bits == 32)
            {
                mask.s_addr = 0xffffffff;
            }
            else
            {
                mask.s_addr = 0;
                for (c = 0; c < bits; c++)
                {
                    mask.s_addr |= htonl(1 << (31 - c));
                }
            }

            addr.s_addr = addr.s_addr & mask.s_addr;

            memset(ipbuf, '\0', sizeof ipbuf);
            ipbuf[0] = '!';
            (void) arcf_inet_ntoa(addr, &ipbuf[1], sizeof ipbuf - 1);
            iplen = strlen(&ipbuf[1]);
            c = strlen(ipbuf);
            ipbuf[c] = '/';
            c++;

            snprintf(&ipbuf[c], sizeof ipbuf - c, "%d", bits);

            LIST_FOREACH(node, list, entries)
            if (strcmp(ipbuf, node->value) == 0)
            {
                return false;
            }
            LIST_FOREACH(node, list, entries)
            if (strcmp(&ipbuf[1], node->value) == 0)
            {
                return true;
            }

            /* try it with square brackets */
            memmove(&ipbuf[2], &ipbuf[1], strlen(&ipbuf[1]) + 1);
            ipbuf[1] = '[';
            ipbuf[iplen + 2] = ']';
            ipbuf[iplen + 3] = '/';
            snprintf(&ipbuf[iplen + 4], sizeof ipbuf - iplen - 4, "%d", bits);

            LIST_FOREACH(node, list, entries)
            if (strcmp(ipbuf, node->value) == 0)
            {
                return false;
            }
            LIST_FOREACH(node, list, entries)
            if (strcmp(&ipbuf[1], node->value) == 0)
            {
                return true;
            }
        }
    }

    return false;
}

#if SMFI_VERSION >= 0x01000000
/*
**  MLFI_NEGOTIATE -- handler called on new SMTP connection to negotiate
**                    MTA options
**
**  Parameters:
**  	ctx -- milter context
**	f0  -- actions offered by the MTA
**	f1  -- protocol steps offered by the MTA
**	f2  -- reserved for future extensions
**	f3  -- reserved for future extensions
**	pf0 -- actions requested by the milter
**	pf1 -- protocol steps requested by the milter
**	pf2 -- reserved for future extensions
**	pf3 -- reserved for future extensions
**
**  Return value:
**  	An SMFIS_* constant.
*/

sfsistat
mlfi_negotiate(SMFICTX       *ctx,
               unsigned long  f0,
               unsigned long  f1,
               unsigned long  f2,
               unsigned long  f3,
               unsigned long *pf0,
               unsigned long *pf1,
               unsigned long *pf2,
               unsigned long *pf3)
{
    unsigned long reqactions = SMFIF_ADDHDRS;
    unsigned long wantactions = 0;
    unsigned long protosteps = (SMFIP_NOHELO | SMFIP_NORCPT | SMFIP_NOUNKNOWN |
                                SMFIP_NODATA | SMFIP_SKIP);
    connctx       cc;
    struct arcf_config *conf;

    arcf_config_reload();

    /* initialize connection context */
    cc = ARC_CALLOC(1, sizeof(struct connctx));
    if (cc == NULL)
    {
        if (curconf->conf_dolog)
        {
            syslog(LOG_ERR, "mlfi_negotiate(): malloc(): %s", strerror(errno));
        }

        return SMFIS_TEMPFAIL;
    }

    pthread_mutex_lock(&conf_lock);

    cc->cctx_config = curconf;
    curconf->conf_refcnt++;
    conf = curconf;

    pthread_mutex_unlock(&conf_lock);

    /* verify the actions we need are available */
    if ((f0 & reqactions) != reqactions)
    {
        if (conf->conf_dolog)
        {
            syslog(
                LOG_ERR,
                "mlfi_negotiate(): required milter action(s) not available (got 0x%lx, need 0x%lx)",
                f0, reqactions);
        }

        pthread_mutex_lock(&conf_lock);
        conf->conf_refcnt--;
        pthread_mutex_unlock(&conf_lock);

        ARC_FREE(cc);

        return SMFIS_REJECT;
    }

    /* also try to get some nice features */
    wantactions = (wantactions & f0);

    /* set the actions we want */
    *pf0 = (reqactions | wantactions);

    /* disable as many protocol steps we don't need as are available */
    *pf1 = (protosteps & f1);

#ifdef SMFIP_HDR_LEADSPC
    /* request preservation of leading spaces if possible */
    if ((f1 & SMFIP_HDR_LEADSPC) != 0)
    {
        if (cc != NULL)
        {
            cc->cctx_noleadspc = true;
            *pf1 |= SMFIP_HDR_LEADSPC;
        }
    }
#endif /* SMFIP_HDR_LEADSPC */

    *pf2 = 0;
    *pf3 = 0;

    /* set "milterv2" flag if SMFIP_SKIP was available */
    if ((f1 & SMFIP_SKIP) != 0)
    {
        cc->cctx_milterv2 = true;
    }

    (void) arcf_setpriv(ctx, cc);

    return SMFIS_CONTINUE;
}
#endif /* SMFI_VERSION >= 0x01000000 */

/*
**  MLFI_CONNECT -- connection handler
**
**  Parameters:
**  	ctx -- milter context
**  	host -- hostname
**  	ip -- address, in in_addr form
**
**  Return value:
**  	An SMFIS_* constant.
*/

sfsistat
mlfi_connect(SMFICTX *ctx, char *host, _SOCK_ADDR *ip)
{
    connctx cc;

    arcf_config_reload();

    /* copy hostname and IP information to a connection context */
    cc = arcf_getpriv(ctx);
    if (cc == NULL)
    {
        cc = ARC_CALLOC(1, sizeof(struct connctx));
        if (cc == NULL)
        {
            pthread_mutex_lock(&conf_lock);

            if (curconf->conf_dolog)
            {
                syslog(LOG_ERR, "%s malloc(): %s", host, strerror(errno));
            }

            int retval = curconf->conf_ret_unable;
            pthread_mutex_unlock(&conf_lock);

            return retval;
        }

        pthread_mutex_lock(&conf_lock);

        cc->cctx_config = curconf;
        curconf->conf_refcnt++;

        pthread_mutex_unlock(&conf_lock);

        arcf_setpriv(ctx, cc);
    }

    arc_lowercase(host);

    if (host != NULL)
    {
        strlcpy(cc->cctx_host, host, sizeof cc->cctx_host);
    }

    if (ip == NULL)
    {
        struct sockaddr_in sin;

        memset(&sin, '\0', sizeof sin);
        sin.sin_family = AF_INET;
        sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

        memcpy(&cc->cctx_ip, &sin, sizeof sin);
    }
    else if (ip->sa_family == AF_INET)
    {
        memcpy(&cc->cctx_ip, ip, sizeof(struct sockaddr_in));
    }
#ifdef AF_INET6
    else if (ip->sa_family == AF_INET6)
    {
        memcpy(&cc->cctx_ip, ip, sizeof(struct sockaddr_in6));
    }
#endif /* AF_INET6 */

    /* if the client is on the peer list, then ignore it */
    if (((host != NULL && host[0] != '[') &&
         arcf_checkhost(&curconf->conf_peers, host)) ||
        (ip != NULL && arcf_checkip(&curconf->conf_peers, ip)))
    {
        if (curconf->conf_dolog)
        {
            syslog(
                LOG_INFO, "peer connection from %s, returning %s", host,
                arc_code_to_name(arcf_responses, curconf->conf_ret_disabled));
        }
        return curconf->conf_ret_disabled;
    }

    /* infer operating mode if not explicitly set */
    if (curconf->conf_mode != 0)
    {
        cc->cctx_mode = curconf->conf_mode;
    }
    else
    {
        char *modestr;

        if (((host != NULL && host[0] != '[') &&
             arcf_checkhost(&curconf->conf_internal, host)) ||
            (ip != NULL && arcf_checkip(&curconf->conf_internal, ip)))
        {
            /* internal host; assume outbound, so sign */
            cc->cctx_mode = ARC_MODE_SIGN;
            modestr = "sign";
        }
        else
        {
            /* non-internal host; assume inbound, so verify */
            cc->cctx_mode = ARC_MODE_VERIFY;
            modestr = "verify";
        }

        if (curconf->conf_dolog)
        {
            syslog(LOG_INFO, "assuming %s mode for host %s", modestr,
                   cc->cctx_host);
        }
    }

    cc->cctx_msg = NULL;

    return SMFIS_CONTINUE;
}

#if SMFI_VERSION == 2
/*
**  MLFI_HELO -- handler for HELO/EHLO command (start of message)
**
**  Parameters:
**  	ctx -- milter context
**  	helo -- HELO/EHLO parameter
**
**  Return value:
**  	An SMFIS_* constant.
*/

sfsistat
mlfi_helo(SMFICTX *ctx, char *helo)
{
    assert(ctx != NULL);
    assert(helo != NULL);

    return SMFIS_CONTINUE;
}
#endif /* SMFI_VERSION == 2 */

/*
**  MLFI_ENVFROM -- handler for MAIL FROM command (start of message)
**
**  Parameters:
**  	ctx -- milter context
**  	envfrom -- envelope from arguments
**
**  Return value:
**  	An SMFIS_* constant.
*/

sfsistat
mlfi_envfrom(SMFICTX *ctx, char **envfrom)
{
    connctx             cc;
    msgctx              afc;
    struct arcf_config *conf;

    assert(ctx != NULL);
    assert(envfrom != NULL);

    cc = (connctx) arcf_getpriv(ctx);
    assert(cc != NULL);
    conf = cc->cctx_config;

    /*
    **  Initialize a filter context.
    */

    arcf_cleanup(ctx);
    afc = arcf_initcontext(conf);
    if (afc == NULL)
    {
        if (conf->conf_dolog)
        {
            syslog(LOG_INFO, "message requeueing (internal error)");
        }

        arcf_cleanup(ctx);
        return SMFIS_TEMPFAIL;
    }

    /*
    **  Save it in this thread's private space.
    */

    cc->cctx_msg = afc;

    /*
    **  Continue processing.
    */

    return SMFIS_CONTINUE;
}

/*
**  MLFI_HEADER -- handler for mail headers; stores the header in a vector
**                 of headers for later perusal, removing RFC822 comment
**                 substrings
**
**  Parameters:
**  	ctx -- milter context
**  	headerf -- header
**  	headerv -- value
**
**  Return value:
**  	An SMFIS_* constant.
*/

sfsistat
mlfi_header(SMFICTX *ctx, char *headerf, char *headerv)
{
    msgctx              afc;
    connctx             cc;
    Header              newhdr;
    struct arcf_config *conf;

    assert(ctx != NULL);
    assert(headerf != NULL);
    assert(headerv != NULL);

    cc = (connctx) arcf_getpriv(ctx);
    assert(cc != NULL);
    afc = cc->cctx_msg;
    assert(afc != NULL);
    conf = cc->cctx_config;

    /* check for too much header data */
    if (conf->conf_maxhdrsz > 0 &&
        afc->mctx_hdrbytes + strlen(headerf) + strlen(headerv) + 2 >
            conf->conf_maxhdrsz)
    {
        if (conf->conf_dolog)
        {
            syslog(LOG_NOTICE, "too much header data, returning %s",
                   arc_code_to_name(arcf_responses, conf->conf_ret_unwilling));
        }

        return conf->conf_ret_unwilling;
    }

    /*
    **  Completely ignore a field name containing a semicolon; this is
    **  strangely legal by RFC5322, but completely incompatible with ARC.
    */

    if (strchr(headerf, ';') != NULL)
    {
        if (conf->conf_dolog)
        {
            syslog(LOG_NOTICE, "ignoring header field '%s'", headerf);
        }

        return SMFIS_CONTINUE;
    }

    newhdr = ARC_CALLOC(1, sizeof(struct Header));
    if (newhdr == NULL)
    {
        if (conf->conf_dolog)
        {
            syslog(LOG_ERR, "malloc(): %s", strerror(errno));
        }

        arcf_cleanup(ctx);
        return conf->conf_ret_unable;
    }

    newhdr->hdr_hdr = ARC_STRDUP(headerf);

    if (afc->mctx_tmpstr == NULL)
    {
        afc->mctx_tmpstr = arc_dstring_new(BUFRSZ, 0, NULL, NULL);
        if (afc->mctx_tmpstr == NULL)
        {
            if (conf->conf_dolog)
            {
                syslog(LOG_ERR, "arc_dstring_new() failed");
            }

            ARC_FREE(newhdr->hdr_hdr);
            ARC_FREE(newhdr);

            arcf_cleanup(ctx);

            return conf->conf_ret_unable;
        }
    }
    else
    {
        arc_dstring_blank(afc->mctx_tmpstr);
    }

    if (!cc->cctx_noleadspc)
    {
        /*
        **  The sendmail MTA does some minor header rewriting on
        **  outgoing mail.  This makes things slightly prettier for
        **  the MUA, but these changes are made after this filter has
        **  already generated and added a signature.  As a result,
        **  verification of the signature will fail because what got
        **  signed isn't the same as what actually goes out.  This
        **  chunk of code attempts to compensate by arranging to
        **  feed to the canonicalization algorithms the header
        **  fields exactly as the MTA will modify them, so verification
        **  should still work.
        **
        **  This is based on experimentation and on reading
        **  sendmail/headers.c, and may require more tweaking before
        **  it's precisely right.  There are other munges the
        **  sendmail MTA makes which are not (yet) addressed by this
        **  code.
        **
        **  This should not be used with sendmail 8.14 and later as
        **  it is not required; that version of sendmail and
        **  libmilter handles the munging correctly (by suppressing
        **  it).
        */

        char *p;

        p = headerv;
        while (isascii(*p) && isspace(*p))
        {
            p++;
        }

        arc_dstring_copy(afc->mctx_tmpstr, p);
    }
    else
    {
        arc_dstring_copy(afc->mctx_tmpstr, headerv);
    }

    newhdr->hdr_val = ARC_STRDUP(arc_dstring_get(afc->mctx_tmpstr));

    newhdr->hdr_next = NULL;
    newhdr->hdr_prev = afc->mctx_hqtail;

    if (newhdr->hdr_hdr == NULL || newhdr->hdr_val == NULL)
    {
        if (conf->conf_dolog)
        {
            syslog(LOG_ERR, "malloc(): %s", strerror(errno));
        }

        ARC_FREE(newhdr->hdr_hdr);
        ARC_FREE(newhdr->hdr_val);
        ARC_FREE(newhdr);
        arcf_cleanup(ctx);
        return conf->conf_ret_unable;
    }

    afc->mctx_hdrbytes += strlen(newhdr->hdr_hdr) + 1;
    afc->mctx_hdrbytes += strlen(newhdr->hdr_val) + 1;

    if (afc->mctx_hqhead == NULL)
    {
        afc->mctx_hqhead = newhdr;
    }

    if (afc->mctx_hqtail != NULL)
    {
        afc->mctx_hqtail->hdr_next = newhdr;
    }

    afc->mctx_hqtail = newhdr;

    return SMFIS_CONTINUE;
}

/*
**  MLFI_EOH -- handler called when there are no more headers
**
**  Parameters:
**  	ctx -- milter context
**
**  Return value:
**  	An SMFIS_* constant.
*/

sfsistat
mlfi_eoh(SMFICTX *ctx)
{
    char                last;
    unsigned int        mode;
    ARC_STAT            status;
    connctx             cc;
    msgctx              afc;
    char               *p;
    const char         *err = NULL;
    struct arcf_config *conf;
    Header              hdr;

    assert(ctx != NULL);

    cc = (connctx) arcf_getpriv(ctx);
    assert(cc != NULL);
    afc = cc->cctx_msg;
    assert(afc != NULL);
    conf = cc->cctx_config;

    /*
    **  Determine the message ID for logging.
    */

    afc->mctx_jobid = (unsigned char *) arcf_getsymval(ctx, "i");
    if (afc->mctx_jobid == NULL || afc->mctx_jobid[0] == '\0')
    {
        afc->mctx_jobid = (unsigned char *) JOBIDUNKNOWN;
    }

    /* if requested, verify RFC5322-required headers (RFC5322 3.6) */
    if (conf->conf_reqhdrs)
    {
        bool ok = true;

        /* exactly one From: */
        if (arcf_findheader(afc, "From", 0) == NULL ||
            arcf_findheader(afc, "From", 1) != NULL)
        {
            ok = false;
        }

        /* exactly one Date: */
        if (arcf_findheader(afc, "Date", 0) == NULL ||
            arcf_findheader(afc, "Date", 1) != NULL)
        {
            ok = false;
        }

        /* no more than one Reply-To: */
        if (arcf_findheader(afc, "Reply-To", 1) != NULL)
        {
            ok = false;
        }

        /* no more than one To: */
        if (arcf_findheader(afc, "To", 1) != NULL)
        {
            ok = false;
        }

        /* no more than one Cc: */
        if (arcf_findheader(afc, "Cc", 1) != NULL)
        {
            ok = false;
        }

        /* no more than one Bcc: */
        if (arcf_findheader(afc, "Bcc", 1) != NULL)
        {
            ok = false;
        }

        /* no more than one Message-Id: */
        if (arcf_findheader(afc, "Message-Id", 1) != NULL)
        {
            ok = false;
        }

        /* no more than one In-Reply-To: */
        if (arcf_findheader(afc, "In-Reply-To", 1) != NULL)
        {
            ok = false;
        }

        /* no more than one References: */
        if (arcf_findheader(afc, "References", 1) != NULL)
        {
            ok = false;
        }

        /* no more than one Subject: */
        if (arcf_findheader(afc, "Subject", 1) != NULL)
        {
            ok = false;
        }

        if (!ok)
        {
            if (conf->conf_dolog)
            {
                syslog(LOG_INFO, "%s: RFC5322 header requirement error",
                       afc->mctx_jobid);
            }

            return SMFIS_ACCEPT;
        }
    }

#ifdef USE_JANSSON
    /*
    **  If we only care about messages with specific header properties,
    **  see if this is one of those.
    */

    if (!LIST_EMPTY(&conf->conf_sealheaderchecks))
    {
        bool                found = false;
        int                 restatus;
        struct configvalue *node;
        char                buf[BUFRSZ];

        LIST_FOREACH(node, &conf->conf_sealheaderchecks, entries)
        {
            int          hfnum = 0;
            char        *hfname = NULL;
            char        *hfmatch;
            regex_t      re;
            json_t      *json;
            const char  *str;
            json_error_t json_err;

            strlcpy(buf, node->value, sizeof buf);
            hfmatch = strchr(buf, ':');
            if (hfmatch != NULL)
            {
                hfname = buf;
                *hfmatch++ = '\0';
            }

            if (hfmatch != NULL)
            {
                restatus = regcomp(&re, hfmatch, 0);
            }

            if (hfname == NULL || hfmatch == NULL || restatus != 0)
            {
                if (conf->conf_dolog)
                {
                    syslog(LOG_ERR, "%s: invalid seal header check \"%s\"",
                           afc->mctx_jobid, node->value);
                }
            }

            for (hfnum = 0; !found; hfnum++)
            {
                hdr = arcf_findheader(afc, hfname, hfnum);
                if (hdr == NULL)
                {
                    break;
                }

                json = json_loads(hdr->hdr_val, 0, &json_err);
                if (json != NULL)
                {
                    if (json_is_string(json))
                    {
                        str = json_string_value(json);
                        if (regexec(&re, str, 0, NULL, 0) == 0)
                        {
                            found = true;
                            break;
                        }
                    }
                    else if (json_is_array(json))
                    {
                        size_t  jn;
                        json_t *entry;

                        for (jn = 0; !found && jn < json_array_size(json); jn++)
                        {
                            entry = json_array_get(json, jn);

                            if (json_is_string(entry))
                            {
                                str = json_string_value(entry);

                                if (regexec(&re, str, 0, NULL, 0) == 0)
                                {
                                    found = true;
                                    break;
                                }
                            }
                        }
                    }

                    json_decref(json);
                }
                else if (regexec(&re, hdr->hdr_val, 0, NULL, 0) == 0)
                {
                    found = true;
                    break;
                }
            }

            regfree(&re);
        }

        if (!found)
        {
            if (conf->conf_dolog)
            {
                syslog(LOG_INFO, "%s: no seal header check matched; continuing",
                       afc->mctx_jobid);
            }

            return conf->conf_ret_disabled;
        }
    }
#endif /* USE_JANSSON */

    /* run the header fields */
    mode = conf->conf_mode;
    if (mode == 0)
    {
        mode = cc->cctx_mode;
    }
    afc->mctx_arcmsg = arc_message(conf->conf_libopenarc, conf->conf_canonhdr,
                                   conf->conf_canonbody, conf->conf_signalg,
                                   mode, &err);
    if (afc->mctx_arcmsg == NULL)
    {
        if (conf->conf_dolog)
        {
            syslog(LOG_INFO, "%s: can't initialize ARC handle: %s",
                   afc->mctx_jobid, err);
        }

        return conf->conf_ret_unable;
    }

    for (hdr = afc->mctx_hqhead; hdr != NULL; hdr = hdr->hdr_next)
    {
        if (afc->mctx_tmpstr == NULL)
        {
            afc->mctx_tmpstr = arc_dstring_new(BUFRSZ, 0, NULL, NULL);
            if (afc->mctx_tmpstr == NULL)
            {
                if (conf->conf_dolog)
                {
                    syslog(LOG_ERR, "%s: arc_dstring_new() failed",
                           afc->mctx_jobid);
                }

                return conf->conf_ret_unable;
            }
        }
        else
        {
            arc_dstring_blank(afc->mctx_tmpstr);
        }

        arc_dstring_copy(afc->mctx_tmpstr, hdr->hdr_hdr);
        arc_dstring_cat1(afc->mctx_tmpstr, ':');
        if (!cc->cctx_noleadspc)
        {
            arc_dstring_cat1(afc->mctx_tmpstr, ' ');
        }

        last = '\0';

        /* do milter-ized continuation conversion */
        for (p = hdr->hdr_val; *p != '\0'; p++)
        {
            if (*p == '\n' && last != '\r')
            {
                arc_dstring_cat1(afc->mctx_tmpstr, '\r');
            }

            arc_dstring_cat1(afc->mctx_tmpstr, *p);

            last = *p;
        }

        status = arc_header_field(afc->mctx_arcmsg,
                                  arc_dstring_get(afc->mctx_tmpstr),
                                  arc_dstring_len(afc->mctx_tmpstr));
        if (status != ARC_STAT_OK)
        {
            if (conf->conf_dolog)
            {
                syslog(LOG_INFO, "%s: error processing header field \"%s\"",
                       afc->mctx_jobid, hdr->hdr_hdr);
            }

            if (status == ARC_STAT_SYNTAX)
            {
                return conf->conf_ret_unwilling;
            }
            return conf->conf_ret_unable;
        }
    }

    /* signal end of headers to libopenarc */
    status = arc_eoh(afc->mctx_arcmsg);
    if (status != ARC_STAT_OK)
    {
        if (conf->conf_dolog)
        {
            syslog(LOG_INFO, "%s: error processing at end of header",
                   afc->mctx_jobid);
        }

        /* record a bad chain here, and short-circuit crypto */
        arc_set_cv(afc->mctx_arcmsg, ARC_CHAIN_FAIL);
    }

    return SMFIS_CONTINUE;
}

/*
**  MLFI_BODY -- handler for an arbitrary body block
**
**  Parameters:
**  	ctx -- milter context
**  	bodyp -- body block
**  	bodylen -- amount of data available at bodyp
**
**  Return value:
**  	An SMFIS_* constant.
**
**  Description:
**  	This function reads the body chunks passed by the MTA and
**  	stores them for later wrapping, if needed.
*/

sfsistat
mlfi_body(SMFICTX *ctx, unsigned char *bodyp, size_t bodylen)
{
    int                 status;
    msgctx              afc;
    connctx             cc;
    struct arcf_config *conf;

    assert(ctx != NULL);
    assert(bodyp != NULL);

    cc = (connctx) arcf_getpriv(ctx);
    assert(cc != NULL);
    afc = cc->cctx_msg;
    assert(afc != NULL);
    conf = cc->cctx_config;

    /*
    **  No need to do anything if the body was empty.
    */

    if (bodylen == 0)
    {
        return SMFIS_CONTINUE;
    }

    if (afc->mctx_arcmsg != NULL)
    {
        status = arc_body(afc->mctx_arcmsg, bodyp, bodylen);
        if (status != ARC_STAT_OK)
        {
            if (conf->conf_dolog)
            {
                syslog(LOG_INFO, "%s: error processing body chunk",
                       afc->mctx_jobid);
            }

            return conf->conf_ret_unable;
        }
    }

    return SMFIS_CONTINUE;
}

/* helper function to handle overriding the chain state */
static bool
reconcile_arc_state(msgctx afc, struct result *r)
{
    int initial_cv;
    int ar_cv;
    int new_cv;

    switch (r->result_result)
    {
    case ARES_RESULT_NONE:
        ar_cv = ARC_CHAIN_NONE;
        break;

    case ARES_RESULT_PASS:
        ar_cv = ARC_CHAIN_PASS;
        break;

    case ARES_RESULT_FAIL:
        ar_cv = ARC_CHAIN_FAIL;
        break;

    default:
        ar_cv = ARC_CHAIN_UNKNOWN;
        break;
    }

    initial_cv = arc_chain_status(afc->mctx_arcmsg);
    arc_set_cv(afc->mctx_arcmsg, ar_cv);
    new_cv = arc_chain_status(afc->mctx_arcmsg);

    if (new_cv != ar_cv)
    {
        /* allow the library to override the result */
        switch (arc_chain_status(afc->mctx_arcmsg))
        {
        case ARC_CHAIN_NONE:
            r->result_result = ARES_RESULT_NONE;
            break;
        case ARC_CHAIN_PASS:
            r->result_result = ARES_RESULT_PASS;
            break;
        case ARC_CHAIN_FAIL:
            r->result_result = ARES_RESULT_FAIL;
            break;
        }
    }

    return initial_cv != new_cv;
}

/* helper function to generate the arc authentication result for AR and AAR */
static void
add_arc_authres(msgctx afc, struct arcf_config *conf, const char *ip)
{
    arc_dstring_printf(afc->mctx_tmpstr, "arc=%s",
                       arc_chain_status_str(afc->mctx_arcmsg));

    if (arc_chain_oldest_pass(afc->mctx_arcmsg) >= 0)
    {
        arc_dstring_printf(afc->mctx_tmpstr, " header.oldest-pass=%d",
                           arc_chain_oldest_pass(afc->mctx_arcmsg));
    }

    if (conf->conf_authresip && ip[0] != '\0')
    {
        bool quote = !ares_istoken(ip);

        arc_dstring_printf(afc->mctx_tmpstr, " smtp.remote-ip=%s%s%s",
                           quote ? "\"" : "", ip, quote ? "\"" : "");
    }
}

/*
**  MLFI_EOM -- handler called at the end of the message; we can now decide
**              based on the configuration if and how to add the text
**              to this message, then release resources
**
**  Parameters:
**  	ctx -- milter context
**
**  Return value:
**  	An SMFIS_* constant.
*/

sfsistat
mlfi_eom(SMFICTX *ctx)
{
    int                 status = ARC_STAT_OK;
    connctx             cc;
    msgctx              afc;
    char               *hostname;
    struct arcf_config *conf;
    ARC_HDRFIELD       *seal = NULL;
    ARC_HDRFIELD       *sealhdr = NULL;
    struct sockaddr    *ip;
    Header              hdr;
    struct authres      ar;
    char                arcchainbuf[ARC_MAXHEADER + 1];
    char                ipbuf[INET6_ADDRSTRLEN];

    assert(ctx != NULL);

    cc = (connctx) arcf_getpriv(ctx);
    assert(cc != NULL);
    afc = cc->cctx_msg;
    assert(afc != NULL);
    conf = cc->cctx_config;

    /*
    **  If necessary, try again to get the job ID in case it came down
    **  later than expected (e.g. postfix).
    */

    if (strcmp((char *) afc->mctx_jobid, JOBIDUNKNOWN) == 0)
    {
        afc->mctx_jobid = (unsigned char *) arcf_getsymval(ctx, "i");
        if (afc->mctx_jobid == NULL || afc->mctx_jobid[0] == '\0')
        {
            if (no_i_whine && conf->conf_dolog)
            {
                syslog(LOG_WARNING, "WARNING: symbol 'i' not available");
                no_i_whine = false;
            }
            afc->mctx_jobid = (unsigned char *) JOBIDUNKNOWN;
        }
    }

    if (afc->mctx_tmpstr == NULL)
    {
        afc->mctx_tmpstr = arc_dstring_new(BUFRSZ, 0, NULL, NULL);
        if (afc->mctx_tmpstr == NULL)
        {
            if (conf->conf_dolog)
            {
                syslog(LOG_ERR, "arc_dstring_new() failed");
            }

            return conf->conf_ret_unable;
        }
    }

    /* get hostname; used in the X header and in new MIME boundaries */
    hostname = arcf_getsymval(ctx, "j");
    if (hostname == NULL)
    {
        hostname = HOSTUNKNOWN;
    }

    /* get IP string */
    ip = (struct sockaddr *) &cc->cctx_ip;
    memset(ipbuf, '\0', sizeof ipbuf);

    if (getnameinfo(ip,
                    (ip->sa_family == AF_INET6) ? sizeof(struct sockaddr_in6)
                                                : sizeof(struct sockaddr_in),
                    ipbuf, sizeof ipbuf, NULL, 0, NI_NUMERICHOST) != 0)
    {
        memset(ipbuf, '\0', sizeof ipbuf);
    }

    /*
    **  Signal end-of-message to ARC.
    */

    status = arc_eom(afc->mctx_arcmsg);
    if (status != ARC_STAT_OK)
    {
        if (conf->conf_dolog)
        {
            syslog(LOG_WARNING, "%s: error processing at end-of-message",
                   afc->mctx_jobid);
        }

        return conf->conf_ret_unable;
    }

    if (BITSET(ARC_MODE_SIGN, cc->cctx_mode))
    {
        bool arfound = false;
        memset(&ar, '\0', sizeof ar);
        arc_dstring_blank(afc->mctx_tmpstr);

        /* assemble authentication results */
        for (int i = 0;; i++)
        {
            hdr = arcf_findheader(afc, AUTHRESULTSHDR, i);
            if (hdr == NULL)
            {
                break;
            }
            status = ares_parse(hdr->hdr_val, &ar, conf->conf_authservid);
            if (status == -1)
            {
                if (conf->conf_dolog)
                {
                    syslog(LOG_WARNING, "%s: can't parse %s; %s ; ignoring",
                           afc->mctx_jobid, AUTHRESULTSHDR, hdr->hdr_val);
                }

                continue;
            }
        }

        for (int i = 0; i < ar.ares_count; i++)
        {
            if (ar.ares_result[i].result_method == ARES_METHOD_ARC)
            {
                if (!conf->conf_overridecv)
                {
                    continue;
                }

                arfound = true;
                if (reconcile_arc_state(afc, &ar.ares_result[i]) &&
                    conf->conf_dolog)
                {
                    syslog(
                        LOG_INFO,
                        "%s: chain state forced to \"%s\" due to prior result found",
                        afc->mctx_jobid,
                        arc_chain_status_str(afc->mctx_arcmsg));
                }
            }

            if (arc_dstring_len(afc->mctx_tmpstr) > 0)
            {
                arc_dstring_cat(afc->mctx_tmpstr, ";\n\t");
            }

            arc_dstring_printf(afc->mctx_tmpstr, "%s=%s",
                               ares_getmethod(ar.ares_result[i].result_method),
                               ares_getresult(ar.ares_result[i].result_result));

            if (ar.ares_result[i].result_reason[0] != '\0')
            {
                arc_dstring_printf(afc->mctx_tmpstr, " reason=\"%s\"",
                                   ar.ares_result[i].result_reason);
            }

            for (int j = 0; j < ar.ares_result[i].result_props; j++)
            {
                if (ar.ares_result[i].result_ptype[j] == ARES_PTYPE_COMMENT)
                {
                    arc_dstring_printf(afc->mctx_tmpstr, " %s",
                                       ar.ares_result[i].result_value[j]);
                }
                else
                {
                    bool quote = !ares_istoken(
                        ar.ares_result[i].result_value[j]);
                    arc_dstring_printf(
                        afc->mctx_tmpstr, " %s.%s=%s%s%s",
                        ares_getptype(ar.ares_result[i].result_ptype[j]),
                        ar.ares_result[i].result_property[j], quote ? "\"" : "",
                        ar.ares_result[i].result_value[j], quote ? "\"" : "");
                }
            }
        }

        if (!arfound)
        {
            if (arc_dstring_len(afc->mctx_tmpstr) > 0)
            {
                arc_dstring_cat(afc->mctx_tmpstr, ";\n\t");
            }
            add_arc_authres(afc, conf, ipbuf);
        }

        /*
        **  Get the seal fields to apply.
        */

        status = arc_getseal(afc->mctx_arcmsg, &seal, conf->conf_authservid,
                             conf->conf_selector, conf->conf_domain,
                             conf->conf_keydata, conf->conf_keylen,
                             arc_dstring_len(afc->mctx_tmpstr) > 0
                                 ? arc_dstring_get(afc->mctx_tmpstr)
                                 : NULL);
        if (status != ARC_STAT_OK)
        {
            if (conf->conf_dolog)
            {
                syslog(LOG_WARNING, "%s: failed to compute seal",
                       afc->mctx_jobid);
            }

            return conf->conf_ret_unable;
        }

        for (sealhdr = seal; sealhdr != NULL; sealhdr = arc_hdr_next(sealhdr))
        {
            size_t len;
            char  *hfvalue;
            char   hfname[BUFRSZ + 1];

            memset(hfname, '\0', sizeof hfname);
            strlcpy(hfname, arc_hdr_name(sealhdr, &len), sizeof hfname);
            hfname[len] = '\0';

            hfvalue = arc_hdr_value(sealhdr);
            if (!cc->cctx_noleadspc)
            {
                /* strip off the leading space */
                hfvalue++;
            }

            status = arcf_insheader(ctx, 0, hfname, hfvalue);
            if (status == MI_FAILURE)
            {
                if (conf->conf_dolog)
                {
                    syslog(LOG_WARNING,
                           "%s: error inserting header field \"%s\"",
                           afc->mctx_jobid, hfname);
                }

                return SMFIS_TEMPFAIL;
            }
        }
    }

    if (BITSET(ARC_MODE_VERIFY, cc->cctx_mode))
    {
        /*
        **  Authentication-Results
        */

        int arcchainlen = arc_chain_custody_str(afc->mctx_arcmsg, arcchainbuf,
                                                sizeof(arcchainbuf));

        if (arcchainlen >= sizeof(arcchainbuf))
        {
            if (conf->conf_dolog)
            {
                syslog(LOG_ERR, "%s: arc.chain buffer overflow: %s",
                       afc->mctx_jobid, "");
            }

            return conf->conf_ret_unable;
        }

        arc_dstring_blank(afc->mctx_tmpstr);
        arc_dstring_printf(afc->mctx_tmpstr, "%s%s; ",
                           cc->cctx_noleadspc ? " " : "",
                           conf->conf_authservid);

        add_arc_authres(afc, conf, ipbuf);

        if (conf->conf_finalreceiver && arcchainlen > 0)
        {
            bool quote = !ares_istoken(arcchainbuf);

            arc_dstring_printf(afc->mctx_tmpstr, " arc.chain=%s%s%s",
                               quote ? "\"" : "", arcchainbuf,
                               quote ? "\"" : "");
        }

        if (arcf_insheader(ctx, 0, AUTHRESULTSHDR,
                           arc_dstring_get(afc->mctx_tmpstr)) != MI_SUCCESS)
        {
            if (conf->conf_dolog)
            {
                syslog(LOG_ERR, "%s: %s header add failed", afc->mctx_jobid,
                       AUTHRESULTSHDR);
            }

            return SMFIS_TEMPFAIL;
        }
    }

    /*
    **  Identify the filter, if requested.
    */

    if (conf->conf_addswhdr)
    {
        char xfhdr[ARC_MAXHEADER + 1];

        memset(xfhdr, '\0', sizeof xfhdr);

        snprintf(xfhdr, ARC_MAXHEADER, "%s%s v%s %s %s",
                 cc->cctx_noleadspc ? " " : "", ARCF_PRODUCT, VERSION, hostname,
                 afc->mctx_jobid != NULL ? afc->mctx_jobid
                                         : (unsigned char *) JOBIDUNKNOWN);

        if (arcf_insheader(ctx, 0, SWHEADERNAME, xfhdr) != MI_SUCCESS)
        {
            if (conf->conf_dolog)
            {
                syslog(LOG_ERR, "%s: %s header add failed", afc->mctx_jobid,
                       SWHEADERNAME);
            }

            return SMFIS_TEMPFAIL;
        }
    }

    /*
    **  If we got this far, we're ready to complete.
    */

    return SMFIS_ACCEPT;
}

/*
**  MLFI_ABORT -- handler called if an earlier filter in the filter process
**                rejects the message
**
**  Parameters:
**  	ctx -- milter context
**
**  Return value:
**  	An SMFIS_* constant.
*/

sfsistat
mlfi_abort(SMFICTX *ctx)
{
    arcf_cleanup(ctx);
    return SMFIS_CONTINUE;
}

/*
**  MLFI_CLOSE -- handler called on connection shutdown
**
**  Parameters:
**  	ctx -- milter context
**
**  Return value:
**  	An SMFIS_* constant.
*/

sfsistat
mlfi_close(SMFICTX *ctx)
{
    connctx cc;

    arcf_cleanup(ctx);

    cc = (connctx) arcf_getpriv(ctx);
    if (cc != NULL)
    {
        pthread_mutex_lock(&conf_lock);

        cc->cctx_config->conf_refcnt--;

        if (cc->cctx_config->conf_refcnt == 0 && cc->cctx_config != curconf)
        {
            arcf_config_free(cc->cctx_config);
        }

        pthread_mutex_unlock(&conf_lock);

        ARC_FREE(cc);
        arcf_setpriv(ctx, NULL);
    }

    return SMFIS_CONTINUE;
}

/*
**  smfilter -- the milter module description
*/

struct smfiDesc smfilter = {
    ARCF_PRODUCT, /* filter name */
    SMFI_VERSION, /* version code -- do not change */
    0,            /* flags; updated in main() */
    mlfi_connect, /* connection info filter */
#if SMFI_VERSION == 2
    mlfi_helo,    /* SMTP HELO command filter */
#else             /* SMFI_VERSION == 2 */
    NULL, /* SMTP HELO command filter */
#endif            /* SMFI_VERSION == 2 */
    mlfi_envfrom, /* envelope sender filter */
    NULL,         /* envelope recipient filter */
    mlfi_header,  /* header filter */
    mlfi_eoh,     /* end of header */
    mlfi_body,    /* body block filter */
    mlfi_eom,     /* end of message */
    mlfi_abort,   /* message aborted */
    mlfi_close,   /* shutdown */
#if SMFI_VERSION > 2
    NULL, /* unrecognised command */
#endif
#if SMFI_VERSION > 3
    NULL, /* DATA */
#endif
#if SMFI_VERSION >= 0x01000000
    mlfi_negotiate /* negotiation callback */
#endif
};

/*
**  USAGE -- print a usage message and return the appropriate exit status
**
**  Parameters:
**  	None.
**
**  Return value:
**  	EX_USAGE.
*/

static int
usage(void)
{
    fprintf(stderr,
            "%s: usage: %s -p socketfile [options]\n"
            "\t-A          \tauto-restart\n"
            "\t-c conffile \tread configuration from conffile\n"
            "\t-f          \tdon't fork-and-exit\n"
            "\t-h          \tprint this help message and exit\n"
            "\t-l          \tlog activity to system log\n"
            "\t-n          \tcheck configuration and exit\n"
            "\t-P pidfile  \tfile into which to write process ID\n"
            "\t-r          \trequire basic RFC5322 header compliance\n"
            "\t-t testfile \tevaluate RFC5322 message in \"testfile\"\n"
            "\t-u userid   \tchange to specified userid\n"
            "\t-v          \tincrease verbosity during testing\n"
            "\t-V          \tprint version number and terminate\n",
            progname, progname);
    return EX_USAGE;
}

/*
**  MAIN -- program mainline
**
**  Process command line arguments and call the milter mainline.
*/

int
main(int argc, char **argv)
{
    bool autorestart = false;
    bool gotp = false;
    bool dofork = true;
    bool configonly = false;
    int  c;
    int  status;
    int  n;
    int  verbose = 0;
    int  maxrestarts = 0;
    int  maxrestartrate_n = 0;
    int  filemask = -1;
    int  mdebug = 0;
#ifdef HAVE_SMFI_VERSION
    unsigned int mvmajor;
    unsigned int mvminor;
    unsigned int mvrelease;
#endif /* HAVE_SMFI_VERSION */
    time_t         now;
    gid_t          gid = (gid_t) -1;
    sigset_t       sigset;
    time_t         maxrestartrate_t = 0;
    pthread_t      rt;
    const char    *args = CMDLINEOPTS;
    FILE          *f;
    struct passwd *pw = NULL;
    struct group  *gr = NULL;
    char          *become = NULL;
    char          *chrootdir = NULL;
    char          *p;
    char          *pidfile = NULL;
    char          *testfile = NULL;
    struct config *cfg = NULL;
    char          *end;
    char           argstr[MAXARGV];
    char           err[BUFRSZ + 1];

    /* initialize */
    reload = false;
    sock = NULL;
    no_i_whine = true;
    conffile = NULL;

    memset(myhostname, '\0', sizeof myhostname);
    (void) gethostname(myhostname, sizeof myhostname);

    progname = (p = strrchr(argv[0], '/')) == NULL ? argv[0] : p + 1;

    (void) time(&now);
    srandom(now);

    curconf = arcf_config_new();
    if (curconf == NULL)
    {
        fprintf(stderr, "%s: malloc(): %s\n", progname, strerror(errno));

        return EX_OSERR;
    }

    /* process command line options */
    while ((c = getopt(argc, argv, args)) != -1)
    {
        switch (c)
        {
        case 'A':
            autorestart = true;
            break;

        case 'c':
            if (optarg == NULL || *optarg == '\0')
            {
                return usage();
            }
            else
            {
                conffile = optarg;
            }
            break;

        case 'f':
            dofork = false;
            break;

        case 'l':
            curconf->conf_dolog = true;
            break;

        case 'n':
            configonly = true;
            break;

        case 'p':
            if (optarg == NULL || *optarg == '\0')
            {
                return usage();
            }
            sock = optarg;
            (void) smfi_setconn(optarg);
            gotp = true;
            break;

        case 'P':
            if (optarg == NULL || *optarg == '\0')
            {
                return usage();
            }
            pidfile = optarg;
            break;

        case 'r':
            curconf->conf_reqhdrs = true;
            break;

        case 't':
            if (optarg == NULL || *optarg == '\0')
            {
                return usage();
            }
            testmode = true;
            testfile = optarg;
            break;

        case 'u':
            if (optarg == NULL || *optarg == '\0')
            {
                return usage();
            }
            become = optarg;
            break;

        case 'v':
            verbose++;
            break;

        case 'V':
            if (!arcf_config_setlib(curconf, &p))
            {
                fprintf(stderr, "%s: can't configure ARC library: %s\n",
                        progname, p);

                return EX_SOFTWARE;
            }

            printf("%s: %s v%s\n", progname, ARCF_PRODUCT, VERSION);
            printf("\tCompiled with %s\n",
#if OPENSSL_VERSION_NUMBER < 0x10100000L
                   SSLeay_version(SSLEAY_VERSION)
#else
                   OpenSSL_version(OPENSSL_VERSION)
#endif /* OpenSSL < 1.1.0 */
            );
            printf("\tSMFI_VERSION 0x%x\n", SMFI_VERSION);
#ifdef HAVE_SMFI_VERSION
            (void) smfi_version(&mvmajor, &mvminor, &mvrelease);
            printf("\tlibmilter version %d.%d.%d\n", mvmajor, mvminor,
                   mvrelease);
#endif /* HAVE_SMFI_VERSION */
            arcf_optlist(stdout);
            return EX_OK;

        default:
            return usage();
        }
    }

    if (optind != argc)
    {
        return usage();
    }

    if (arc_ssl_version() != OPENSSL_VERSION_NUMBER)
    {
        fprintf(
            stderr,
            "%s: incompatible SSL versions (library = 0x%09lx, filter = %09lx)\n",
            progname, arc_ssl_version(),
            (unsigned long) OPENSSL_VERSION_NUMBER);

        return EX_SOFTWARE;
    }

    /* if there's a default config file readable, use it */
    if (conffile == NULL && access(DEFCONFFILE, R_OK) == 0)
    {
        conffile = DEFCONFFILE;
        if (verbose > 1)
        {
            fprintf(stderr, "%s: using default configfile %s\n", progname,
                    DEFCONFFILE);
        }
    }

    if (conffile != NULL)
    {
        unsigned int line = 0;
        char        *missing;
        char        *deprecated = NULL;
        char         path[MAXPATHLEN + 1];

        cfg = config_load(conffile, arcf_config, &line, path, sizeof path,
                          &deprecated);

        if (cfg == NULL)
        {
            fprintf(stderr, "%s: %s: configuration error at line %u: %s\n",
                    progname, path, line, config_error());
            arcf_config_free(curconf);
            return EX_CONFIG;
        }

#ifdef DEBUG
        (void) config_dump(cfg, stdout, NULL);
#endif /* DEBUG */

        missing = config_check(cfg, arcf_config);
        if (missing != NULL)
        {
            fprintf(stderr, "%s: %s: required parameter \"%s\" missing\n",
                    progname, conffile, missing);
            config_free(cfg);
            arcf_config_free(curconf);
            return EX_CONFIG;
        }

        if (deprecated != NULL)
        {
            fprintf(
                stderr,
                "%s: %s: settings found for deprecated value(s): %s; aborting\n",
                progname, conffile, deprecated);

            config_free(cfg);
            arcf_config_free(curconf);
            return EX_CONFIG;
        }
    }

    if (arcf_config_load(cfg, curconf, err, sizeof err, become) != 0)
    {
        if (conffile == NULL)
        {
            conffile = "(stdin)";
        }
        fprintf(stderr, "%s: %s: %s\n", progname, conffile, err);
        config_free(cfg);
        arcf_config_free(curconf);
        return EX_CONFIG;
    }

    if (configonly)
    {
        config_free(cfg);
        arcf_config_free(curconf);
        return EX_OK;
    }

    dolog = curconf->conf_dolog;
    curconf->conf_data = cfg;

    /*
    **  Use values found in the configuration file, if any.  Note that
    **  these are operational parameters for the filter (e.g which socket
    **  to use which userid to become, etc.) and aren't reloaded upon a
    **  reload signal.  Reloadable values are handled via the
    **  arcf_config_load() function, which has already been called.
    */

    if (cfg != NULL)
    {
        if (!autorestart)
        {
            (void) config_get(cfg, "AutoRestart", &autorestart,
                              sizeof autorestart);
        }

        if (autorestart)
        {
            char *rate = NULL;

            (void) config_get(cfg, "AutoRestartCount", &maxrestarts,
                              sizeof maxrestarts);

            (void) config_get(cfg, "AutoRestartRate", &rate, sizeof rate);

            if (rate != NULL)
            {
                time_t t;
                char  *q;

                p = strchr(rate, '/');
                if (p == NULL)
                {
                    fprintf(stderr, "%s: AutoRestartRate invalid\n", progname);
                    config_free(cfg);
                    return EX_CONFIG;
                }

                *p = '\0';
                n = strtol(rate, &q, 10);
                if (n < 0 || *q != '\0')
                {
                    fprintf(stderr, "%s: AutoRestartRate invalid\n", progname);
                    config_free(cfg);
                    return EX_CONFIG;
                }

                t = (time_t) strtoul(p + 1, &q, 10);
                switch (*q)
                {
                case 'd':
                case 'D':
                    t *= 86400;
                    break;

                case 'h':
                case 'H':
                    t *= 3600;
                    break;

                case 'm':
                case 'M':
                    t *= 60;
                    break;

                case '\0':
                case 's':
                case 'S':
                    break;

                default:
                    t = 0;
                    break;
                }

                if (*q != '\0' && *(q + 1) != '\0')
                {
                    t = 0;
                }

                if (t == 0)
                {
                    fprintf(stderr, "%s: AutoRestartRate invalid\n", progname);
                    config_free(cfg);
                    return EX_CONFIG;
                }

                maxrestartrate_n = n;
                maxrestartrate_t = t;
            }
        }

        if (dofork)
        {
            (void) config_get(cfg, "Background", &dofork, sizeof dofork);
        }

        (void) config_get(cfg, "MilterDebug", &mdebug, sizeof mdebug);

        if (!gotp)
        {
            (void) config_get(cfg, "Socket", &sock, sizeof sock);
            if (sock != NULL)
            {
                gotp = true;
                (void) smfi_setconn(sock);
            }
        }

        if (pidfile == NULL)
        {
            (void) config_get(cfg, "PidFile", &pidfile, sizeof pidfile);
        }

        (void) config_get(cfg, "UMask", &filemask, sizeof filemask);

        if (become == NULL)
        {
            (void) config_get(cfg, "Userid", &become, sizeof become);
        }

        (void) config_get(cfg, "ChangeRootDirectory", &chrootdir,
                          sizeof chrootdir);
    }

    if (!gotp && !testmode)
    {
        fprintf(stderr, "%s: milter socket must be specified\n", progname);
        if (argc == 1)
        {
            fprintf(stderr, "\t(use \"-?\" for help)\n");
        }
        return EX_CONFIG;
    }

    /* suppress a bunch of things if we're in test mode */
    if (testmode)
    {
        curconf->conf_dolog = false;
        autorestart = false;
        dofork = false;
        become = NULL;
        pidfile = NULL;
        chrootdir = NULL;
    }

    arcf_setmaxfd();

    /* prepare to change user if appropriate */
    if (become != NULL)
    {
        char *colon;

        /* see if there was a group specified; if so, validate */
        colon = strchr(become, ':');
        if (colon != NULL)
        {
            *colon = '\0';

            gr = getgrnam(colon + 1);
            if (gr == NULL)
            {
                char *q;

                gid = (gid_t) strtol(colon + 1, &q, 10);
                if (*q == '\0')
                {
                    gr = getgrgid(gid);
                }

                if (gr == NULL)
                {
                    if (curconf->conf_dolog)
                    {
                        syslog(LOG_ERR, "no such group or gid '%s'", colon + 1);
                    }

                    fprintf(stderr, "%s: no such group '%s'\n", progname,
                            colon + 1);

                    return EX_DATAERR;
                }
            }
        }

        /* validate the user */
        pw = getpwnam(become);
        if (pw == NULL)
        {
            char *q;
            uid_t uid;

            uid = (uid_t) strtoul(become, &q, 10);
            if (*q == '\0')
            {
                pw = getpwuid(uid);
            }

            if (pw == NULL)
            {
                if (curconf->conf_dolog)
                {
                    syslog(LOG_ERR, "no such user or uid '%s'", become);
                }

                fprintf(stderr, "%s: no such user '%s'\n", progname, become);

                return EX_DATAERR;
            }
        }

        if (gr == NULL)
        {
            gid = pw->pw_gid;
        }
        else
        {
            gid = gr->gr_gid;
        }

        (void) endpwent();
    }

    /* change root if requested */
    if (chrootdir != NULL)
    {
        /* warn if doing so as root without then giving up root */
        if (become == NULL && getuid() == 0)
        {
            if (curconf->conf_dolog)
            {
                syslog(LOG_WARNING,
                       "using ChangeRootDirectory without Userid not advised");
            }

            fprintf(
                stderr,
                "%s: use of ChangeRootDirectory without Userid not advised\n",
                progname);
        }

        /* change to the new root first */
        if (chdir(chrootdir) != 0)
        {
            if (curconf->conf_dolog)
            {
                syslog(LOG_ERR, "%s: chdir(): %s", chrootdir, strerror(errno));
            }

            fprintf(stderr, "%s: %s: chdir(): %s\n", progname, chrootdir,
                    strerror(errno));
            return EX_OSERR;
        }

        /* now change the root */
        if (chroot(chrootdir) != 0)
        {
            if (curconf->conf_dolog)
            {
                syslog(LOG_ERR, "%s: chroot(): %s", chrootdir, strerror(errno));
            }

            fprintf(stderr, "%s: %s: chroot(): %s\n", progname, chrootdir,
                    strerror(errno));
            return EX_OSERR;
        }
    }

    if (curconf->conf_enablecores)
    {
        bool enabled = false;

#ifdef __linux__
        if (prctl(PR_SET_DUMPABLE, 1) == -1)
        {
            if (curconf->conf_dolog)
            {
                syslog(LOG_ERR, "prctl(): %s", strerror(errno));
            }

            fprintf(stderr, "%s: prctl(): %s\n", progname, strerror(errno));
        }
        else
        {
            enabled = true;
        }
#endif /* __linux__ */

        if (!enabled)
        {
            if (curconf->conf_dolog)
            {
                syslog(LOG_WARNING, "can't enable coredumps; continuing");
            }

            fprintf(stderr, "%s: can't enable coredumps; continuing\n",
                    progname);
        }
    }

    die = false;

    if (autorestart)
    {
        bool             quitloop = false;
        int              restarts = 0;
        int              status;
        pid_t            pid;
        pid_t            wpid;
        struct sigaction sa;

        if (dofork)
        {
            pid = fork();
            switch (pid)
            {
            case -1:
                if (curconf->conf_dolog)
                {
                    int saveerrno;

                    saveerrno = errno;

                    syslog(LOG_ERR, "fork(): %s", strerror(errno));

                    errno = saveerrno;
                }

                fprintf(stderr, "%s: fork(): %s\n", progname, strerror(errno));

                return EX_OSERR;

            case 0:
                arcf_stdio();
                break;

            default:
                return EX_OK;
            }
        }

        if (pidfile != NULL)
        {
            f = fopen(pidfile, "w");
            if (f != NULL)
            {
                fprintf(f, "%ld\n", (long) getpid());
                (void) fclose(f);
            }
            else
            {
                if (curconf->conf_dolog)
                {
                    syslog(LOG_ERR, "can't write pid to %s: %s", pidfile,
                           strerror(errno));
                }
            }
        }

        sa.sa_handler = arcf_sighandler;
        sigemptyset(&sa.sa_mask);
        sigaddset(&sa.sa_mask, SIGHUP);
        sigaddset(&sa.sa_mask, SIGINT);
        sigaddset(&sa.sa_mask, SIGTERM);
        sigaddset(&sa.sa_mask, SIGUSR1);
        sa.sa_flags = 0;

        if (sigaction(SIGHUP, &sa, NULL) != 0 ||
            sigaction(SIGINT, &sa, NULL) != 0 ||
            sigaction(SIGTERM, &sa, NULL) != 0 ||
            sigaction(SIGUSR1, &sa, NULL) != 0)
        {
            if (curconf->conf_dolog)
            {
                syslog(LOG_ERR, "[parent] sigaction(): %s", strerror(errno));
            }
        }

        /* now enact the user change */
        if (become != NULL)
        {
            /* make all the process changes */
            if (getuid() != pw->pw_uid)
            {
                if (initgroups(pw->pw_name, gid) != 0)
                {
                    if (curconf->conf_dolog)
                    {
                        syslog(LOG_ERR, "initgroups(): %s", strerror(errno));
                    }
                    fprintf(stderr, "%s: initgroups(): %s", progname,
                            strerror(errno));
                    return EX_NOPERM;
                }
                else if (setgid(gid) != 0)
                {
                    if (curconf->conf_dolog)
                    {
                        syslog(LOG_ERR, "setgid(): %s", strerror(errno));
                    }
                    fprintf(stderr, "%s: setgid(): %s", progname,
                            strerror(errno));
                    return EX_NOPERM;
                }
                else if (setuid(pw->pw_uid) != 0)
                {
                    if (curconf->conf_dolog)
                    {
                        syslog(LOG_ERR, "setuid(): %s", strerror(errno));
                    }
                    fprintf(stderr, "%s: setuid(): %s", progname,
                            strerror(errno));
                    return EX_NOPERM;
                }
            }
        }

        if (maxrestartrate_n > 0)
        {
            arcf_restart_check(maxrestartrate_n, 0);
        }

        while (!quitloop)
        {
            status = arcf_socket_cleanup(sock);
            if (status != 0)
            {
                if (curconf->conf_dolog)
                {
                    syslog(LOG_ERR, "[parent] socket cleanup failed: %s",
                           strerror(status));
                }
                return EX_UNAVAILABLE;
            }

            pid = fork();
            switch (pid)
            {
            case -1:
                if (curconf->conf_dolog)
                {
                    syslog(LOG_ERR, "fork(): %s", strerror(errno));
                }

                return EX_OSERR;

            case 0:
                sa.sa_handler = SIG_DFL;

                if (sigaction(SIGHUP, &sa, NULL) != 0 ||
                    sigaction(SIGINT, &sa, NULL) != 0 ||
                    sigaction(SIGTERM, &sa, NULL) != 0)
                {
                    if (curconf->conf_dolog)
                    {
                        syslog(LOG_ERR, "[child] sigaction(): %s",
                               strerror(errno));
                    }
                }

                quitloop = true;
                break;

            default:
                for (;;)
                {
                    wpid = wait(&status);

                    if (wpid == -1 && errno == EINTR)
                    {
                        if (die)
                        {
                            arcf_killchild(pid, diesig, curconf->conf_dolog);

                            while (wpid != pid)
                            {
                                wpid = wait(&status);
                            }

                            if (pidfile != NULL)
                            {
                                (void) unlink(pidfile);
                            }

                            exit(EX_OK);
                        }
                        else if (reload)
                        {
                            arcf_killchild(pid, SIGUSR1, curconf->conf_dolog);

                            reload = false;

                            continue;
                        }
                    }

                    if (pid != wpid)
                    {
                        continue;
                    }

                    if (wpid != -1 && curconf->conf_dolog)
                    {
                        if (WIFSIGNALED(status))
                        {
                            syslog(LOG_NOTICE,
                                   "terminated with signal %d, restarting",
                                   WTERMSIG(status));
                        }
                        else if (WIFEXITED(status))
                        {
                            if (WEXITSTATUS(status) == EX_CONFIG ||
                                WEXITSTATUS(status) == EX_SOFTWARE)
                            {
                                syslog(LOG_NOTICE, "exited with status %d",
                                       WEXITSTATUS(status));
                                quitloop = true;
                            }
                            else
                            {
                                syslog(LOG_NOTICE,
                                       "exited with status %d, restarting",
                                       WEXITSTATUS(status));
                            }
                        }
                    }

                    if (conffile != NULL)
                    {
                        reload = true;
                    }

                    break;
                }
                break;
            }

            if (maxrestarts > 0 && restarts >= maxrestarts)
            {
                if (curconf->conf_dolog)
                {
                    syslog(LOG_ERR, "maximum restart count exceeded");
                }

                return EX_UNAVAILABLE;
            }

            if (maxrestartrate_n > 0 && maxrestartrate_t > 0 &&
                !arcf_restart_check(0, maxrestartrate_t))
            {
                if (curconf->conf_dolog)
                {
                    syslog(LOG_ERR, "maximum restart rate exceeded");
                }

                return EX_UNAVAILABLE;
            }

            restarts++;
        }
    }

    if (!autorestart && dofork)
    {
        pid_t pid;

        pid = fork();
        switch (pid)
        {
        case -1:
            if (curconf->conf_dolog)
            {
                int saveerrno;

                saveerrno = errno;

                syslog(LOG_ERR, "fork(): %s", strerror(errno));

                errno = saveerrno;
            }

            fprintf(stderr, "%s: fork(): %s\n", progname, strerror(errno));

            return EX_OSERR;

        case 0:
            arcf_stdio();
            break;

        default:
            return EX_OK;
        }
    }

    /* write out the pid */
    if (!autorestart && pidfile != NULL)
    {
        f = fopen(pidfile, "w");
        if (f != NULL)
        {
            fprintf(f, "%ld\n", (long) getpid());
            (void) fclose(f);
        }
        else
        {
            if (curconf->conf_dolog)
            {
                syslog(LOG_ERR, "can't write pid to %s: %s", pidfile,
                       strerror(errno));
            }
        }
    }

    /*
    **  Block SIGUSR1 for use of our reload thread, and SIGHUP, SIGINT
    **  and SIGTERM for use of libmilter's signal handling thread.
    */

    sigemptyset(&sigset);
    sigaddset(&sigset, SIGUSR1);
    sigaddset(&sigset, SIGHUP);
    sigaddset(&sigset, SIGTERM);
    sigaddset(&sigset, SIGINT);
    status = pthread_sigmask(SIG_BLOCK, &sigset, NULL);
    if (status != 0)
    {
        if (curconf->conf_dolog)
        {
            syslog(LOG_ERR, "pthread_sigprocmask(): %s", strerror(status));
        }

        fprintf(stderr, "%s: pthread_sigprocmask(): %s\n", progname,
                strerror(status));

        return EX_OSERR;
    }

    /* now enact the user change */
    if (!autorestart && become != NULL)
    {
        /* make all the process changes */
        if (getuid() != pw->pw_uid)
        {
            if (initgroups(pw->pw_name, gid) != 0)
            {
                if (curconf->conf_dolog)
                {
                    syslog(LOG_ERR, "initgroups(): %s", strerror(errno));
                }
                fprintf(stderr, "%s: initgroups(): %s", progname,
                        strerror(errno));
                return EX_NOPERM;
            }
            else if (setgid(gid) != 0)
            {
                if (curconf->conf_dolog)
                {
                    syslog(LOG_ERR, "setgid(): %s", strerror(errno));
                }
                fprintf(stderr, "%s: setgid(): %s", progname, strerror(errno));
                return EX_NOPERM;
            }
            else if (setuid(pw->pw_uid) != 0)
            {
                if (curconf->conf_dolog)
                {
                    syslog(LOG_ERR, "setuid(): %s", strerror(errno));
                }
                fprintf(stderr, "%s: setuid(): %s", progname, strerror(errno));
                return EX_NOPERM;
            }
        }
    }

    /* initialize ARC library */
    if (!arcf_config_setlib(curconf, &p))
    {
        if (curconf->conf_dolog)
        {
            syslog(LOG_ERR, "can't configure ARC library: %s", p);
            fprintf(stderr, "%s: can't configure ARC library: %s", progname, p);
        }

        return EX_SOFTWARE;
    }

    if (filemask != -1)
    {
        (void) umask((mode_t) filemask);
    }

    if (mdebug > 0)
    {
        (void) smfi_setdbg(mdebug);
    }

    /* try to clean up the socket */
    if (sock != NULL)
    {
        status = arcf_socket_cleanup(sock);
        if (status != 0)
        {
            if (curconf->conf_dolog)
            {
                syslog(LOG_ERR, "socket cleanup failed: %s", strerror(status));
            }

            fprintf(stderr, "%s: socket cleanup failed: %s\n", progname,
                    strerror(status));

            if (!autorestart && pidfile != NULL)
            {
                (void) unlink(pidfile);
            }

            return EX_UNAVAILABLE;
        }
    }

    smfilter.xxfi_flags = SMFIF_ADDHDRS;

#ifdef SMFIF_SETSYMLIST
    smfilter.xxfi_flags |= SMFIF_SETSYMLIST;
#endif /* SMFIF_SETSYMLIST */

    /* register with the milter interface */
    if (smfi_register(smfilter) == MI_FAILURE)
    {
        if (curconf->conf_dolog)
        {
            syslog(LOG_ERR, "smfi_register() failed");
        }

        fprintf(stderr, "%s: smfi_register() failed\n", progname);

        if (!autorestart && pidfile != NULL)
        {
            (void) unlink(pidfile);
        }

        return EX_UNAVAILABLE;
    }

#ifdef HAVE_SMFI_OPENSOCKET
    /* try to establish the milter socket */
    if (!testmode && smfi_opensocket(false) == MI_FAILURE)
    {
        if (curconf->conf_dolog)
        {
            syslog(LOG_ERR, "smfi_opensocket() failed");
        }

        fprintf(stderr, "%s: smfi_opensocket() failed\n", progname);

        return EX_UNAVAILABLE;
    }
#endif /* HAVE_SMFI_OPENSOCKET */

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    /* initialize libcrypto mutexes */
    if (!curconf->conf_disablecryptoinit)
    {
        status = arcf_crypto_init();
        if (status != 0)
        {
            fprintf(stderr, "%s: error initializing crypto library: %s\n",
                    progname, strerror(status));
        }
    }
#endif /* OpenSSL < 1.1.0 */

    pthread_mutex_init(&conf_lock, NULL);
    pthread_mutex_init(&pwdb_lock, NULL);

    /* perform test mode */
    if (testfile != NULL)
    {
        status = arcf_testfiles(curconf->conf_libopenarc, testfile, verbose);
        arc_close(curconf->conf_libopenarc);
        return status;
    }

    memset(argstr, '\0', sizeof argstr);
    end = &argstr[sizeof argstr - 1];
    n = sizeof argstr;
    for (c = 1, p = argstr; c < argc && p < end; c++)
    {
        if (strchr(argv[c], ' ') != NULL)
        {
            status = snprintf(p, n, "%s \"%s\"", c == 1 ? "args:" : "",
                              argv[c]);
        }
        else
        {
            status = snprintf(p, n, "%s %s", c == 1 ? "args:" : "", argv[c]);
        }

        p += status;
        n -= status;
    }

    if (curconf->conf_dolog)
    {
        syslog(LOG_INFO, "%s v%s starting (%s)", ARCF_PRODUCT, VERSION, argstr);
    }

    /* spawn the SIGUSR1 handler */
    status = pthread_create(&rt, NULL, arcf_reloader, NULL);
    if (status != 0)
    {
        if (curconf->conf_dolog)
        {
            syslog(LOG_ERR, "pthread_create(): %s", strerror(status));
        }

        if (!autorestart && pidfile != NULL)
        {
            (void) unlink(pidfile);
        }

        return EX_OSERR;
    }

    /* call the milter mainline */
    errno = 0;
    status = smfi_main();

    if (curconf->conf_dolog)
    {
        syslog(LOG_INFO, "%s v%s terminating with status %d, errno = %d",
               ARCF_PRODUCT, VERSION, status, errno);
    }

    /* tell the reloader thread to die */
    die = true;
    (void) raise(SIGUSR1);

    if (!autorestart && pidfile != NULL)
    {
        (void) unlink(pidfile);
    }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    arcf_crypto_free();
#endif /* OpenSSL < 1.1.0 */

    arcf_config_free(curconf);

    return status;
}
