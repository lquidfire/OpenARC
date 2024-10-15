/*
**  Copyright (c) 2007-2009 Sendmail, Inc. and its suppliers.
**	All rights reserved.
**
**  Copyright (c) 2009, 2011-2014, 2016, 2017, The Trusted Domain Project.
**    All rights reserved.
*/

#include "build-config.h"

/* system includes */
#include <sys/types.h>
#include <sys/param.h>
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#endif /* HAVE_STDBOOL_H */
#include <ctype.h>
#include <assert.h>
#include <string.h>
#ifdef ARTEST
# include <sysexits.h>
#endif /* ARTEST */

/* libbsd if found */
#ifdef USE_BSD_H
# include <bsd/string.h>
#endif /* USE_BSD_H */

/* libstrl if needed */
#ifdef USE_STRL_H
# include <strl.h>
#endif /* USE_STRL_H */

/* openarc includes */
#include "openarc-ar.h"

/* macros */
#define	ARES_ENDOF(x)		((x) + sizeof(x) - 1)
#define	ARES_STRORNULL(x)	((x) == NULL ? "(null)" : (x))
#define	ARES_TOKENS		";=."
#define	ARES_TOKENS2		"=."

#define	ARES_MAXTOKENS		1024

/* tables */
struct lookup
{
	char *	str;
	int	code;
};

struct lookup methods[] =
{
	{ "arc",		ARES_METHOD_ARC },
	{ "auth",		ARES_METHOD_AUTH },
	{ "dkim",		ARES_METHOD_DKIM },
	{ "dkim-adsp",		ARES_METHOD_DKIMADSP },
	{ "dkim-atps",		ARES_METHOD_DKIMATPS },
	{ "dmarc",		ARES_METHOD_DMARC },
	{ "dnswl",		ARES_METHOD_DNSWL },
	{ "domainkeys",		ARES_METHOD_DOMAINKEYS },
	{ "iprev",		ARES_METHOD_IPREV },
	{ "rrvs",		ARES_METHOD_RRVS },
	{ "sender-id",		ARES_METHOD_SENDERID },
	{ "smime",		ARES_METHOD_SMIME },
	{ "spf",		ARES_METHOD_SPF },
	{ "vbr",		ARES_METHOD_VBR },
	{ NULL,			ARES_METHOD_UNKNOWN }
};

struct lookup aresults[] =
{
	{ "discard",		ARES_RESULT_DISCARD },
	{ "fail",		ARES_RESULT_FAIL },
	{ "neutral",		ARES_RESULT_NEUTRAL },
	{ "none",		ARES_RESULT_NONE },
	{ "nxdomain",		ARES_RESULT_NXDOMAIN },
	{ "pass",		ARES_RESULT_PASS },
	{ "permerror",		ARES_RESULT_PERMERROR },
	{ "policy",		ARES_RESULT_POLICY },
	{ "signed",		ARES_RESULT_SIGNED },
	{ "softfail",		ARES_RESULT_SOFTFAIL },
	{ "temperror",		ARES_RESULT_TEMPERROR },
	{ "unknown",		ARES_RESULT_UNKNOWN },
	{ NULL,			ARES_RESULT_UNDEFINED }
};

struct lookup ptypes[] =
{
	{ "body",		ARES_PTYPE_BODY },
	{ "dns",		ARES_PTYPE_DNS },
	{ "header",		ARES_PTYPE_HEADER },
	{ "policy",		ARES_PTYPE_POLICY },
	{ "smtp",		ARES_PTYPE_SMTP },
	{ NULL,			ARES_PTYPE_UNKNOWN }
};


enum ar_parser_state {
	ARP_STATE_AUTHSERVID,
	ARP_STATE_AUTHRESVERSION_OR_AUTHSERVID,
	ARP_STATE_RESINFO,
	ARP_STATE_METHODSPEC,
	ARP_STATE_METHODSPEC_EQUALS,
	ARP_STATE_RESULT,
	ARP_STATE_REASONSPEC_EQUALS,
	ARP_STATE_REASONSPEC_VALUE,
	ARP_STATE_PROP_OR_REASON,
	ARP_STATE_PTYPE,
	ARP_STATE_PROPSPEC_DOT,
	ARP_STATE_PROPERTY,
	ARP_STATE_PROPSPEC_EQUALS,
	ARP_STATE_PVALUE,
	ARP_STATE_DONE,
};

/*
**  ARES_TOKENIZE -- tokenize a string
**
**  Parameters:
**  	input -- input string
**  	outbuf -- output buffer
**  	outbuflen -- number of bytes available at "outbuf"
**  	tokens -- array of token pointers
**  	ntokens -- number of token pointers available at "tokens"
**
**  Return value:
**  	-1 -- bad syntax or not enough space at "outbuf" for tokenizing
**  	other -- number of tokens identified; may be greater than
**  	"ntokens" if there were more tokens found than there were
**  	pointers available.
*/

static int
ares_tokenize(const char *input, char *outbuf, size_t outbuflen,
              char **tokens, int ntokens)
{
	_Bool quoted = FALSE;
	_Bool escaped = FALSE;
	_Bool intok = FALSE;
	int n = 0;
	int parens = 0;
	char *q;
	char *end;

	assert(input != NULL);
	assert(outbuf != NULL);
	assert(outbuflen > 0);
	assert(tokens != NULL);
	assert(ntokens > 0);

	q = outbuf;
	end = outbuf + outbuflen - 1;

	for (const char *p = input; *p != '\0' && q <= end; p++)
	{
		if (escaped)				/* escape */
		{
			if (!intok)
			{
				if (n < ntokens)
					tokens[n] = q;
				intok = TRUE;
			}

			if (*p == '\\' || *p == '"') {
				/* Needs to remain escaped. */
				*q = '\\';
				q++;
			}
			*q = *p;
			q++;
			escaped = FALSE;
		}
		else if (*p == '\\' && quoted)			/* escape */
		{
			escaped = TRUE;
		}
		else if (*p == '"' && parens == 0)	/* quoting */
		{
			quoted = !quoted;

			if (!intok)
			{
				if (n < ntokens)
					tokens[n] = q;
				intok = TRUE;
			}
		}
		else if (*p == '(' && !quoted)		/* "(" (comment) */
		{
			parens++;

			if (!intok)
			{
				if (n < ntokens)
					tokens[n] = q;
				intok = TRUE;
			}

			*q = *p;
			q++;

		}
		else if (*p == ')' && !quoted)		/* ")" (comment) */
		{
			if (parens > 0)
			{
				parens--;

				if (parens == 0)
				{
					intok = FALSE;
					n++;

					*q = ')';
					q++;
					if (q <= end)
					{
						*q = '\0';
						q++;
					}
				}
			}
		}
		else if (quoted)			/* quoted character */
		{
			*q = *p;
			q++;
		}
		else if (isascii(*p) && isspace(*p))	/* whitespace */
		{
			if (intok)
			{
				if (quoted)
				{
					*q = *p;
					q++;
				}
				else if (parens > 0)
				{
					/* turn all whitespace in comments into single spaces */
					*q = ' ';
					q++;
					while isspace(p[1])
					{
						p++;
					}
				}
				else
				{
					intok = FALSE;
					*q = '\0';
					q++;
					n++;
				}
			}
		}
		else if (strchr(ARES_TOKENS, *p) != NULL) /* delimiter */
		{
			if (parens > 0)
			{
				*q = *p;
				q++;
				continue;
			}

			if (intok)
			{
				intok = FALSE;
				*q = '\0';
				q++;
				n++;
			}

			if (q <= end)
			{
				*q = *p;
				if (n < ntokens)
				{
					tokens[n] = q;
					n++;
				}
				q++;
			}

			if (q <= end)
			{
				*q = '\0';
				q++;
			}
		}
		else					/* other */
		{
			if (!intok)
			{
				if (n < ntokens)
					tokens[n] = q;
				intok = TRUE;
			}

			*q = *p;
			q++;
		}
	}

	if (quoted || parens > 0)
	{
		return -1;
	}

	if (q >= end)
	{
		return -1;
	}

	if (intok)
	{
		*q = '\0';
		n++;
	}

	return n;
}

/*
**  ARES_CONVERT -- convert a string to its code
**
**  Parameters:
**  	table -- in which table to look up
**  	str -- string to find
**
**  Return value:
**  	A code translation of "str".
*/

static int
ares_convert(struct lookup *table, char *str)
{
	int c;

	assert(table != NULL);
	assert(str != NULL);

	for (c = 0; ; c++)
	{
		if (table[c].str == NULL ||
		    strcasecmp(table[c].str, str) == 0)
			return table[c].code;
	}

	/* NOTREACHED */
}

/*
**  ARES_XCONVERT -- convert a code to its string
**
**  Parameters:
**  	table -- in which table to look up
**  	code -- code to find
**
**  Return value:
**  	A string translation of "code".
*/

static char *
ares_xconvert(struct lookup *table, int code)
{
	int c;

	assert(table != NULL);

	for (c = 0; ; c++)
	{
		if (table[c].str == NULL || table[c].code == code)
			return table[c].str;
	}

	/* NOTREACHED */
}

/*
**  ARES_METHOD_ADD -- add a parsed method to the results if there's room
**  and we haven't already seen it.
**
**  Parameters:
**  	ar -- authentication results
**	r -- result to add
**
**  Return value:
**  	Whether the method was added
*/

static _Bool
ares_method_add(struct authres *ar, struct result *r)
{
	if (r->result_method == ARES_METHOD_UNKNOWN || ar->ares_count >= MAXARESULTS)
	{
		return FALSE;
	}
	if (r->result_method != ARES_METHOD_DKIM)
	{
		for (int i = 0; i < ar->ares_count; i++)
		{
			if (ar->ares_result[i].result_method == r->result_method)
			{
				return FALSE;
			}
		}
	}

	memcpy(ar->ares_result + ar->ares_count, r, sizeof ar->ares_result[ar->ares_count]);
	ar->ares_count++;
	return TRUE;
}

/*
**  ARES_PARSE -- parse an Authentication-Results: header, return a
**                structure containing a parsed result
**
**  Parameters:
**  	hdr -- NULL-terminated contents of an Authentication-Results:
**  	       header field
**  	ar -- a pointer to a (struct authres) loaded by values after parsing
**	authserv -- string containing the authserv-id we care about
**
**  Return value:
**  	0 on success, -1 on failure, -2 when a header is uninteresting.
*/

int
ares_parse(const char *hdr, struct authres *ar, const char *authserv)
{
	int ntoks;
	enum ar_parser_state state;
	enum ar_parser_state prevstate;
	ares_method m;
	char tmp[ARC_MAXHEADER + 2];
	char *tokens[ARES_MAXTOKENS];
	char ares_host[ARC_MAXHOSTNAMELEN + 1];
	struct result cur;
	int initial_ares_count;

	assert(hdr != NULL);
	assert(ar != NULL);

	memset(tmp, '\0', sizeof tmp);
	memset(&cur, '\0', sizeof cur);
	memset(ares_host, '\0', sizeof ares_host);

	ntoks = ares_tokenize(hdr, tmp, sizeof tmp, tokens, ARES_MAXTOKENS);
	if (ntoks == -1 || ntoks > ARES_MAXTOKENS)
		return -1;

	prevstate = ARP_STATE_AUTHSERVID;
	state = ARP_STATE_AUTHSERVID;
	initial_ares_count = ar->ares_count;

	for (int c = 0; c < ntoks; c++)
	{
		if (tokens[c][0] == '(')
		{
			/* Comments are valid in a lot of places, but we're
			 * only interested in storing ones that are placed
			 * like properties
			 */
			if (cur.result_props < MAXPROPS &&
			    (state == ARP_STATE_PROP_OR_REASON ||
			    state == ARP_STATE_PTYPE)) {
				cur.result_ptype[cur.result_props] = ARES_PTYPE_COMMENT;
				strlcpy((char *) cur.result_value[cur.result_props],
				        (char *) tokens[c],
				        sizeof cur.result_value[cur.result_props]);
				cur.result_props++;
			}
			continue;
		}

		switch (state)
		{
		  case ARP_STATE_AUTHSERVID:
			if (!isascii(tokens[c][0]) || !isalnum(tokens[c][0]))
			{
				ar->ares_count = initial_ares_count;
				return -1;
			}


			if (tokens[c][0] == ';')
			{
				prevstate = state;
				state = ARP_STATE_METHODSPEC;
			}
			else
			{
				strlcat((char *) ares_host, (char *) tokens[c], sizeof ares_host);

				prevstate = state;
				state = ARP_STATE_AUTHRESVERSION_OR_AUTHSERVID;
			}

			break;

		  case ARP_STATE_AUTHRESVERSION_OR_AUTHSERVID:
			if (tokens[c][0] == '.' &&
			    tokens[c][1] == '\0' && prevstate == ARP_STATE_AUTHSERVID)
			{
				strlcat((char *) ares_host, (char *) tokens[c], sizeof ares_host);

				prevstate = state;
				state = ARP_STATE_AUTHSERVID;

				break;
			}

			/* We've successfully assembled the authserv-id,
			 * see if it's what we're looking for.
			 */
			if (authserv && strcasecmp(authserv, ares_host) != 0)
			{
				ar->ares_count = initial_ares_count;
				return -2;
			}
			strlcpy(ar->ares_host, ares_host, sizeof ar->ares_host);

			if (tokens[c][0] == ';')
			{
				prevstate = state;
				state = ARP_STATE_METHODSPEC;
			}
			else if (isascii(tokens[c][0]) &&
			         isdigit(tokens[c][0]))
			{
				strlcpy((char *) ar->ares_version,
				        (char *) tokens[c],
				        sizeof ar->ares_version);

				prevstate = state;
				state = ARP_STATE_RESINFO;
			}
			else
			{
				ar->ares_count = initial_ares_count;
				return -1;
			}

			break;

		  case ARP_STATE_RESINFO:
			if (tokens[c][0] != ';' || tokens[c][1] != '\0')
			{
				ar->ares_count = initial_ares_count;
				return -1;
			}

			prevstate = state;
			state = ARP_STATE_METHODSPEC;

			break;

		  case ARP_STATE_METHODSPEC:
			if (strcasecmp((char *) tokens[c], "none") == 0)
			{
				switch (prevstate)
				{
				  case ARP_STATE_AUTHSERVID:
				  case ARP_STATE_AUTHRESVERSION_OR_AUTHSERVID:
				  case ARP_STATE_RESINFO:
					prevstate = state;
					state = ARP_STATE_DONE;
					continue;
				 default:
					/* should not have other resinfo */
					ar->ares_count = initial_ares_count;
					return -1;
				}
			}

			memset(&cur, '\0', sizeof cur);

			m = ares_convert(methods, (char *) tokens[c]);

			cur.result_method = m;
			prevstate = state;
			state = ARP_STATE_METHODSPEC_EQUALS;

			break;

		  case ARP_STATE_METHODSPEC_EQUALS:
			if (tokens[c][0] != '=' || tokens[c][1] != '\0')
			{
				ar->ares_count = initial_ares_count;
				return -1;
			}

			prevstate = state;
			state = ARP_STATE_RESULT;

			break;

		  case ARP_STATE_RESULT:
			cur.result_result = ares_convert(aresults, (char *) tokens[c]);
			prevstate = state;
			state = ARP_STATE_PROP_OR_REASON;

			break;

		  case ARP_STATE_REASONSPEC_EQUALS:
			if (tokens[c][0] != '=' || tokens[c][1] != '\0')
			{
				ar->ares_count = initial_ares_count;
				return -1;
			}
			prevstate = state;
			state = ARP_STATE_REASONSPEC_VALUE;

			break;

		  case ARP_STATE_REASONSPEC_VALUE:
			strlcpy((char *) cur.result_reason, (char *) tokens[c], sizeof cur.result_reason);

			prevstate = state;
			state = ARP_STATE_PTYPE;

			break;

		  case ARP_STATE_PROP_OR_REASON:
			if (tokens[c][0] == ';' &&	/* neither */
			    tokens[c][1] == '\0')
			{
				ares_method_add(ar, &cur);
				memset(&cur, '\0', sizeof cur);
				prevstate = state;
				state = ARP_STATE_METHODSPEC;

				continue;
			}

			if (strcasecmp((char *) tokens[c], "reason") == 0)
			{				/* reason */
				prevstate = state;
				state = ARP_STATE_REASONSPEC_EQUALS;
				continue;
			}
			else
			{
				prevstate = state;
				state = ARP_STATE_PTYPE;
			}

			/* FALLTHROUGH */

		  case ARP_STATE_PTYPE:
			if (prevstate == ARP_STATE_PVALUE &&
			    strchr(ARES_TOKENS2, tokens[c][0]) != NULL &&
			    tokens[c][1] == '\0')
			{
				/* actually a part of the previous value */
				cur.result_props--;
				strlcat((char *) cur.result_value[cur.result_props],
				        (char *) tokens[c],
				        sizeof cur.result_value[cur.result_props]);

				prevstate = state;
				state = ARP_STATE_PVALUE;
				continue;
			}

			if (tokens[c][0] == ';' &&
			    tokens[c][1] == '\0')
			{
				ares_method_add(ar, &cur);
				memset(&cur, '\0', sizeof(cur));
				prevstate = state;
				state = ARP_STATE_METHODSPEC;
				continue;
			}
			else
			{
				ares_ptype x;

				x = ares_convert(ptypes, (char *) tokens[c]);
				if (x == ARES_PTYPE_UNKNOWN)
				{
					ar->ares_count = initial_ares_count;
					return -1;
				}

				if (cur.result_props < MAXPROPS)
				{
					cur.result_ptype[cur.result_props] = x;
				}

				prevstate = state;
				state = ARP_STATE_PROPSPEC_DOT;
			}

			break;

		  case ARP_STATE_PROPSPEC_DOT:
			if (tokens[c][0] != '.' || tokens[c][1] != '\0')
			{
				ar->ares_count = initial_ares_count;
				return -1;
			}

			prevstate = state;
			state = ARP_STATE_PROPERTY;

			break;

		  case ARP_STATE_PROPERTY:
			if (cur.result_props < MAXPROPS)
			{
				strlcpy((char *) cur.result_property[cur.result_props],
				        (char *) tokens[c],
				        sizeof cur.result_property[cur.result_props]);
			}

			prevstate = state;
			state = ARP_STATE_PROPSPEC_EQUALS;

			break;

		  case ARP_STATE_PROPSPEC_EQUALS:
			if (tokens[c][0] != '=' || tokens[c][1] != '\0')
			{
				ar->ares_count = initial_ares_count;
				return -1;
			}

			prevstate = state;
			state = ARP_STATE_PVALUE;

			break;

		  case ARP_STATE_PVALUE:
			if (cur.result_props < MAXPROPS)
			{
				strlcat((char *) cur.result_value[cur.result_props],
				        (char *) tokens[c],
				        sizeof cur.result_value[cur.result_props]);
				cur.result_props++;
			}

			prevstate = state;
			state = ARP_STATE_PTYPE;

			break;

		  case ARP_STATE_DONE:
			/* unexpected content after a singleton value */
			ar->ares_count = initial_ares_count;
			return -1;
		}
	}

	/* error out on non-terminal states */
	if (state != ARP_STATE_METHODSPEC &&
	    state != ARP_STATE_PROP_OR_REASON &&
	    state != ARP_STATE_PTYPE &&
	    state != ARP_STATE_DONE)
	{
		ar->ares_count = initial_ares_count;
		return -1;
	}

	ares_method_add(ar, &cur);

	return 0;
}

/*
**  ARES_ISTOKEN -- check whether a string is a valid token
**
**  Parameters:
**	str -- string to check
**
**  Return value:
**	TRUE if the string contains no characters that require quoting,
**      FALSE otherwise.
*/
_Bool
ares_istoken(const char *str)
{
	for (const char *c = str; *c != '\0'; c++)
	{
		if (iscntrl(*c)) {
			return FALSE;
		}
		/* ' ' and tspecials from RFC 2045 except @
		 * (local-part@domain-name doesn't require quoting)
		 */
		if (strchr(" ()<>,;:\\\"/[]?=", *c) != NULL) {
			return FALSE;
		}
	}
	return TRUE;
}

/*
**  ARES_GETMETHOD -- translate a method code to its name
**
**  Parameters:
**  	method -- method to convert
**
**  Return value:
**  	String matching the provided method, or NULL.
*/

const char *
ares_getmethod(ares_method method)
{
	return (const char *) ares_xconvert(methods, method);
}

/*
**  ARES_GETRESULT -- translate a result code to its name
**
**  Parameters:
**  	result -- result to convert
**
**  Return value:
**  	String matching the provided result, or NULL.
*/

const char *
ares_getresult(ares_result result)
{
	return (const char *) ares_xconvert(aresults, result);
}

/*
**  ARES_GETPTYPE -- translate a ptype code to its name
**
**  Parameters:
**  	ptype -- ptype to convert
**
**  Return value:
**  	String matching the provided ptype, or NULL.
*/

const char *
ares_getptype(ares_ptype ptype)
{
	return (const char *) ares_xconvert(ptypes, ptype);
}

#ifdef ARTEST
/*
**  MAIN -- program mainline
**
**  Parameters:
**  	argc, argv -- the usual
**
**  Return value:
**  	EX_USAGE or EX_OK
*/

int
main(int argc, char **argv)
{
	int c;
	int d;
	int status;
	char *p;
	char *progname;
	struct authres ar;
	u_char buf[ARC_MAXHEADER + 2];
	u_char *toks[ARES_MAXTOKENS];

	progname = (p = strrchr(argv[0], '/')) == NULL ? argv[0] : p + 1;

	if (argc != 2)
	{
		printf("%s: usage: %s header-value\n", progname, progname);
		return EX_USAGE;
	}

	c = ares_tokenize(((u_char **)argv)[1], buf, sizeof buf, toks,
	                  ARES_MAXTOKENS);
	for (d = 0; d < c; d++)
		printf("token %d = '%s'\n", d, toks[d]);

	printf("\n");

	status = ares_parse(((u_char **)argv)[1], &ar, NULL);
	if (status == -1)
	{
		printf("%s: ares_parse() returned -1\n", progname);
		return EX_OK;
	}

	printf("%d result%s found\n", ar.ares_count,
	       ar.ares_count == 1 ? "" : "s");

	printf("authserv-id '%s'\n", ar.ares_host);
	printf("version '%s'\n", ar.ares_version);

	for (c = 0; c < ar.ares_count; c++)
	{
		printf("result #%d, %d propert%s\n", c,
		       ar.ares_result[c].result_props,
		       ar.ares_result[c].result_props == 1 ? "y" : "ies");

		printf("\tmethod \"%s\"\n",
		       ares_xconvert(methods,
		                     ar.ares_result[c].result_method));
		printf("\tresult \"%s\"\n",
		       ares_xconvert(aresults,
		                     ar.ares_result[c].result_result));
		printf("\treason \"%s\"\n", ar.ares_result[c].result_reason);
		printf("\tcomment \"%s\"\n", ar.ares_result[c].result_comment);

		for (d = 0; d < ar.ares_result[c].result_props; d++)
		{
			printf("\tproperty #%d\n", d);
			printf("\t\tptype \"%s\"\n",
			       ares_xconvert(ptypes,
			                     ar.ares_result[c].result_ptype[d]));
			printf("\t\tproperty \"%s\"\n",
			       ar.ares_result[c].result_property[d]);
			printf("\t\tvalue \"%s\"\n",
			       ar.ares_result[c].result_value[d]);
		}
	}
}
#endif /* ARTEST */
