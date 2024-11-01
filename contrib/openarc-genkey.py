#!/usr/bin/env python3

# Copyright 2024 OpenARC contributors.
# See LICENSE.

import argparse
import os
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-b', '--bits',
        type=int,
        default=2048,
        help='size of RSA key to generate',
    )
    parser.add_argument(
        '-d', '--domain',
        required=True,
        help='domain name the key will be used for',
    )
    parser.add_argument(
        '-D', '--directory',
        help='directory to store the keys in',
    )
    parser.add_argument(
        '-f', '--format',
        default='zone',
        choices=['bare', 'testkey', 'text', 'zone'],
        help='output format for the public key',
    )
    parser.add_argument(
        '--fqdn',
        action='store_true',
        help='include the domain name in the DNS output',
    )
    parser.add_argument(
        '--hash-algorithms',
        help='tag the generated DNS record for use with this colon-separated list of algorithms',
    )
    parser.add_argument(
        '-n', '--note',
        help='free-form text to include in the generated DNS record'
    )
    parser.add_argument(
        '--no-subdomains',
        action='store_true',
        help='tag the generated DNS record to indicate that identities in a signature are required to be from this exact domain, not subdomains',
    )
    parser.add_argument(
        '-r', '--restrict',
        action='store_true',
        help='tag the generated DNS record to indicate that this key should only be used for email',
    )
    parser.add_argument(
        '-s', '--selector',
        required=True,
        help='selector the key will use',
    )
    parser.add_argument(
        '-t', '--type',
        default='rsa',
        choices=['rsa', 'ed25519'],
        help='type of key to generate',
    )
    parser.add_argument(
        '--testing',
        action='store_true',
        help='tag the generated DNS record to indicate that this domain is testing its deployment',
    )

    args = parser.parse_args()

    fname_base = f'{args.selector}._domainkey.{args.domain}'
    if args.directory:
        if not os.path.exists(args.directory):
            print(f'{args.directory} does not exist', file=sys.stderr)
            sys.exit(1)
        fname_base = os.path.join(args.directory, fname_base)

    binargs = [
        'openssl',
        'genpkey',
        '-algorithm', args.type,
        '-outform', 'PEM',
        '-out', f'{fname_base}.key',
    ]

    if args.type == 'rsa':
        binargs.extend(
            [
                '-pkeyopt', f'rsa_keygen_bits:{args.bits}',
            ]
        )

    res = subprocess.run(binargs, capture_output=True, text=True)
    if res.returncode != 0:
        print(f'openssl returned error code {res.returncode} while generating the private key: {res.stderr}', file=sys.stderr)
        sys.exit(1)

    binargs = [
        'openssl',
        'pkey',
        '-in', f'{fname_base}.key',
        '-inform', 'PEM',
        '-outform', 'PEM',
        '-pubout',
    ]

    res = subprocess.run(binargs, capture_output=True, text=True)
    if res.returncode != 0:
        print(f'openssl returned error code {res.returncode} while extracting the public key: {res.stderr}', file=sys.stderr)
        sys.exit(1)

    pkey = ''.join(res.stdout.splitlines()[1:-1])
    if args.type == 'ed25519':
        # This key type is published without the ASN1 prefix. Conveniently,
        # the prefix is 12 bytes so we can strip it off without decoding the
        # base64.
        pkey = pkey[16:]

    # Format the DNS record contents
    txt = f'v=DKIM1; k={args.type}'

    if args.hash_algorithms:
        txt += f'; h={args.hash_algorithms}'

    if args.note:
        txt += f'; n=\\"{args.note}\\"'

    if args.restrict:
        txt += '; s=email'

    flags = []
    if args.testing:
        flags.append('y')
    if args.no_subdomains:
        flags.append('s')
    if flags:
        txt += f'; t={":".join(flags)}'

    txt += f'; p={pkey}'

    # Write it out
    with open(f'{fname_base}.txt', 'w') as f:
        if args.format == 'bare':
            f.write(pkey)
        elif args.format in ('testkey', 'text'):
            if args.format == 'testkey':
                f.write(f'{args.selector}._domainkey.{args.domain} ')
            f.write(txt.replace('\\"', '"'))
        else:
            f.write(f'{args.selector}._domainkey')
            if args.fqdn:
                f.write(f'.{args.domain}.')
            f.write('\tIN\tTXT\t( "')
            # Individual strings within a TXT record are limited to 255 bytes
            f.write('"\n\t"'.join(txt[i:i+255] for i in range(0, len(txt), 255)))
            f.write(f'" )')
        f.write('\n')


if __name__ == '__main__':
    main()
