#!/usr/bin/env python3

import copy
import json
import pathlib
import socket
import subprocess
import sys
import time

import miltertest
import pytest


@pytest.fixture(scope='session')
def private_key(tmp_path_factory, tool_path):
    basepath = tmp_path_factory.mktemp('keys')

    selectors = [
        ['elpmaxe', 'example.com'],
        ['xn--2j5b', 'xn--vv4b606a.example.com'],
        ['dkimpy', 'example.com'],
        ['perl', 'example.com'],
    ]

    for s, d in [
        *selectors,
        ['unsafe', 'example.com'],
    ]:
        binargs = [
            sys.executable,
            tool_path('contrib/openarc-keygen'),
            '-D',
            str(basepath),
            '-d',
            d,
            '-s',
            s,
            '--hash-algorithms',
            'sha256',
            '-f',
            'testkey',
        ]
        subprocess.run(binargs, check=True)

    basepath.joinpath('unsafe._domainkey.example.com.key').chmod(0o644)

    testkeys = ''
    for s, d in selectors:
        with open(basepath.joinpath(f'{s}._domainkey.{d}.txt'), 'r') as f:
            testkeys += f.read()

    keyfile = basepath.joinpath('public.key')
    with open(keyfile, 'w') as f:
        f.write(testkeys)

    return {
        'basepath': basepath,
        'public_keys': str(keyfile),
    }


@pytest.fixture(scope='session')
def tool_path():
    def _tool_path(tool):
        return pathlib.Path(__file__).parent.parent.joinpath(tool).absolute()

    return _tool_path


@pytest.fixture()
def milter_config(request, tmp_path, private_key):
    base_path = request.path.parent.joinpath('files')

    base_config = {
        'Domain': 'example.com',
        'AuthservID': 'example.com',
        'TestKeys': private_key['public_keys'],
        'Selector': 'elpmaxe',
        'KeyFile': 'elpmaxe._domainkey.example.com.key',
        'Mode': 'sv',
        'FixedTimestamp': '1234567890',
        'PermitAuthenticationOverrides': 'true',
        'RequireSafeKeys': 'false',  # tmp is world writeable
    }

    config = [base_config.copy()]

    for candidate in [
        request.path.name,  # test file
        request.function.__name__,  # test function
    ]:
        fname = base_path.joinpath(f'{candidate}.conf')
        if fname.exists():
            new_config = json.loads(fname.read_text())
            if isinstance(new_config, list):
                for i, upd in enumerate(new_config):
                    if i >= len(config):
                        config.append(base_config.copy())
                    config[i].update(upd)
            else:
                for i in range(0, len(config)):
                    config[i].update(new_config)

    ret = []
    for i, c in enumerate(config):
        if c['KeyFile']:
            c['KeyFile'] = private_key['basepath'].joinpath(c['KeyFile'])

        for static_file in ['PeerList', 'InternalHosts']:
            if c.get(static_file):
                c[static_file] = base_path.joinpath(c[static_file])

        fname = tmp_path.joinpath(f'milter-{i}.conf')
        with open(fname, 'w') as f:
            for k, v in c.items():
                if v is not None:
                    f.write(f'{k} {v}\n')

        ret.append({'file': fname, 'sock': tmp_path.joinpath(f'milter-{i}.sock')})

    return ret


@pytest.fixture()
def milter_cmdline(tmp_path, tool_path):
    def _milter_cmdline(conf, extra_args=None):
        args = [
            tool_path('openarc/openarc'),
            '-f',
            '-v',
            '-c',
            conf['file'],
            '-p',
            conf['sock'],
        ]
        if extra_args:
            args.extend(extra_args)
        return args

    return _milter_cmdline


@pytest.fixture()
def milter(milter_cmdline, milter_config):
    milter_procs = []

    for i in range(0, len(milter_config)):
        proc = subprocess.Popen(milter_cmdline(milter_config[i]))
        while not proc.poll() and not milter_config[i]['sock'].exists():
            time.sleep(0.1)
        milter_procs.append(proc)

    yield milter_procs

    for proc in milter_procs:
        proc.terminate()


@pytest.fixture
def run_miltertest(request, milter, milter_config):
    def _run_miltertest(
        headers=None,
        standard_headers=True,
        body='test body\r\n',
        protocol=miltertest.SMFI_V6_PROT,
        milter_instance=0,
    ):
        headers = copy.copy(headers) or []
        if standard_headers:
            headers.extend(
                [
                    ['From', ' user@example.com'],
                    ['Date', ' Fri, 04 Oct 2024 10:11:12 -0400'],
                    ['Subject', request.function.__name__],
                ]
            )

        # Connect
        sock = socket.socket(family=socket.AF_UNIX)
        sock.connect(bytes(milter_config[milter_instance]['sock']))
        conn = miltertest.MilterConnection(sock)
        conn.optneg_mta(protocol=protocol)
        conn.send(miltertest.SMFIC_CONNECT, hostname='localhost', address='127.0.0.1', family=miltertest.SMFIA_INET, port=666)
        conn.send(miltertest.SMFIC_HELO, helo='mx.example.com')

        # Envelope data
        conn.send(miltertest.SMFIC_MAIL, args=['<sender@example.com>'])
        conn.send(miltertest.SMFIC_RCPT, args=['<recipient@example.com>'])

        # Send headers
        conn.send(miltertest.SMFIC_DATA)
        conn.send_headers(headers)
        conn.send(miltertest.SMFIC_EOH)

        # Send body
        conn.send_body(body)
        resp = conn.send_eom()
        ins_headers = []
        for msg in resp:
            if msg[0] == miltertest.SMFIR_INSHEADER:
                # Check for invalid characters
                assert '\r' not in msg[1]['value']
                # Check for proper wrapping
                if msg[1]['name'] in ['ARC-Message-Signature', 'ARC-Seal']:
                    assert not any(len(x) > 78 for x in msg[1]['value'].splitlines())
                ins_headers.insert(msg[1]['index'], [msg[1]['name'], msg[1]['value']])
            elif msg[0] in miltertest.DISPOSITION_REPLIES:
                assert msg[0] == miltertest.SMFIR_ACCEPT
            else:
                pytest.fail(f'Unexpected EOM response {msg}')

        return {
            'headers': ins_headers,
            'msg_headers': headers,
            'msg_body': body,
        }

    return _run_miltertest
