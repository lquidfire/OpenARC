#!/usr/bin/env python3

import json
import pathlib
import subprocess
import time

import pytest


@pytest.fixture(scope='session')
def private_key(tmp_path_factory, tool_path):
    basepath = tmp_path_factory.mktemp('keys')

    for s, d in [
        ['elpmaxe', 'example.com'],
        ['xn--2j5b', 'xn--vv4b606a.example.com'],
        ['unsafe', 'example.com'],
    ]:
        binargs = [
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

    testkeys = (
        'sel._domainkey.dkimpy.example.com v=DKIM1; k=rsa; '
        'p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqf/MoqRqzK3/bcCyLSx5'
        'CDvyPotNDBjLLFHdMmcWDiSZ8saslFyNR6FkFxuNtw843m7MkwOSJ9TRd9p+OoRLDv'
        'H0jDR1Dqq22QOJKiG5XQ91aZwin9jpWKkuoRoRZRhWrzUOJWAybHarsEQm9iCPh2zn'
        'dbSPSzPQL1OsjURIuw5G9+/nr5rhJ72Qi6v86zofWUKdXhLf+oVmho79D0xGMFFm0f'
        'b98xIeZlgJTnmrj/zuxIKHeVmGKI1j6L3xttdcDiUVRGxoubkFzg9TIBGhdeFkpa0C'
        'ZuhB/1/U3f1oG3Upx5o/jXTQk/dwVaaeEXnRmTsfGYn4GQ9ziity1ijLsQIDAQAB\n'
    )

    for fname in [
        'elpmaxe._domainkey.example.com.txt',
        'xn--2j5b._domainkey.xn--vv4b606a.example.com.txt',
    ]:
        with open(basepath.joinpath(fname), 'r') as f:
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

    config = {
        'Domain': 'example.com',
        'AuthservID': 'example.com',
        'TestKeys': private_key['public_keys'],
        'Selector': 'elpmaxe',
        'KeyFile': 'elpmaxe._domainkey.example.com.key',
        'Mode': 'sv',
        'FixedTimestamp': '1234567890',
        'RequireSafeKeys': 'false',  # tmp is world writeable
    }

    for candidate in [
        request.path.name,  # test file
        request.function.__name__,  # test function
    ]:
        fname = base_path.joinpath(f'{candidate}.conf')
        if fname.exists():
            config.update(json.loads(fname.read_text()))

    if config['KeyFile']:
        config['KeyFile'] = private_key['basepath'].joinpath(config['KeyFile'])

    for static_file in ['PeerList', 'InternalHosts']:
        if config.get(static_file):
            config[static_file] = base_path.joinpath(config[static_file])

    fname = tmp_path.joinpath('milter.conf')
    with open(fname, 'w') as f:
        for k, v in config.items():
            if v is not None:
                f.write(f'{k} {v}\n')

    return {
        'file': fname,
        'sock': tmp_path.joinpath('milter.sock'),
    }


@pytest.fixture()
def milter_cmdline(tmp_path, tool_path, milter_config):
    return [
        tool_path('openarc/openarc'),
        '-f',
        '-v',
        '-c',
        milter_config['file'],
        '-p',
        milter_config['sock'],
    ]


@pytest.fixture()
def milter(milter_cmdline, milter_config):
    milter_proc = subprocess.Popen(milter_cmdline)
    while not milter_proc.poll() and not milter_config['sock'].exists():
        time.sleep(0.1)

    yield milter_proc

    milter_proc.terminate()
