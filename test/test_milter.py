#!/usr/bin/env python3

import subprocess

import pytest

from email import message_from_string


mt_connect = '''
conn = mt.connect(sock)
if conn == nil then
    error("connect failed")
end

-- envelope data
if mt.conninfo(conn, "localhost", "127.0.0.1") ~= nil then
    error("conninfo failed")
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
    error("conninfo did not reply continue")
end
'''

mt_body = '''
-- eoh
if mt.eoh(conn) ~= nil then
    error("eoh failed")
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
    error("eoh did not reply continue")
end

-- body
if mt.bodystring(conn, "test body\\r\\n") ~= nil then
    error("bodystring failed")
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
    error("bodystring did not reply continue")
end

-- eom
if mt.eom(conn) ~= nil then
    error("eom failed")
end
if mt.getreply(conn) ~= SMFIR_ACCEPT then
    error("eom did not reply accept")
end

-- get header set
ar = mt.getheader(conn, "Authentication-Results", 0)
print("Authentication-Results:" .. (ar or ""))
aar = mt.getheader(conn, "ARC-Authentication-Results", 0)
print("ARC-Authentication-Results:" .. (aar or ""))
ams = mt.getheader(conn, "ARC-Message-Signature", 0)
print("ARC-Message-Signature:" .. (ams or ""))
as = mt.getheader(conn, "ARC-Seal", 0)
print("ARC-Seal:" .. (as or ""))

mt.disconnect(conn)
'''


def mt_headers(raw):
    cooked = []
    for k, v in raw:
        v = v.replace('\n', '\\n')
        cooked.append(f'''
if mt.header(conn, "{k}", "{v}") ~= nil then
    error("header({k}) failed")
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
    error("header({k}) did not reply continue")
end
''')
    return ''.join(cooked)


def msg_arc_set(msg):
    return [
        ['ARC-Authentication-Results', msg['ARC-Authentication-Results']],
        ['ARC-Message-Signature', msg['ARC-Message-Signature']],
        ['ARC-Seal', msg['ARC-Seal']],
    ]


@pytest.fixture
def run_miltertest(request, milter, milter_config):
    def _run_miltertest(headers):
        headers = headers + [
            ['From', 'user@example.com'],
            ['Date', 'Fri, 04 Oct 2024 10:11:12 -0400'],
            ['Subject', request.function.__name__],
        ]

        testprog = mt_connect + mt_headers(headers) + mt_body

        return subprocess.run(
            [
                'miltertest',
                '-D', f'sock={milter_config["sock"]}',
            ],
            input=testprog,
            capture_output=True,
            text=True,
        )

    return _run_miltertest


def test_milter_basic(run_miltertest):
    res = run_miltertest([])

    assert res.returncode == 0
    assert res.stderr == ''

    msg = message_from_string(res.stdout)

    assert msg['Authentication-Results'] == 'example.com; arc=none smtp.remote-ip=127.0.0.1'
    assert msg['ARC-Authentication-Results'] == 'i=1; example.com; arc=none'
    assert 'ARC-Message-Signature' in msg
    assert 'cv=none' in msg['ARC-Seal']


def test_milter_resign(run_miltertest):
    res = run_miltertest([])
    msg = message_from_string(res.stdout)

    headers = []
    for i in range(2, 52):
        headers = msg_arc_set(msg) + [['Authentication-Results', msg['Authentication-Results']]] + headers

        res = run_miltertest(headers)

        assert res.returncode == 0
        assert res.stderr == ''

        msg = message_from_string(res.stdout)

        assert msg['Authentication-Results'] == 'example.com; arc=pass smtp.remote-ip=127.0.0.1'

        if i <= 50:
            assert msg['ARC-Authentication-Results'] == f'i={i}; example.com; arc=pass'
            assert 'cv=pass' in msg['ARC-Seal']
        else:
            assert msg['ARC-Authentication-Results'] == ''
            assert msg['ARC-Message-Signature'] == ''
            assert msg['ARC-Seal'] == ''


def test_milter_mode_s(run_miltertest):
    res = run_miltertest([])

    assert res.returncode == 0
    assert res.stderr == ''

    msg = message_from_string(res.stdout)

    assert msg['Authentication-Results'] == ''
    assert msg['ARC-Authentication-Results'] == 'i=1; example.com; arc=none'
    assert 'ARC-Message-Signature' in msg
    assert 'cv=none' in msg['ARC-Seal']


def test_milter_mode_v(run_miltertest):
    res = run_miltertest([])

    assert res.returncode == 0
    assert res.stderr == ''

    msg = message_from_string(res.stdout)

    assert msg['Authentication-Results'] == 'example.com; arc=none smtp.remote-ip=127.0.0.1'
    assert msg['ARC-Authentication-Results'] == ''
    assert msg['ARC-Message-Signature'] == ''
    assert msg['ARC-Seal'] == ''


def test_milter_ar(run_miltertest):
    res = run_miltertest([])
    msg = message_from_string(res.stdout)

    # override the result to "fail"
    headers = msg_arc_set(msg)
    res = run_miltertest(headers + [['Authentication-Results', 'example.com; arc=fail']])

    msg = message_from_string(res.stdout)
    assert msg['Authentication-Results'] == 'example.com; arc=fail smtp.remote-ip=127.0.0.1'
    assert msg['ARC-Authentication-Results'] == 'i=2; example.com; arc=fail'
    assert 'cv=fail' in msg['ARC-Seal']

    # override the result to "pass"
    headers = msg_arc_set(msg) + headers
    res = run_miltertest(headers + [['Authentication-Results', 'example.com; arc=pass']])

    # the chain is dead because it came in as failed, no matter what A-R says
    msg = message_from_string(res.stdout)
    assert msg['Authentication-Results'] == 'example.com; arc=fail smtp.remote-ip=127.0.0.1'
    assert msg['ARC-Authentication-Results'] == ''
    assert msg['ARC-Message-Signature'] == ''
    assert msg['ARC-Seal'] == ''


def test_milter_ar_multi(run_miltertest):
    res = run_miltertest([])
    msg = message_from_string(res.stdout)

    # make sure older headers don't override
    headers = [
        ['Authentication-Results', 'example.com; arc=pass'],
        ['Authentication-Results', 'example.com; arc=fail'],
    ] + msg_arc_set(msg)
    res = run_miltertest(headers)

    msg = message_from_string(res.stdout)
    assert msg['Authentication-Results'] == 'example.com; arc=pass smtp.remote-ip=127.0.0.1'
    assert msg['ARC-Authentication-Results'] == 'i=2; example.com; arc=pass'


def test_milter_peerlist(run_miltertest):
    res = run_miltertest([])
    assert res.returncode == 1
    assert res.stdout == ''
    assert res.stderr == 'miltertest: (stdin): [string "(stdin)"]:12: conninfo did not reply continue\n'
