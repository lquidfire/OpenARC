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
print("Authentication-Results:" .. ar)
aar = mt.getheader(conn, "ARC-Authentication-Results", 0)
print("ARC-Authentication-Results:" .. aar)
ams = mt.getheader(conn, "ARC-Message-Signature", 0)
print("ARC-Message-Signature:" .. ams)
as = mt.getheader(conn, "ARC-Seal", 0)
print("ARC-Seal:" .. as)

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
    # FIXME: this should match the above
    assert msg['ARC-Authentication-Results'] == 'i=1; example.com; none'
    assert 'ARC-Message-Signature' in msg
    assert 'cv=none' in msg['ARC-Seal']


def test_milter_resign(run_miltertest):
    res = run_miltertest([])
    msg = message_from_string(res.stdout)

    headers = []
    for i in range(2,50):
        headers = [
            ['ARC-Authentication-Results', msg['ARC-Authentication-Results']],
            ['ARC-Message-Signature', msg['ARC-Message-Signature']],
            ['ARC-Seal', msg['ARC-Seal']],
            ['Authentication-Results', msg['Authentication-Results']],
        ] + headers

        res = run_miltertest(headers)

        assert res.returncode == 0
        assert res.stderr == ''

        msg = message_from_string(res.stdout)

        # FIXME: this should be arc=pass
        assert msg['ARC-Authentication-Results'] == f'i={i}; example.com; arc=none smtp.remote-ip=127.0.0.1'
        assert 'cv=pass' in msg['ARC-Seal']
