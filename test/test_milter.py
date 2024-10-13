#!/usr/bin/env python3

import socket

import miltertest
import pytest


@pytest.fixture
def run_miltertest(request, milter, milter_config):
    def _run_miltertest(headers=None, standard_headers=True, body='test body\r\n'):
        headers = headers or []
        if standard_headers:
            headers.extend(
                [
                    ['From', 'user@example.com\n'],
                    ['Date', 'Fri, 04 Oct 2024 10:11:12 -0400'],
                    ['Subject', request.function.__name__],
                ]
            )

        # Connect
        sock = socket.socket(family=socket.AF_UNIX)
        sock.connect(bytes(milter_config['sock']))
        conn = miltertest.MilterConnection(sock)
        conn.optneg_mta(protocol=miltertest.SMFI_V6_PROT ^ miltertest.SMFIP_HDR_LEADSPC)
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
                ins_headers.insert(msg[1]['index'], [msg[1]['name'], msg[1]['value']])
            elif msg[0] in miltertest.DISPOSITION_REPLIES:
                assert msg[0] == miltertest.SMFIR_ACCEPT
            else:
                pytest.fail(f'Unexpected EOM response {msg}')

        return {
            'headers': ins_headers,
        }

    return _run_miltertest


def test_milter_basic(run_miltertest):
    """Basic signing"""
    res = run_miltertest()

    assert res['headers'][0] == ['Authentication-Results', 'example.com; arc=none smtp.remote-ip=127.0.0.1']
    assert res['headers'][1][0] == 'ARC-Seal'
    assert 'cv=none' in res['headers'][1][1]
    assert res['headers'][2][0] == 'ARC-Message-Signature'
    assert res['headers'][3] == ['ARC-Authentication-Results', 'i=1; example.com; arc=none']


def test_milter_staticmsg(run_miltertest):
    headers = [
        ['ARC-Seal', (
            'i=1; cv=none; a=rsa-sha256; d=dkimpy.example.com; s=sel;\r\n'
            ' t=1728713840;\r\n'
            ' b=jmHJmDXHe4eFAurv+yXz1RTRLj+XNaHedD4GYWPt0XntR94pMNSFlU2TxT0rzkMcE4Nkt\r\n'
            ' xFrz0OYVfexpgNJ393tO8czBH4OwEwV2E5h+U/8N1vM+KHKfcg2n02SOxUa991Z1+CXUrO6\r\n'
            ' lUnIx7gN+iz3x2muWG6hm6d1J0h4+yaQCuVlNImf3PM/M7l57GbfHvQpbYI9m4hf6IMncRS\r\n'
            ' sOuXyTaH8NrWpqqM0KctxR4x+kC/Y3dKNYcL5VwbajlXletkmHO79sbuGD0HsK8HUdzfE1Z\r\n'
            ' gGinobwxRu7skmTPq0TSlBQQ/1fuxpSOpocjnY+E/g3FH3ZsAtbOG2jVYd9w=='
        )],
        ['ARC-Message-Signature', (
            'i=1; a=rsa-sha256; c=relaxed/relaxed;\r\n'
            ' d=dkimpy.example.com; s=sel; t=1728713840; h=content-type :\r\n'
            ' mime-version : content-transfer-encoding : subject : from : to : from;\r\n'
            ' bh=Pb6s/Xlf4u1eDlYyO0NCaMRMrCg6xDNkK5byz8RDY1s=;\r\n'
            ' b=dmFKbeiAEsaA/gnLQyuRBcX72pvARuJMrZIptplgCGp9vqudMP2ngI/g8eo63nQYMB0md\r\n'
            ' AaofYsl5lD8qE/B20FDgn66jTHQIGsPi0Fv06Mf45NaTFpeaEyexjZunYXSLao3RY5Cqtac\r\n'
            ' m0BcCS/MaaiMBoDmcRa5GOzBi02coJG5IsDt+ZWT6P7nHQHrDNsuLBeJBX7+vJ0bM9QHbCE\r\n'
            ' Q+eZZxcT7W2MWaByV2Jjz4B+sh0IzfX2wPNsGOsNpD+MvpehQsa9ig7eEndNWw7V1qpaMN+\r\n'
            ' vtOnb5H80nu0K4H7fvrNUI4h4b+UTumqR/HhiNTFRobUGiwuvrP4CWHj3dtQ==\r\n'
        )],
        ['ARC-Authentication-Results', 'i=1; dkimpy.example.com'],
        ['Content-Type', 'text/plain; charset="us-ascii"'],
        ['MIME-Version', '1.0'],
        ['Content-Transfer-Encoding', '7bit'],
        ['Subject', 'test message from dkimpy'],
        ['From', 'testsender@example.com'],
        ['To', 'testrcpt@example.com'],
    ]
    res = run_miltertest(headers, False, 'test message\r\n')
    assert res['headers'][0] == ['Authentication-Results', 'example.com; arc=pass smtp.remote-ip=127.0.0.1']
    assert res['headers'][1][0] == 'ARC-Seal'
    assert 'cv=pass' in res['headers'][1][1]
    assert res['headers'][2][0] == 'ARC-Message-Signature'
    assert res['headers'][3] == ['ARC-Authentication-Results', 'i=2; example.com; arc=pass']


def test_milter_resign(run_miltertest):
    """Extend the chain as much as possible"""
    res = run_miltertest()

    headers = []
    for i in range(2, 52):
        headers = [*res['headers'], *headers]
        res = run_miltertest(headers)

        assert res['headers'][0] == ['Authentication-Results', 'example.com; arc=pass smtp.remote-ip=127.0.0.1']

        if i <= 50:
            assert res['headers'][3] == ['ARC-Authentication-Results', f'i={i}; example.com; arc=pass']
            assert 'cv=pass' in res['headers'][1][1]
        else:
            assert len(res['headers']) == 1


def test_milter_mode_s(run_miltertest):
    """Sign mode"""
    res = run_miltertest()

    assert len(res['headers']) == 3
    assert 'cv=none' in res['headers'][0][1]
    assert res['headers'][1][0] == 'ARC-Message-Signature'
    assert res['headers'][2] == ['ARC-Authentication-Results', 'i=1; example.com; arc=none']


def test_milter_mode_v(run_miltertest):
    """Verify mode"""
    res = run_miltertest()

    assert len(res['headers']) == 1
    assert res['headers'][0] == ['Authentication-Results', 'example.com; arc=none smtp.remote-ip=127.0.0.1']


def test_milter_mode_none_verify(run_miltertest):
    """No configured mode, from a host that's not in InternalHosts"""
    res = run_miltertest()

    assert len(res['headers']) == 1
    assert res['headers'][0] == ['Authentication-Results', 'example.com; arc=none smtp.remote-ip=127.0.0.1']


def test_milter_mode_none_sign(run_miltertest):
    """No configured mode, from a host that's in InternalHosts"""
    res = run_miltertest()

    assert len(res['headers']) == 3
    assert 'cv=none' in res['headers'][0][1]
    assert res['headers'][1][0] == 'ARC-Message-Signature'
    assert res['headers'][2] == ['ARC-Authentication-Results', 'i=1; example.com; arc=none']


def test_milter_ar(run_miltertest):
    """Override the chain validation state with Authentication-Results"""
    res = run_miltertest()

    # override the result to "fail"
    headers = res['headers']
    headers[0][1] = 'example.com; arc=fail'

    res = run_miltertest(headers)

    assert res['headers'][0] == ['Authentication-Results', 'example.com; arc=fail smtp.remote-ip=127.0.0.1']
    assert 'cv=fail' in res['headers'][1][1]
    assert res['headers'][3] == ['ARC-Authentication-Results', 'i=2; example.com; arc=fail']

    # override the result to "pass"
    headers = [*res['headers'], *headers]
    headers[0][1] = 'example.com; arc=pass'
    res = run_miltertest(headers)

    # the chain is dead because it came in as failed, no matter what A-R says
    assert res['headers'][0] == ['Authentication-Results', 'example.com; arc=fail smtp.remote-ip=127.0.0.1']
    assert len(res['headers']) == 1


def test_milter_ar_disabled(run_miltertest):
    """`PermitAuthenticationOverrides = no` preserves the actual state"""
    res = run_miltertest()

    # override the result to "fail"
    headers = res['headers']
    headers[0][1] = 'example.com; arc=fail'

    res = run_miltertest(headers)

    assert res['headers'][0] == ['Authentication-Results', 'example.com; arc=pass smtp.remote-ip=127.0.0.1']
    assert 'cv=pass' in res['headers'][1][1]
    assert res['headers'][3] == ['ARC-Authentication-Results', 'i=2; example.com; arc=pass']


def test_milter_ar_multi(run_miltertest):
    """Only the most recent A-R header should matter"""
    res = run_miltertest()

    headers = [
        ['Authentication-Results', 'example.com; arc=pass'],
        ['Authentication-Results', 'example.com; arc=fail'],
        *[x for x in res['headers'] if x[0] != 'Authentication-Results'],
    ]
    res = run_miltertest(headers)

    assert res['headers'][0] == ['Authentication-Results', 'example.com; arc=pass smtp.remote-ip=127.0.0.1']
    assert 'cv=pass' in res['headers'][1][1]
    assert res['headers'][3] == ['ARC-Authentication-Results', 'i=2; example.com; arc=pass']


def test_milter_peerlist(run_miltertest):
    """Connections from peers just get `accept` back immediately"""
    with pytest.raises(miltertest.MilterError, match='unexpected response: a'):
        run_miltertest()
