#!/usr/bin/env python3

import subprocess


def test_config(milter):
    pass


def test_config_fail(milter_cmdline):
    res = subprocess.run(milter_cmdline, capture_output=True, text=True, timeout=4)
    assert res.returncode != 0
    assert 'parameter "KeyFile" required when signing' in res.stderr
