import json

import pytest

from hardenscan.models import SEVERITY_RANK, CheckResult, Severity, Status


def make_result(**overrides):
    """A valid CheckResult; tests change only the fields they care about."""
    values = dict(
        check_id='win.firewall',
        title='Firewall is on for all profiles',
        status=Status.FAIL,
        severity=Severity.HIGH,
        evidence='Public profile: off',
    )
    values.update(overrides)
    return CheckResult(**values)


def test_result_holds_its_fields_and_defaults():
    r = make_result()
    assert r.status is Status.FAIL
    assert r.fix == ''
    assert r.controls == []
    assert r.duration_ms == 0


def test_status_is_also_a_string():
    assert Status.FAIL == 'fail'
    assert Status('warn') is Status.WARN


def test_unknown_status_is_rejected():
    with pytest.raises(ValueError):
        Status('fial')


def test_each_result_gets_its_own_controls_list():
    a = make_result()
    b = make_result()
    a.controls.append('CIS 4.1')
    assert b.controls == []


def test_severity_rank_order():
    order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    ranks = [SEVERITY_RANK[s] for s in order]
    assert ranks == sorted(ranks)


def test_to_dict_is_plain_json():
    d = make_result(controls=['CIS 9.1.1']).to_dict()
    assert d['status'] == 'fail'
    assert type(d['status']) is str        # a real str, not the enum
    assert json.loads(json.dumps(d)) == d  # survives a JSON round trip