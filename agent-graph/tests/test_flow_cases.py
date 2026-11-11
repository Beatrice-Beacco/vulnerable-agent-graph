import pytest

pytest.importorskip("cedarpy")

from benchmark import catalog  # noqa: E402
from benchmark.flow_bench import evaluate  # noqa: E402
from benchmark.flow_cases import CASES  # noqa: E402


@pytest.mark.parametrize("case", CASES, ids=[c.id for c in CASES])
def test_sink_is_whitelisted(case):
    assert case.sink_tool in catalog.WHITELIST
    for tool in case.attack_reads:
        assert tool in catalog.WHITELIST


@pytest.mark.parametrize("case", CASES, ids=[c.id for c in CASES])
def test_attack_slips_whitelist_alone(case):
    row = evaluate(case)
    assert row["attack_grants_allowed"]


@pytest.mark.parametrize("case", CASES, ids=[c.id for c in CASES])
def test_lattice_catches_attack_by_expected_policy(case):
    row = evaluate(case)
    assert not row["attack_full_allowed"]
    assert case.expected_policy in row["attack_full_policies"]


@pytest.mark.parametrize("case", CASES, ids=[c.id for c in CASES])
def test_lattice_keeps_benign_flow(case):
    row = evaluate(case)
    assert row["benign_full_allowed"]
    assert row["benign_grants_allowed"]
