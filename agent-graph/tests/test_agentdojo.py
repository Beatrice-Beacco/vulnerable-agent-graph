import pytest

pytest.importorskip("cedarpy")

from benchmark.agentdojo import manifest  # noqa: E402
from benchmark.agentdojo.bench import evaluate  # noqa: E402

CASES = [(suite, case) for suite in manifest.SUITES
         for case in manifest.SUITES[suite]["injections"]]
IDS = [case["id"] for _, case in CASES]


@pytest.mark.parametrize("suite,case", CASES, ids=IDS)
def test_sink_is_whitelisted(suite, case):
    assert case["sink_tool"] in manifest.SUITES[suite]["whitelist"]


@pytest.mark.parametrize("suite,case", CASES, ids=IDS)
def test_attack_slips_whitelist_alone(suite, case):
    assert evaluate(suite, case)["attack_grants_allowed"]


@pytest.mark.parametrize("suite,case", CASES, ids=IDS)
def test_catch_matches_prediction(suite, case):
    assert evaluate(suite, case)["actual_catch"] == case.get("catch", "dataflow")


@pytest.mark.parametrize("suite,case", CASES, ids=IDS)
def test_lattice_keeps_benign(suite, case):
    assert evaluate(suite, case)["benign_full_allowed"]
