from benchmark.teamflow.suites import devops, finance, healthcare, hr, legal

_MODULES = (healthcare, finance, legal, hr, devops)

SUITES = {module.SUITE.name: module.SUITE for module in _MODULES}
CASES = tuple(case for module in _MODULES for case in module.CASES)
BY_ID = {case.id: case for case in CASES}
