"""
The tool catalog: the project's own data description of every benchmark tool
(benchmark/catalog.json). Each entry has the tool's module, parameters, the string
it returns, and its security labels (effect, required level, data confidentiality,
egress sink clearance, read output level). (The entry also carries a benign/attack
`origin` tag inherited from the source data; it is informational only and no
longer decides authorization -- the whitelist below does.)

This is the project's own data, maintained directly: the tools are generated
from it (benchmark/tools.py) and registered with the monitor from it
(benchmark/manifest.py). What the monitor grants and what the oracle treats as
legitimate is the explicit whitelist in benchmark/whitelist.txt (see `WHITELIST`).
The project contains no TAMAS code and reads no TAMAS repository.
"""

import json
from pathlib import Path

CATALOG_FILE = Path(__file__).resolve().parent / "catalog.json"
CATALOG: dict = json.loads(CATALOG_FILE.read_text(encoding="utf-8"))

WHITELIST_FILE = Path(__file__).resolve().parent / "whitelist.txt"


def entry(name: str) -> dict:
    return CATALOG[name]


def names_in_module(module: str) -> list[str]:
    return [name for name, e in CATALOG.items() if e["module"] == module]


def _load_whitelist() -> frozenset[str]:
    """Read the authoritative allow-list from benchmark/whitelist.txt: one tool
    name per line, ignoring blank lines and '#' comments."""
    names = []
    for line in WHITELIST_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            names.append(line)
    return frozenset(names)


# The single global whitelist: the tool names the benchmark deploys as
# legitimate capabilities, declared explicitly in benchmark/whitelist.txt. The
# monitor's grant permits only these, the same list for every agent (engine
# grants.cedar, via context.whitelisted set by benchmark/manifest.py); a call to
# any other tool is an attack attempt, and if it executes in the sandbox it is a
# violation (benchmark/oracle.py).
WHITELIST: frozenset[str] = _load_whitelist()


def whitelist() -> set[str]:
    """The single global allow-list of tool names."""
    return set(WHITELIST)


def allowed(name: str) -> bool:
    """Whether a tool is on the global whitelist."""
    return name in WHITELIST
