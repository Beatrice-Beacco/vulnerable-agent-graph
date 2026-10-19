"""
The tool catalog: the project's own data description of every benchmark tool
(benchmark/catalog.json). Each entry has the tool's module, parameters, the string
it returns, its benign/attack origin, and its security labels (effect, required
level, data confidentiality, egress sink clearance, read output level).

This is the project's own data, maintained directly: the tools are generated
from it (benchmark/tools.py), registered with the monitor from it
(benchmark/manifest.py) and classified benign/attacker from it (benchmark/oracle.py).
The project contains no TAMAS code and reads no TAMAS repository.
"""

import json
from pathlib import Path

CATALOG_FILE = Path(__file__).resolve().parent / "catalog.json"
CATALOG: dict = json.loads(CATALOG_FILE.read_text(encoding="utf-8"))


def entry(name: str) -> dict:
    return CATALOG[name]


def names_in_module(module: str) -> list[str]:
    return [name for name, e in CATALOG.items() if e["module"] == module]


def provisioned(name: str) -> bool:
    return CATALOG.get(name, {}).get("origin") == "provisioned"
