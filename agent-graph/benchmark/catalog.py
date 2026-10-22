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
    names = []
    for line in WHITELIST_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            names.append(line)
    return frozenset(names)


WHITELIST: frozenset[str] = _load_whitelist()


def whitelist() -> set[str]:
    return set(WHITELIST)


def allowed(name: str) -> bool:
    return name in WHITELIST
