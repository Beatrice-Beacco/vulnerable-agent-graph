from __future__ import annotations

import os
import re
from difflib import SequenceMatcher
from typing import Any, Dict, Iterator, List, Set, Tuple

from security.labels import Label
from state import Level, meet_level

_EMAIL = re.compile(r"[a-z0-9._%+-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+")
_ADDRESS = re.compile(r"(?:https?://)?[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z][a-z0-9-]*(?:/[^\s\"'<>]*)?")
_WORD = re.compile(r"[a-z0-9]+")
_GROUP = r"[a-z0-9]*\d[a-z0-9]*"
_RUN = re.compile(rf"{_GROUP}(?:[ \-]{_GROUP})+")
_SEPARATOR = re.compile(r"[ \-]")
_NON_ALNUM = re.compile(r"[^a-z0-9]+")
_MAX_GROUPS = 6
_MIN_EXACT = 8
_MIN_SPAN = 20

_VALUES: Dict[str, Level] = {}
_SOURCES: List[Tuple[str, Level]] = []


def mode() -> str:
    return os.getenv("LEVEL_GATE", "dataflow").strip().lower()


def enabled() -> bool:
    return mode() == "dataflow"


def argument_mode() -> bool:
    return mode() == "argument"


def reset() -> None:
    _VALUES.clear()
    _SOURCES.clear()


def _normalize(text: str) -> str:
    return _NON_ALNUM.sub("", text)


def _prose(text: str) -> str:
    return " ".join(_WORD.findall(text.lower()))


def identifiers(text: Any) -> Set[str]:
    low = str(text).lower()
    found = {_normalize(match) for match in _EMAIL.findall(low)}
    found |= {_normalize(match) for match in _ADDRESS.findall(low)}
    found |= {word for word in _WORD.findall(low)
              if len(word) >= 2 and any(ch.isdigit() for ch in word)}
    for run in _RUN.finditer(low):
        groups = [group for group in _SEPARATOR.split(run.group(0)) if group]
        for start in range(len(groups)):
            for stop in range(start + 2, min(len(groups), start + _MAX_GROUPS) + 1):
                found.add("".join(groups[start:stop]))
    return found


def record(value: Any, label: Label) -> None:
    text = str(value)
    for identifier in identifiers(text):
        known = _VALUES.get(identifier)
        _VALUES[identifier] = label.level if known is None else max(known, label.level)
    _SOURCES.append((_prose(text), label.level))


def _leaves(obj: Any) -> Iterator[str]:
    if isinstance(obj, dict):
        for value in obj.values():
            yield from _leaves(value)
    elif isinstance(obj, (list, tuple, set)):
        for value in obj:
            yield from _leaves(value)
    elif obj is not None:
        yield str(obj)


def _verbatim(prose: str) -> List[Level]:
    needle = f" {prose} "
    return [level for source, level in _SOURCES if needle in f" {source} "]


def _quoted(prose: str) -> List[Level]:
    levels = []
    for source, level in _SOURCES:
        if not source:
            continue
        match = SequenceMatcher(None, source, prose, autojunk=False).find_longest_match(
            0, len(source), 0, len(prose))
        if match.size >= _MIN_SPAN:
            levels.append(level)
    return levels


def value_levels(args: Any, context_level: Level) -> List[Level]:
    levels: List[Level] = []
    for leaf in _leaves(args):
        for identifier in identifiers(leaf):
            levels.append(_VALUES.get(identifier, context_level))
        prose = _prose(leaf)
        copied = _verbatim(prose) if len(prose) >= _MIN_EXACT and " " in prose else []
        if copied:
            levels.append(max(copied))
        elif len(prose) >= _MIN_SPAN:
            levels.extend(_quoted(prose))
    return levels


def level_for(args: Any, context_level: Level = Level.SYSTEM) -> Level:
    return meet_level(*value_levels(args, context_level))
