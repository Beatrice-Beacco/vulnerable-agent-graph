from __future__ import annotations

import os
import re
from difflib import SequenceMatcher
from typing import Any, List, Tuple

from security.labels import Label
from security.security_context import _arg_text
from state import Level, join_confidentiality, meet_level

_TOKEN = re.compile(r"[a-z0-9]{6,}|\d{4,}")
_NON_ALNUM = re.compile(r"[^a-z0-9]+")
_MIN_SPAN = 20

_LEDGER: List[Tuple[str, str, Label]] = []


def mode() -> str:
    return os.getenv("LEVEL_GATE", "dataflow").strip().lower()


def enabled() -> bool:
    return mode() == "dataflow"


def argument_mode() -> bool:
    return mode() == "argument"


def reset() -> None:
    _LEDGER.clear()


def _normalize(text: str) -> str:
    return _NON_ALNUM.sub(" ", text.lower()).strip()


def _tokens(normalized: str) -> set:
    return set(_TOKEN.findall(normalized))


def record(value: Any, label: Label) -> None:
    raw = str(value)
    _LEDGER.append((raw, _normalize(raw), label))


def _derived(source: str, target: str, target_tokens: set) -> bool:
    if _tokens(source) & target_tokens:
        return True
    if not source or not target:
        return False
    match = SequenceMatcher(None, source, target, autojunk=False).find_longest_match(
        0, len(source), 0, len(target))
    return match.size >= _MIN_SPAN


def _sources(text: str) -> List[Label]:
    target = _normalize(text)
    target_tokens = _tokens(target)
    return [label for _, source, label in _LEDGER
            if _derived(source, target, target_tokens)]


def level_for(args: Any) -> Level:
    return meet_level(*[label.level for label in _sources(_arg_text(args))])


def label_for(text: str) -> Label:
    labels = _sources(text)
    if not labels:
        return Label.bottom()
    return Label(
        meet_level(*[label.level for label in labels]),
        join_confidentiality(*[label.confidentiality for label in labels]),
        frozenset().union(*[label.provenance for label in labels]),
    )
