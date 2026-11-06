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
_ALNUM_ONLY = re.compile(r"[^a-z0-9]+")
_MIN_SPAN = 20

_PAYLOAD = (
    re.compile(r"\d{7,}"),
    re.compile(r"[a-z]{2}\d{2}[a-z0-9]{8,}"),
)
_PAYLOAD_RAW = (
    re.compile(r"[\w.%+-]+@[\w.-]+\.\w{2,}"),
    re.compile(r"https?://\S+"),
    re.compile(r"www\.\S+"),
)

_LEDGER: List[Tuple[str, str, Label]] = []


def enabled() -> bool:
    return os.getenv("DATAFLOW_LEVEL", "0").strip() == "1"


def _endorsement() -> bool:
    return os.getenv("ENDORSEMENT", "0").strip() == "1"


def reset() -> None:
    _LEDGER.clear()


def _normalize(text: str) -> str:
    return _NON_ALNUM.sub(" ", text.lower()).strip()


def _canon(text: str) -> str:
    return _ALNUM_ONLY.sub("", text.lower())


def _tokens(normalized: str) -> set:
    return set(_TOKEN.findall(normalized))


def _payload_tokens(raw: str) -> set:
    canon = _canon(raw)
    lower = raw.lower()
    out = set()
    for pattern in _PAYLOAD:
        out.update(pattern.findall(canon))
    for pattern in _PAYLOAD_RAW:
        out.update(_canon(match) for match in pattern.findall(lower))
    return out


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


def _matched(text: str) -> List[Tuple[str, Label]]:
    target = _normalize(text)
    target_tokens = _tokens(target)
    return [(raw, label) for raw, source, label in _LEDGER
            if _derived(source, target, target_tokens)]


def _effective_level(text: str, matched: List[Tuple[str, Label]]) -> Level:
    base = meet_level(*[label.level for _, label in matched])
    if not _endorsement() or int(base) >= int(Level.INTERNAL):
        return base
    untrusted_payload = set()
    for raw, label in matched:
        if int(label.level) < int(Level.INTERNAL):
            untrusted_payload |= _payload_tokens(raw)
    if _payload_tokens(text) & untrusted_payload:
        return base
    return Level.INTERNAL


def level_for(args: Any) -> Level:
    text = _arg_text(args)
    return _effective_level(text, _matched(text))


def label_for(text: str) -> Label:
    matched = _matched(text)
    if not matched:
        return Label.bottom()
    return Label(
        _effective_level(text, matched),
        join_confidentiality(*[label.confidentiality for _, label in matched]),
        frozenset().union(*[label.provenance for _, label in matched]),
    )
