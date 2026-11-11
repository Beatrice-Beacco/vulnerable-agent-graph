"""Lattices, labels and the security context (state.py, security/)."""

from security.labels import Label
from security.security_context import SecurityContext, build_security_context
from state import Confidentiality as C
from state import Level as L
from state import TaintedValue, join_confidentiality, meet_level


def test_meet_is_minimum_and_identity_is_system():
    assert meet_level(L.USER, L.UNTRUSTED_EXTERNAL, L.INTERNAL) == L.UNTRUSTED_EXTERNAL
    assert meet_level() == L.SYSTEM


def test_join_is_maximum_and_identity_is_public():
    assert join_confidentiality(C.PUBLIC, C.CONFIDENTIAL) == C.CONFIDENTIAL
    assert join_confidentiality() == C.PUBLIC


def test_label_combine_and_extremes():
    a = Label(L.USER, C.PUBLIC, frozenset({"a"}))
    b = Label(L.EXTERNAL_KNOWN, C.INTERNAL, frozenset({"b"}))
    assert a.join(b) == Label(L.EXTERNAL_KNOWN, C.INTERNAL, frozenset({"a", "b"}))
    assert a.join(Label.bottom()) == a  # bottom is the identity
    assert Label.top().level == L.UNTRUSTED_EXTERNAL
    assert Label.top().confidentiality == C.CONFIDENTIAL


def test_context_without_labeled_fields_fails_closed():
    ctx = build_security_context({"x": "plain string"}, origin="t")
    assert ctx.label == Label.top()


def test_context_is_meet_of_fields_and_absorb_lowers_it():
    ctx = build_security_context({
        "q": TaintedValue("q", L.USER, source="user"),
        "r": TaintedValue("r", L.INTERNAL, confidentiality=C.INTERNAL),
    })
    assert (ctx.level, ctx.confidentiality) == (L.INTERNAL, C.INTERNAL)
    ctx.absorb(Label(L.UNTRUSTED_EXTERNAL, C.PUBLIC, frozenset({"tool:x"})))
    assert ctx.level == L.UNTRUSTED_EXTERNAL
    assert "tool:x" in ctx.provenance


def test_raised_to_is_a_copy():
    ctx = SecurityContext(label=Label(L.UNTRUSTED_EXTERNAL, C.PUBLIC), denied_tools={"t"})
    raised = ctx.raised_to(L.USER)
    assert raised.level == L.USER and raised.denied_tools == {"t"}
    assert ctx.level == L.UNTRUSTED_EXTERNAL  # the original is unchanged


def test_labeled_reply_carries_the_context_label():
    ctx = SecurityContext(label=Label(L.EXTERNAL_KNOWN, C.CONFIDENTIAL, frozenset({"s"})))
    tv = ctx.labeled("reply", source="agent")
    assert (tv.level, tv.confidentiality) == (L.EXTERNAL_KNOWN, C.CONFIDENTIAL)
    assert tv.provenance == ["s", "agent"]
