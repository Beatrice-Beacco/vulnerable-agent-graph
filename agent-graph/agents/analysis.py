"""
Analysis step of a branch (triage, parser): analysts turn the request into a
structured CRM operation, and the reference monitor decides which analysis,
if any, the executors run. Every decision is a policy:

1. check   each analysis is a check_analysis request (validation.cedar,
           quarantine.cedar);
2. adopt   the checked analysis becomes the operation only through an
           adopt_analysis request (consensus.cedar);
3. arbiter if the checked analyses are none or disagree, the LLM arbiter
           proposes one from the request and the checked analyses (it never
           sees a rejected analysis); the proposal goes through the same check
           and adoption;
4. stop    if nothing is adopted the run stops before any CRM operation: the
           request needs a human.

Removing a policy file (DISABLED_POLICIES) removes the corresponding defense.
"""

import dataclasses
from typing import Callable, Optional

from agents.arbiter import AGENT_ID as ARBITER_ID, arbitrate
from engine.facts import agreement_key
from security import trace
from security.authorization_middleware import monitor


def _as_dict(output) -> dict:
    if dataclasses.is_dataclass(output) and not isinstance(output, type):
        return dataclasses.asdict(output)
    return dict(output)


def _record(node: str, phase: str, decision, analysis: dict) -> None:
    print(f"ANALYSIS {phase.upper()} @ {node}: {decision}")
    trace.event(
        "analysis_decision",
        node=node,
        phase=phase,
        agent=decision.agent,
        analysis=analysis,
        allowed=decision.allowed,
        policies=decision.policies,
        reason=decision.reason,
    )


def _stop(node: str, reason: str) -> None:
    print(f"STOP @ {node}: {reason}")
    trace.event("stop", node=node, reason=reason)


def run_analysis(
    node: str,
    analysts: dict,
    analyze: Callable,
    request: str,
    context_for: Callable,
    arbiter=None,
    instructions: str = "",
) -> Optional[dict]:
    """
    `analysts` maps agent ids to agents; `analyze(agent, context)` returns
    the structured output of one analyst; `context_for(agent_id)` builds its
    security context. Returns the adopted analysis, or None when the run
    must stop.
    """
    checked = {}
    for agent_id, agent in analysts.items():
        context = context_for(agent_id)
        try:
            analysis = _as_dict(analyze(agent, context))
        except PermissionError:
            # A denied call ended the analyst's invocation: no analysis.
            continue
        decision = monitor.check_analysis(agent_id, analysis, request, context)
        _record(node, "check", decision, analysis)
        if decision.allowed:
            checked[agent_id] = analysis

    if len({agreement_key(a) for a in checked.values()}) == 1:
        candidate_id, candidate = next(iter(checked.items()))
    elif arbiter is not None:
        # No checked analysis, or checked analyses that disagree: the arbiter
        # proposes from the request and the checked analyses only.
        context = context_for(ARBITER_ID)
        candidate_id = ARBITER_ID
        candidate = _as_dict(arbitrate(arbiter, request, checked, context, instructions))
        decision = monitor.check_analysis(ARBITER_ID, candidate, request, context)
        _record(node, "check", decision, candidate)
        if not decision.allowed:
            _stop(node, "the arbiter's proposal did not pass the check")
            return None
    else:
        _stop(node, "no analysis passed the check")
        return None

    key = agreement_key(candidate)
    conflicting = sum(agreement_key(a) != key for a in checked.values())
    decision = monitor.adopt_analysis(candidate_id, candidate, conflicting, request)
    _record(node, "adopt", decision, candidate)
    if not decision.allowed:
        _stop(node, "the analysis was not adopted")
        return None
    return candidate
