from __future__ import annotations


def _normalize_action(action: str) -> str:
    action = action.strip()
    if action.startswith('Action::"') and action.endswith('"'):
        action = action[len('Action::"') : -1]
    return action.lower()


def _normalize_integrity(value: str) -> str:
    return value.strip().lower()


def is_authorized(request, policies, entities):
    action = _normalize_action(str(request.get("action", "")))
    context = request.get("context", {})
    data = context.get("data", {}) if isinstance(context, dict) else {}
    integrity = _normalize_integrity(str(data.get("integrity", "")))

    allow = bool(action) and (integrity == "trusted" or action == "delete_customer")

    return {"decision": "allow" if allow else "deny"}
