POLICIES = """
    forbid (
        principal,
        action == Action::"delete_customer",
        resource
    )
    when {
        context.data.integrity == "Untrusted"
    };

    permit (
        principal,
        action,
        resource
    )

    when {
        context.integrity == "Trusted"
    };
    """

ENTITIES = [
    {
        "uid": {"__entity": {"type": "Agent", "id": "AnalysisAgent"}},
        "attrs": {"role": "analyst"},
        "parents": [],
    },
    {
        "uid": {"__entity": {"type": "Agent", "id": "DatabaseAgent"}},
        "attrs": {"role": "db_admin"},
        "parents": [],
    },
    {
        "uid": {"__entity": {"type": "Tool", "id": "CRMDatabase"}},
        "attrs": {"critical": True},
        "parents": [],
    },
    {
        "uid": {"__entity": {"type": "Data", "id": "EmailSummary"}},
        "attrs": {"integrity": "untrusted", "source": "email"},
        "parents": [],
    },
    {"uid": {"__entity": {"type": "Action", "id": "update_customer"}}},
    {
        "uid": {"__entity": {"type": "Action", "id": "delete_customer"}},
    },
]
