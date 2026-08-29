POLICIES = """
    forbid (
        principal,
        action == Action::"delete_customer",
        resource
    )
    when {
        context.data.integrity > context.data.maxTaint
    };

    permit (
        principal,
        action,
        resource
    )

    when {
        context.data.integrity <= context.data.maxTaint
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
        "uid": {"__entity": {"type": "Tool", "id": "delete_customer"}},
        "attrs": {"critical": True},
        "parents": [],
    },
    {
        "uid": {"__entity": {"type": "Tool", "id": "write_customer"}},
        "attrs": {"critical": True},
        "parents": [],
    },
    {
        "uid": {"__entity": {"type": "Data", "id": "EmailSummary"}},
        "attrs": {"integrity": "untrusted", "source": "email"},
        "parents": [],
    },
]
