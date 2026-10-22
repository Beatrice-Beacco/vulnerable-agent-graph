def entity(entity_type: str, entity_id: str, attrs=None, parents=()) -> dict:
    return {
        "uid": {"type": entity_type, "id": entity_id},
        "attrs": attrs or {},
        "parents": [{"type": t, "id": i} for t, i in parents],
    }
