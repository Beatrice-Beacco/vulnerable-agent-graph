"""Small helpers shared by the schema and the tool declarations (a leaf
module, so neither has to import the other)."""


def entity(entity_type: str, entity_id: str, attrs=None, parents=()) -> dict:
    """A Cedar entity in the shape cedarpy expects."""
    return {
        "uid": {"type": entity_type, "id": entity_id},
        "attrs": attrs or {},
        "parents": [{"type": t, "id": i} for t, i in parents],
    }
