import json

from ovs_logs.ui.preview import serialize_preview_rows


def test_serialize_preview_rows_for_tuple_rows() -> None:
    rows = [
        (1, {"a": 1, "b": ["x", "y"]}),
        (2, {"nested": {"c": 3}}),
    ]
    columns = ["id", "details"]

    result = serialize_preview_rows(rows, columns)

    assert result[0]["id"] == 1
    assert json.loads(result[0]["details"]) == {"a": 1, "b": ["x", "y"]}
    assert json.loads(result[1]["details"]) == {"nested": {"c": 3}}


def test_serialize_preview_rows_for_mapping_rows() -> None:
    rows = [
        {"name": "alice", "tags": ["admin", "user"]},
        {"name": "bob", "content": b"hello"},
    ]

    result = serialize_preview_rows(rows)

    assert result[0]["name"] == "alice"
    assert json.loads(result[0]["tags"]) == ["admin", "user"]
    assert result[1]["content"] == "hello"
