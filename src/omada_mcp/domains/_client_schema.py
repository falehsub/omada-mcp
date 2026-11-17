"""Public options and typed result schemas for the four client collection tools."""
from __future__ import annotations

from typing import Any

from ._tool_model import _LIMIT_PROP, _list_output_schema


def client_query_properties(item_schema: dict[str, Any]) -> dict[str, Any]:
    return {
        "limit": _LIMIT_PROP,
        "pageSize": {"type": "integer", "minimum": 1, "maximum": 500,
                     "description": "Opt-in page size; excludes limit. Resume with cursor."},
        "cursor": {"type": "string", "minLength": 1,
                   "description": "Resume same query/site; omitted options inherit. Process-local, expires."},
        "fields": {"type": "array", "minItems": 1, "uniqueItems": True,
                   "items": {"type": "string", "enum": list(item_schema["properties"])},
                   "description": "Return selected fields; mac always retained. Default all."},
        "resultFormat": {"type": "string", "enum": ["legacy", "envelope"],
                         "description": "envelope makes text equal structuredContent; default legacy."},
    }


def client_output_schema(item_schema: dict[str, Any]) -> dict[str, Any]:
    schema = _list_output_schema({
        "anyOf": [item_schema, {"type": "object", "properties": item_schema["properties"],
                               "required": ["mac"], "additionalProperties": False}],
    })
    props = schema["properties"]
    for key in ("totalRows", "sourceTotalRows", "rowsScanned", "pagesFetched", "controllerRequests", "maxPages", "limit"):
        props[key] = {"type": "integer", "minimum": 0}
    for key in ("totalRowsExact", "hasMore", "complete", "truncated"):
        props[key] = {"type": "boolean"}
    for key in ("nextCursor", "truncationReason", "stopReason", "source", "totalRowsSource"):
        props[key] = {"type": "string"}
    props["consistency"] = {"type": "string", "enum": ["bestEffort"]}
    props["warnings"] = {"type": "array", "items": {"type": "string"}}
    props["selectedFields"] = {"type": "array", "items": {"type": "string", "enum": list(item_schema["properties"])}}
    return schema
