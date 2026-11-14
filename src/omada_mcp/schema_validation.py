"""Recursive JSON Schema argument validator for MCP tool invocations.

Supports the subset of JSON Schema Draft 2020-12 used by ``omada-mcp`` tool
descriptors: nested ``properties``, ``required``, ``additionalProperties``,
``items``, ``type`` (single or list), ``enum``, ``minimum``/``maximum``,
``exclusiveMinimum``/``exclusiveMaximum``, ``minLength``/``maxLength``,
``pattern``, ``minItems``/``maxItems``, ``uniqueItems``, ``anyOf``, and
``oneOf``. Zero third-party dependencies.
"""

from __future__ import annotations

import json
import math
import re
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .tools import Tool

__all__ = ["SchemaValidationError", "validate_tool_arguments"]

_ROOT_ENUM_ALIASES: dict[str, set[str]] = {
    "security": {"none", "wpa3"},
    "aclType": {"0", "1", "2"},
    "category": {"alert", "event", "audits"},
}


class SchemaValidationError(Exception):
    """Raised when tool arguments fail JSON Schema or write-confirmation checks."""

    def __init__(self, message: str, hint: str | None = None):
        super().__init__(message)
        self.message = message
        self.hint = hint


def _camel_norm(text: str) -> str:
    return "".join(ch for ch in text.lower() if ch.isalnum())


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_number(value: Any) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
    )


def _matches_primitive_type(value: Any, expected: str) -> bool:
    if expected == "string":
        return isinstance(value, str)
    if expected == "integer":
        return _is_int(value)
    if expected == "number":
        return _is_number(value)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "array":
        return isinstance(value, list)
    if expected == "object":
        return isinstance(value, dict)
    if expected == "null":
        return value is None
    return True


def _validate_enum(
    value: Any,
    allowed: list[Any],
    *,
    tool_name: str,
    path: str,
    is_root_prop: bool,
    prop_name: str,
) -> None:
    if isinstance(value, str):
        norm = value.strip().lower()
        allowed_lower = {str(e).lower() for e in allowed}
        if is_root_prop and prop_name in _ROOT_ENUM_ALIASES:
            allowed_lower |= _ROOT_ENUM_ALIASES[prop_name]
        if norm in allowed_lower:
            return
    elif value in allowed and not (
        isinstance(value, bool) and all(isinstance(x, int) and not isinstance(x, bool) for x in allowed)
    ):
        return

    raise SchemaValidationError(
        f"{tool_name}: {path} must be one of {allowed}",
        hint=f"Allowed values for {path}: {', '.join(map(str, allowed))}",
    )


def _validate_combinators(
    value: Any,
    schema: Mapping[str, Any],
    *,
    tool_name: str,
    path: str,
) -> None:
    if "anyOf" in schema and isinstance(schema["anyOf"], list):
        branch_errors: list[str] = []
        matched = False
        for branch in schema["anyOf"]:
            try:
                _validate_node(value, branch, tool_name=tool_name, path=path)
                matched = True
                break
            except SchemaValidationError as exc:
                branch_errors.append(exc.message)
        if not matched:
            raise SchemaValidationError(
                f"{tool_name}: {path} did not satisfy any allowed schema variant",
                hint="; ".join(branch_errors[:3]),
            )

    if "oneOf" in schema and isinstance(schema["oneOf"], list):
        matches = 0
        branch_errors = []
        for branch in schema["oneOf"]:
            try:
                _validate_node(value, branch, tool_name=tool_name, path=path)
                matches += 1
            except SchemaValidationError as exc:
                branch_errors.append(exc.message)
        if matches != 1:
            raise SchemaValidationError(
                f"{tool_name}: {path} must match exactly one schema variant (matched {matches})",
                hint="; ".join(branch_errors[:3]) if matches == 0 else None,
            )


def _validate_node(
    value: Any,
    schema: Mapping[str, Any],
    *,
    tool_name: str,
    path: str,
    is_root: bool = False,
    is_root_prop: bool = False,
    prop_name: str = "",
) -> None:
    if not isinstance(schema, Mapping) or not schema:
        return

    _validate_combinators(value, schema, tool_name=tool_name, path=path)

    ptype = schema.get("type")
    if isinstance(ptype, str):
        if value is None:
            if ptype == "boolean":
                raise SchemaValidationError(f"{tool_name}: {path} must not be null")
        elif not _matches_primitive_type(value, ptype):
            if ptype == "boolean":
                raise SchemaValidationError(
                    f"{tool_name}: {path} must be a boolean",
                    hint=f"pass JSON true or false for {path} (not a string)",
                )
            article = "an" if ptype in ("integer", "array", "object") else "a"
            raise SchemaValidationError(f"{tool_name}: {path} must be {article} {ptype}")
    elif isinstance(ptype, list):
        if value is None:
            if "null" not in ptype and "boolean" in ptype:
                raise SchemaValidationError(f"{tool_name}: {path} must not be null")
        elif not any(_matches_primitive_type(value, item) for item in ptype):
            raise SchemaValidationError(
                f"{tool_name}: {path} must match type {' or '.join(ptype)}",
            )

    if value is None:
        return

    if "enum" in schema and isinstance(schema["enum"], list):
        _validate_enum(
            value,
            schema["enum"],
            tool_name=tool_name,
            path=path,
            is_root_prop=is_root_prop,
            prop_name=prop_name,
        )

    if isinstance(value, str):
        if "minLength" in schema and len(value) < int(schema["minLength"]):
            raise SchemaValidationError(
                f"{tool_name}: {path} length must be >= {schema['minLength']}",
            )
        if "maxLength" in schema and len(value) > int(schema["maxLength"]):
            raise SchemaValidationError(
                f"{tool_name}: {path} length must be <= {schema['maxLength']}",
            )
        if "pattern" in schema and not re.search(str(schema["pattern"]), value):
            raise SchemaValidationError(
                f"{tool_name}: {path} does not match pattern {schema['pattern']!r}",
            )

    if _is_number(value):
        if "minimum" in schema and value < schema["minimum"]:
            raise SchemaValidationError(
                f"{tool_name}: {path} must be >= {schema['minimum']}",
            )
        if "maximum" in schema and value > schema["maximum"]:
            raise SchemaValidationError(
                f"{tool_name}: {path} must be <= {schema['maximum']}",
            )
        if "exclusiveMinimum" in schema and value <= schema["exclusiveMinimum"]:
            raise SchemaValidationError(
                f"{tool_name}: {path} must be > {schema['exclusiveMinimum']}",
            )
        if "exclusiveMaximum" in schema and value >= schema["exclusiveMaximum"]:
            raise SchemaValidationError(
                f"{tool_name}: {path} must be < {schema['exclusiveMaximum']}",
            )

    if isinstance(value, list):
        if "minItems" in schema and len(value) < int(schema["minItems"]):
            raise SchemaValidationError(
                f"{tool_name}: {path} must have at least {schema['minItems']} item(s)",
            )
        if "maxItems" in schema and len(value) > int(schema["maxItems"]):
            raise SchemaValidationError(
                f"{tool_name}: {path} must have at most {schema['maxItems']} item(s)",
            )
        if schema.get("uniqueItems"):
            seen_items = [json.dumps(x, sort_keys=True, default=str) for x in value]
            if len(set(seen_items)) != len(seen_items):
                raise SchemaValidationError(f"{tool_name}: {path} items must be unique")
        items_schema = schema.get("items")
        if isinstance(items_schema, Mapping):
            for idx, item in enumerate(value):
                _validate_node(
                    item,
                    items_schema,
                    tool_name=tool_name,
                    path=f"{path}[{idx}]",
                )

    if isinstance(value, dict):
        props = schema.get("properties")
        props_map = props if isinstance(props, Mapping) else None
        addl = schema.get("additionalProperties")

        if props_map is not None and addl is not True:
            unknown = sorted(k for k in value if k not in props_map)
            if unknown:
                camel_lookup = {_camel_norm(prop): prop for prop in props_map}
                fixes = [
                    f"use {camel_lookup[_camel_norm(k)]!r} instead of {k!r}"
                    for k in unknown
                    if _camel_norm(k) in camel_lookup
                ]
                prefix = f"{tool_name}: " if is_root else f"{tool_name}: {path}: "
                hint = "; ".join(fixes) if fixes else "allowed arguments: " + ", ".join(sorted(props_map))
                raise SchemaValidationError(
                    f"{prefix}unexpected argument(s): {', '.join(unknown)}",
                    hint=hint,
                )

        required = schema.get("required") or []
        if required:
            missing = [
                key
                for key in required
                if key not in value or value[key] is None or value[key] == ""
            ]
            if missing:
                if is_root:
                    raise SchemaValidationError(
                        f"{tool_name}: missing required argument(s): {', '.join(missing)}",
                        hint="inputSchema: " + json.dumps(dict(props_map or {})),
                    )
                raise SchemaValidationError(
                    f"{tool_name}: {path} missing required field(s): {', '.join(missing)}",
                )

        if props_map is not None:
            for key, child_val in value.items():
                child_schema = props_map.get(key)
                if not isinstance(child_schema, Mapping):
                    if isinstance(addl, Mapping):
                        _validate_node(
                            child_val,
                            addl,
                            tool_name=tool_name,
                            path=key if is_root else f"{path}.{key}",
                        )
                    continue
                if child_val is None and key in required:
                    raise SchemaValidationError(f"{tool_name}: {key} must not be null")
                _validate_node(
                    child_val,
                    child_schema,
                    tool_name=tool_name,
                    path=key if is_root else f"{path}.{key}",
                    is_root_prop=is_root,
                    prop_name=key,
                )


def validate_tool_arguments(spec: Tool, arguments: dict[str, Any]) -> None:
    """Validate *arguments* recursively against *spec.input_schema*."""
    schema = spec.input_schema or {}
    props = schema.get("properties") or {}
    if not spec.read_only and "dryRun" in props and "dryRun" not in arguments:
        arguments["dryRun"] = True

    # Preserve backward-compatible integer coercions/clamping for 'limit' and 'code'.
    if "limit" in props and arguments.get("limit") is not None:
        raw_limit = arguments["limit"]
        if isinstance(raw_limit, bool):
            raise SchemaValidationError("limit must be an integer between 1 and 5000")
        try:
            arguments["limit"] = max(1, min(5000, int(raw_limit)))
        except (TypeError, ValueError):
            raise SchemaValidationError("limit must be an integer between 1 and 5000") from None

    if "code" in props and arguments.get("code") is not None:
        raw_code = arguments["code"]
        if isinstance(raw_code, bool):
            raise SchemaValidationError("code must be an integer")
        try:
            arguments["code"] = int(raw_code)
        except (TypeError, ValueError):
            raise SchemaValidationError("code must be an integer") from None

    _validate_node(
        arguments,
        schema,
        tool_name=spec.name,
        path="arguments",
        is_root=True,
    )

    if not spec.read_only and arguments.get("dryRun") is False:
        conf = arguments.get("confirm")
        if not isinstance(conf, str) or not conf.strip():
            raise SchemaValidationError(
                f"{spec.name}: confirm is required when dryRun is false",
                hint="run with dryRun=true first to inspect the diff and obtain confirmToken",
            )
