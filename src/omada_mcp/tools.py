"""Backward-compatible MCP tool registry and domain re-export facade."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from .config import Config, ConfigError
from .domains._tool_model import _TOOL_CATEGORIES, Tool, normalize_mac
from .domains.audit_snapshot import _findings_healthy as _findings_healthy
from .domains.clients_read import _fetch_clients as _fetch_clients
from .domains.clients_read import _paginate_client_rows as _paginate_client_rows
from .domains.devices_read import project_device, project_wlan
from .domains.tool_specs_read import READ_TOOLS
from .domains.tool_specs_write_a import WRITE_TOOLS_A
from .domains.tool_specs_write_b import WRITE_TOOLS_B

__all__ = [
    "TOOLS",
    "TOOL_MAP",
    "Tool",
    "get_tool",
    "normalize_mac",
    "project_device",
    "project_wlan",
    "tool_descriptors",
]


TOOLS: list[Tool] = [
    *READ_TOOLS,
    *WRITE_TOOLS_A,
    *WRITE_TOOLS_B,
]

TOOL_MAP: dict[str, Tool] = {tool.name: tool for tool in TOOLS}


def get_tool(name: str) -> Tool | None:
    return TOOL_MAP.get(str(name or ""))


def tool_descriptors(
    config: Config | None = None,
    include_all: bool = False,
    write_tools: Sequence[str] | None = None,
    *,
    schema_mode: str | None = None,
    categories: Sequence[str] | None = None,
) -> list[dict[str, Any]]:
    """Return MCP tool descriptors filtered by config/allowlist, schema mode, and categories."""
    eff_mode = (
        schema_mode
        if schema_mode is not None
        else (getattr(config, "schema_mode", "slim") if config is not None else "slim")
    )
    if str(eff_mode or "slim").strip().lower() not in ("slim", "full"):
        raise ConfigError(
            f"invalid schema_mode {eff_mode!r}; expected 'slim' or 'full'",
            key="OMADA_SCHEMA_MODE",
        )
    eff_cats_raw = (
        categories
        if categories is not None
        else (getattr(config, "tool_categories", ()) if config is not None else ())
    )
    eff_cats = {str(c).strip().lower() for c in eff_cats_raw if str(c).strip()}
    unknown_cats = eff_cats - set(_TOOL_CATEGORIES.values())
    if unknown_cats:
        raise ConfigError(
            f"unknown tool category filter: {', '.join(sorted(unknown_cats))}",
            hint="valid categories: core, diagnostics, switch, wifi, routing, security, rollback",
            key="OMADA_TOOL_CATEGORIES",
        )

    if include_all:
        selected: Sequence[Tool] = TOOLS
    else:
        enabled_writes: set[str] = set()
        if config is not None:
            if not config.read_only:
                enabled_writes = set(config.write_tools)
        elif write_tools is not None:
            enabled_writes = set(write_tools)
        selected = tuple(
            tool for tool in TOOLS
            if tool.read_only or tool.name in enabled_writes
        )

    return [
        tool.descriptor(schema_mode=eff_mode)
        for tool in selected
        if not eff_cats or tool.category in eff_cats
    ]
