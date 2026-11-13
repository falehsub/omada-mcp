"""omada-mcp -- a zero-dependency MCP server for TP-Link Omada SDN controllers.

The package speaks the controller's internal **Web API v2** (the API the web UI
itself uses), so it works with a plain local account and needs no OAuth2 /
"Platform Integration" setup.

Public surface::

    from omada_mcp import load_config, OmadaClient, Server

    config = load_config()          # OMADA_ENV_FILE -> ./.env -> ~/.config/omada-mcp/.env
    server = Server(config)         # JSON-RPC over stdio
    server.serve()

CLI::

    omada-mcp            # run the MCP server on stdio
    omada-mcp --doctor   # self-test: env, TLS, login, version, site, tools
"""

from __future__ import annotations

__version__ = "1.2.2"
__all__ = ["__version__", "Config", "ConfigError", "OmadaClient", "OmadaError",
           "Server", "load_config"]


def __getattr__(name: str):  # keep `import omada_mcp` cheap for --version
    if name in ("Config", "ConfigError", "load_config"):
        from . import config as _config

        return getattr(_config, name)
    if name in ("OmadaClient", "OmadaError"):
        from . import client as _client

        return getattr(_client, name)
    if name == "Server":
        from . import server as _server

        return _server.Server
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
