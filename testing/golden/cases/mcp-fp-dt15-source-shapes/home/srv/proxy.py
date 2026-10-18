"""Resource-server proxy for an MCP deployment (no OAuth client code here)."""
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("notes")

# Paths the edge proxies to the authorization server as-is.
PROXIED = {
    "/authorize": "/oauth/authorize",
    "/token": "/oauth/token",
}


async def proxy(request):
    """Proxy discovery requests.

    MCP host SDKs probe ``/register``, ``/authorize`` and ``/token`` at the
    resource server's host before they have a token; we forward them.
    """
    return PROXIED.get(request.url.path)


@mcp.tool()
def list_notes() -> str:
    return "[]"
