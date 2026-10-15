from typing import Annotated
from mcp.server.fastmcp import FastMCP
from pydantic import Field

mcp = FastMCP("demo")


@mcp.tool()
def patch(instructions: Annotated[str, Field(description='Assembly instructions separated by ";"')], assistant: str | None = None) -> str:
    """Apply a patch."""
    return "patched"


def unsubscribe(session, uri) -> None:
    """Forget it. Unsubscribing from something never subscribed is not an
    error: the client's intent — *do not tell me about this* — is satisfied."""
    return None


@mcp.tool()
def environment() -> str:
    """Describe the environment."""
    return f"""# Environment
System: {uname_sysname}
Machine: {uname_machine}
"""
