import subprocess
import sys
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("pdf")

# Fixed helper script, run in a child so a crash cannot kill the server.
_CHILD_SCRIPT = "import sys; print(open(sys.argv[1], 'rb').read(4))"


@mcp.tool()
def pdf_magic(pdf_path: str) -> str:
    proc = subprocess.run([sys.executable, "-c", _CHILD_SCRIPT, pdf_path], capture_output=True, text=True)
    return proc.stdout
