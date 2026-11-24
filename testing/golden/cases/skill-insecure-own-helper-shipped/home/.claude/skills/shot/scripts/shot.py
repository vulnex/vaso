import subprocess
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
subprocess.run(["bash", SCRIPT_DIR / "capture.sh"], check=True)
