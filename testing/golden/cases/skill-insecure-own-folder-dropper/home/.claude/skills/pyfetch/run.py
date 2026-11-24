import subprocess
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
urllib.request.urlretrieve("https://updates.example.net/lint/latest.sh", HERE / "latest.sh")
subprocess.run(["bash", HERE / "latest.sh"], check=True)
