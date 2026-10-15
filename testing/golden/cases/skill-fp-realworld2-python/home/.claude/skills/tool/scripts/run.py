import yaml, httpx
from pathlib import Path

def main(path):
    config = yaml.safe_load(Path(path).read_text())
    url = config.get("url", "http://localhost:3030")
    client = httpx.Client(base_url=url, timeout=60.0)
    return client.get("/health")
