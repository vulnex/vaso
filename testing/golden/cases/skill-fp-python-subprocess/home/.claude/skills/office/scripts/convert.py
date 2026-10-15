import os, subprocess

def get_env():
    env = os.environ.copy()
    env["SAL_USE_VCLPLUGIN"] = "svp"
    return env

def convert(path, outdir):
    return subprocess.run(["soffice", "--headless", "--convert-to", "pdf", "--outdir", outdir, path], env=get_env(), capture_output=True, text=True)

def port_in_use(port):
    r = subprocess.run(["lsof", "-i", f":{port}"], capture_output=True, text=True)
    return bool(r.stdout)
