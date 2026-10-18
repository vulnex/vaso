import subprocess


def version_single(python_path):
    proc = subprocess.run([str(python_path), "-c", "import sys; print(sys.version_info[:2])"], capture_output=True, text=True)
    return proc.stdout
