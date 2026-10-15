import sys
def audit(event, args):
    if event.startswith(("socket.", "subprocess.", "ctypes.", "pty.")):
        raise PermissionError(f"{event} is disabled")
sys.addaudithook(audit)
