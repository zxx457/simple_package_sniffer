import os
import sys

def check_environment():
    if os.geteuid() != 0:
        sys.exit("Error: Root privileges required for packet capture")
    
    if 'production' in os.uname().nodename.lower():
        sys.exit("Aborting: Prevented execution in production environment")