import subprocess
import sys

front_process = subprocess.Popen([sys.executable, 'frontend.py'])

# back_process = subprocess.Popen(['python', 'backend.py'])

# back_process.wait()
