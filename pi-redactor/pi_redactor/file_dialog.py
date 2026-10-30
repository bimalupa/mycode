"""Native folder / file picker for the local machine.

Streamlit has no folder picker, so a Tk dialog is opened in a separate Python process (Tk must own its own
main thread). Works when the app runs on the user's PC; returns None when no desktop is available.
"""
import json
import subprocess
import sys

_SCRIPT = r"""
import json, sys, tkinter as tk
from tkinter import filedialog
mode, initial, patterns = sys.argv[1], sys.argv[2], sys.argv[3]
root = tk.Tk()
root.withdraw()
root.attributes("-topmost", True)
root.update()
if mode == "folder":
    picked = filedialog.askdirectory(parent=root, initialdir=initial, title="Select a folder to scan")
    result = [picked] if picked else []
else:
    picked = filedialog.askopenfilenames(parent=root, initialdir=initial, title="Select documents to scan",
                                         filetypes=[("Supported documents", patterns), ("All files", "*.*")])
    result = list(picked)
root.destroy()
print(json.dumps(result))
"""


def browse(mode: str, initial_dir: str, patterns: str = "*.*") -> list[str] | None:
    """mode: 'folder' or 'files'. Returns picked paths ([] if cancelled) or None if no dialog is possible."""
    try:
        proc = subprocess.run([sys.executable, "-c", _SCRIPT, mode, initial_dir, patterns],
                              capture_output=True, text=True, timeout=900)
    except (OSError, subprocess.TimeoutExpired):
        return None
    lines = proc.stdout.strip().splitlines()
    if proc.returncode != 0 or not lines:
        return None
    return json.loads(lines[-1])
