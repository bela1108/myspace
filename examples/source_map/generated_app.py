"""Generated output - do not edit.

Stands in for code a template engine would emit.  Bandit scans this file;
examples/source_map/source_map.json projects findings back to the templates.
"""
# === fragment one begins (generated line 7) ===
import subprocess
# === fragment one ends (generated line 8) ===


# === fragment two begins (generated line 12) ===
def build_command(user_input):
    return subprocess.Popen(user_input, shell=True)
# === fragment two ends (generated line 14) ===


# === fragment three begins (generated line 18) ===
import yaml


def load_config(blob):
    return yaml.load(blob)
# === fragment three ends (generated line 23) ===
