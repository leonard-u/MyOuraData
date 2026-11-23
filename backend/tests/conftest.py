"""
Test setup.

The backend creates its data directory, SQLite file and config at import
time, and reads its security settings from the environment at import time,
so all of that must be configured before any ``backend.src`` import.
"""
import os
import sys
import tempfile

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

_DATA_DIR = tempfile.mkdtemp(prefix="cracked-oura-tests-")
os.environ["CRACKED_OURA_DATA_DIR"] = _DATA_DIR
os.environ["CRACKED_OURA_API_TOKEN"] = "test-token"
os.environ.setdefault("PLAYWRIGHT_BROWSERS_PATH", os.path.join(_DATA_DIR, "browsers"))
