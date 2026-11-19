"""Import first in every test: points NetSentinel's data folder at a throw-away directory."""
import os
import sys
import tempfile

HOME = tempfile.mkdtemp(prefix="netsentinel-test-")
os.environ["HOME"] = HOME
os.environ["USERPROFILE"] = HOME
os.environ.pop("ANTHROPIC_API_KEY", None)
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
