import os
import sys

# Ensure the root directory of the repository is on sys.path
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from main import app

# Expose both app and handler for Vercel Serverless Function runtime compatibility
handler = app
