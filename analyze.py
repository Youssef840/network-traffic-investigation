#!/usr/bin/env python3
"""Backward-compatible entry point. Prefer `nti ...` or `python -m nti ...`."""

import sys

from nti.cli import main

if __name__ == "__main__":
    sys.exit(main())
