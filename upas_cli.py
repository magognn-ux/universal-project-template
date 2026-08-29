#!/usr/bin/env python3
"""
UPAS — Universal Project Automation Standard CLI Entrypoint.
"""

import sys
from upas_core.cli.main import main

if __name__ == "__main__":
    sys.exit(main())
