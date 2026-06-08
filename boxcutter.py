#!/usr/bin/env python3
"""boxcutter entry point.

Run straight from source with:

    python3 boxcutter.py <tool> <target> [options]
    python3 boxcutter.py --list
"""

import sys

from boxcutter.cli import main

if __name__ == "__main__":
    sys.exit(main())
