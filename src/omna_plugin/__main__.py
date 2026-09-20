"""Entry point for `python -m omna_plugin` and for the bundled binary.

The console script in pyproject.toml points at ``cli:main``; PyInstaller needs
a real module to start from, and having one also makes ``python -m omna_plugin``
work, which the daemon already relies on when it re-spawns itself.

The import is ABSOLUTE on purpose: PyInstaller runs this file as a top-level
script, where a relative import has no parent package and fails at startup.
"""

import sys

from omna_plugin.cli import main

if __name__ == "__main__":
    sys.exit(main())
