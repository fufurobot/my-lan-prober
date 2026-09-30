"""Allow ``python -m my_lan_prober``."""

from __future__ import annotations

import sys

from . import main

if __name__ == "__main__":
    main(sys.argv[1:])
