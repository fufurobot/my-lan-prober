"""Allow ``python -m my_lan_prober``.

The ``__name__`` check is the one branch here, and it is not a formality: this
file is *imported* by the test suite when it exercises the module entry point,
and running ``main()`` at import time would start a real scan.  Logging the
decision makes that explicit rather than leaving it as a line readers skim.
"""

from __future__ import annotations

import logging
import sys

from . import main

log = logging.getLogger(__name__)

if __name__ == "__main__":
    log.debug("invoked as a module; handing %d argument(s) to main()", len(sys.argv) - 1)
    main(sys.argv[1:])
else:
    log.debug("imported rather than run; not starting a scan")
