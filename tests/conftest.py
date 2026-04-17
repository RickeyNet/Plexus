import datetime as _dt
import sys

# Python 3.11 added datetime.UTC as a convenience alias.  Polyfill it for
# older interpreters so the production code (which uses ``from datetime import
# UTC``) can be imported without modification during tests.
if sys.version_info < (3, 11) and not hasattr(_dt, "UTC"):
    _dt.UTC = _dt.timezone.utc

import pytest
