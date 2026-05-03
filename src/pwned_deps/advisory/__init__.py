"""Advisory data + sources.

* `types` — `Advisory`, `Severity` dataclasses.
* `osv_client` — talks to https://api.osv.dev (allow-listed per
  BUILD_BRIEF §2.3).
* `cache` — local SQLite cache so we work offline and don't hammer OSV.
"""

from pwned_deps.advisory.cache import Cache
from pwned_deps.advisory.osv_client import OsvClient
from pwned_deps.advisory.types import Advisory, Severity

__all__ = ["Advisory", "Cache", "OsvClient", "Severity"]
