"""nginxvet — zero-dependency, evidence-first nginx configuration security auditor.

Parses nginx.conf (including ``include`` expansion) into a block tree with byte
offsets, then reasons in three passes:

* ``directive`` (NGV1xx) — one directive and the value it exposes,
* ``relation`` (NGV2xx) — server/location inheritance and override traps,
* ``crossfile`` (NGV3xx) — what include expansion did to the effective tree.

The flagship finding is NGV201, the ``add_header`` inheritance trap: a
location with any ``add_header`` silently drops every server-level security
header.  ``nginxvet effective`` answers what actually applies to a host.
"""

from .__about__ import __version__

__all__ = ["__version__"]
