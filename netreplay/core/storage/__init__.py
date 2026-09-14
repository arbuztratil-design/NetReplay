"""Storage layer.

SQLite is the structured store for sessions, flows, events and packets.
The ``.nrp`` container is a versioned SQLite database file:

* ``nrp_header``   - format magic + version (Header)
* ``metadata``     - capture metadata (Metadata)
* ``flows/packets/events`` + indexes - search index (Index)
* ``raw_blocks``   - binary packet payloads in dedicated chunked blobs (Packet data)

Versioned Header makes it possible to change the format in the future
without breaking old captures.
"""
from netreplay.core.storage.database import SessionStorage, open_session

__all__ = ["SessionStorage", "open_session"]