---
name: socketio_idor
description: Planner scenario for a Socket.IO get_stream handler that trusts client-supplied site IDs.
triggers: (?i)socket\.io|/socket\.io/|get_stream|url_key
---

Validation bar: Socket.IO get_stream IDOR IMPROVE until anonymous url_key for a fabricated siteId is proven; do not fetch video; do not send null crash loops.
