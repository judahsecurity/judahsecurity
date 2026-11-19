---
name: elasticsearch_exposure
description: Planner scenario for an unauthenticated Elasticsearch HTTP API (:9200, xpack.security disabled).
triggers: (?i):9200\b|elasticsearch|you know, for search|xpack\.security
---

Elasticsearch :9200 without auth is a foothold — prove index enum + sample read + PUT/DELETE aegis_test_index (no Painless RCE, no bulk dump).

Validation bar: Elasticsearch :9200 unauth IMPROVE until indices enumerated and write proven (PUT+DELETE aegis_test_index); do not dump all docs or run Painless RCE.

Finding bar: Elasticsearch :9200 banner alone is not a finding — prove indices + write via aegis_test_index.
