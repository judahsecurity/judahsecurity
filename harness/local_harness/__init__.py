"""
Aegis Harness — workstation-scale tooling for driving the Aegis Vanguard
autonomous pentester across many targets in batch and for benchmarking its
detection accuracy against a known-vulnerable corpus.

Two entry points, mirroring the workflow of a source-code hunting harness but
adapted for black-box / DAST scanning:

    python -m local_harness.batch.run scan
    python -m local_harness.benchmark.run

See README.md for the full guide.
"""

__version__ = "0.1.0"
