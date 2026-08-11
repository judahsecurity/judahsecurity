# Aegis Harness (pointer)

The full harness guide lives next to the code:

**→ [harness/README.md](../harness/README.md)**

### What it is

Workstation tooling to:

1. **Batch-scan** many authorized targets with Aegis Vanguard (`run_pentest.py`)
2. **Benchmark** detection accuracy (recall / precision / F1 or CTF flag success)
3. Gate CI on minimum recall / success rate

### How it connects to the platform agent

| Layer | Role |
|-------|------|
| `aegis-vanguard/` | Autonomous scanner under test |
| `harness/` | Drives Vanguard, collects `findings.jsonl`, judges vs ground truth |
| ASM agent (`backend/.../agent/`) | In-product tester process (engagement brain) — see [TESTER_PROCESS_AND_ENGAGEMENT_BRAIN.md](./TESTER_PROCESS_AND_ENGAGEMENT_BRAIN.md) |

Use harness ground-truth **tags** (`default_credentials`, `ssrf`, `idor`, …) when
you want benchmarks to reflect chain/logic quality, not Nuclei volume alone.

### Minimal commands

```bash
cd harness
pip install -e ".[dev]"
python -m local_harness.batch.run scan
python -m local_harness.benchmark.run \
  --ground-truth local_harness/benchmark/ground_truth/EXAMPLE.json
python -m pytest tests/
```
