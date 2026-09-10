import signal

import pytest

from app.services import scan_runtime


class FakeProcess:
    def __init__(self, pid: int):
        self.pid = pid
        self.returncode = None


@pytest.mark.asyncio
async def test_terminate_scan_processes_targets_only_current_scan(monkeypatch):
    signals = []
    monkeypatch.setattr(
        scan_runtime.os,
        "killpg",
        lambda pid, sig: signals.append((pid, sig)),
    )
    first_token = scan_runtime.set_current_scan(101)
    scan_runtime._register(FakeProcess(1001), True)
    scan_runtime.reset_current_scan(first_token)

    second_token = scan_runtime.set_current_scan(202)
    scan_runtime._register(FakeProcess(2002), True)
    scan_runtime.reset_current_scan(second_token)

    terminated = await scan_runtime.terminate_scan_processes(101, grace_seconds=0)

    assert terminated == 1
    assert signals == [(1001, signal.SIGTERM), (1001, signal.SIGKILL)]
    scan_runtime.discard_scan_processes(202)


def test_process_registry_deduplicates_a_pid():
    token = scan_runtime.set_current_scan(303)
    process = FakeProcess(3003)
    scan_runtime._register(process, True)
    scan_runtime._register(process, True)
    scan_runtime.reset_current_scan(token)

    assert len(scan_runtime._processes[303]) == 1
    scan_runtime.discard_scan_processes(303)
