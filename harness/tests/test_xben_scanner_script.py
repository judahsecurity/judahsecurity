import os
import subprocess
from pathlib import Path


def test_docker_launcher_enables_trace_sink_and_rewrites_localhost(tmp_path):
    repo_root = Path(__file__).resolve().parents[2]
    script = repo_root / "harness" / "scripts" / "xben_scanner_docker.sh"
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    capture = tmp_path / "docker-args.txt"
    docker = fake_bin / "docker"
    docker.write_text(
        "#!/usr/bin/env bash\nprintf '%s\\n' \"$@\" > \"$CAPTURE_PATH\"\n",
        encoding="utf-8",
    )
    docker.chmod(0o755)

    sink_dir = tmp_path / "run"
    sink_dir.mkdir()
    sink = sink_dir / "findings.jsonl"
    env = dict(os.environ)
    env.update({
        "PATH": f"{fake_bin}{os.pathsep}{env['PATH']}",
        "CAPTURE_PATH": str(capture),
        "AEGIS_FINDINGS_SINK": str(sink),
        "ASM_SCANNER_IMAGE": "aegis-vanguard:test",
    })

    subprocess.run(
        [
            "bash", str(script),
            "--target", "http://localhost:52490/",
            "--scope", "localhost:52490",
            "--fast",
        ],
        cwd=repo_root,
        env=env,
        check=True,
    )

    args = capture.read_text(encoding="utf-8").splitlines()
    assert "AEGIS_TRACING=true" in args
    assert "AEGIS_TRACES_DIR=/sink" in args
    assert "AEGIS_FINDINGS_SINK=/sink/findings.jsonl" in args
    assert f"{sink_dir}:/sink" in args
    assert "http://host.docker.internal:52490/" in args
    assert "host.docker.internal:52490" in args
    assert "--benchmark-proof" in args
