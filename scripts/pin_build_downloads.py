#!/usr/bin/env python3
"""Generate the SHA-256 manifests that fetch-verified checks image downloads against.

For every URL below, download it, hash it, and, when the publisher ships a
checksums file for the same release (or go.dev lists the hash), require the
two to agree. The manifest records which kind of evidence each hash has:

  publisher  the hash matches the project's own published checksum
  computed   no published checksum exists; the hash was taken from the
             download when the pin was made (review the version before
             accepting a change to these)

  python3 scripts/pin_build_downloads.py           # rewrite both manifests
  python3 scripts/pin_build_downloads.py --check   # verify the manifests list
                                                   # every URL, offline

Change a tool version by editing URLS here and in the Dockerfile, then rerun.
The Go toolchain is copied from the digest-pinned golang image instead of
downloaded, so it has no entry here.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GH = "https://github.com"


def both(template: str, arches: tuple[str, str]) -> list[str]:
    return [template.format(a=a) for a in arches]


AMD_ARM = ("amd64", "arm64")
X86_AARCH = ("x86_64", "aarch64")


def pd(tool: str, version: str) -> list[str]:
    return both(f"{GH}/projectdiscovery/{tool}/releases/download/v{version}/{tool}_{version}_linux_{{a}}.zip", AMD_ARM)


TRUFFLEHOG = "3.99.9"
TRIVY = "0.76.2"
FEROX = both(f"{GH}/epi052/feroxbuster/releases/download/v2.11.0/{{a}}-linux-feroxbuster.zip", X86_AARCH)
GITLEAKS = both(f"{GH}/gitleaks/gitleaks/releases/download/v8.18.4/gitleaks_8.18.4_linux_{{a}}.tar.gz", ("x64", "arm64"))
KITERUNNER = both(f"{GH}/assetnote/kiterunner/releases/download/v1.0.2/kiterunner_1.0.2_linux_{{a}}.tar.gz", AMD_ARM)
TRUFFLEHOG_URLS = both(
    f"{GH}/trufflesecurity/trufflehog/releases/download/v{TRUFFLEHOG}/trufflehog_{TRUFFLEHOG}_linux_{{a}}.tar.gz", AMD_ARM)
TRIVY_URLS = both(
    f"{GH}/aquasecurity/trivy/releases/download/v{TRIVY}/trivy_{TRIVY}_Linux-{{a}}.tar.gz", ("64bit", "ARM64"))
ZAP = [f"{GH}/zaproxy/zaproxy/releases/download/v2.16.1/ZAP_2.16.1_Linux.tar.gz"]

URLS = {
    "backend/docker/build-checksums.sha256": [
        # backend/Dockerfile
        *pd("nuclei", "3.3.7"), *pd("subfinder", "2.6.7"), *pd("httpx", "1.6.10"),
        *pd("dnsx", "1.2.1"), *pd("naabu", "2.3.3"), *pd("katana", "1.1.0"),
        *pd("chaos-client", "0.5.2"), *pd("tlsx", "1.1.7"), *pd("vulnx", "2.0.1"),
        *both(f"{GH}/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_{{a}}.tar.gz", AMD_ARM),
        *both(f"{GH}/owasp-amass/amass/releases/download/v4.2.0/amass_Linux_{{a}}.zip", AMD_ARM),
        *FEROX, *GITLEAKS, *KITERUNNER, *TRIVY_URLS,
        f"{GH}/OWASP/www-project-api-security-testing-framework/releases/download/v2.0.1/astf-v2.0.1.jar",
        # backend/Dockerfile.scanner
        *pd("nuclei", "3.7.0"), *pd("subfinder", "2.12.0"), *pd("httpx", "1.8.1"),
        *pd("naabu", "2.4.0"), *pd("dnsx", "1.2.3"), *pd("katana", "1.4.0"),
        *TRUFFLEHOG_URLS, *ZAP,
        *both("https://download.docker.com/linux/static/stable/{a}/docker-27.5.1.tgz", X86_AARCH),
        "https://raw.githubusercontent.com/trickest/resolvers/6047aa832a85852caa6ec7d0c2e071bd823a749e/resolvers.txt",
    ],
    "aegis-vanguard/docker/build-checksums.sha256": [
        *FEROX, *TRUFFLEHOG_URLS, *ZAP, *GITLEAKS,
        "https://raw.githubusercontent.com/danielmiessler/SecLists/cc28d5e100cadf6f8b9aa644ff748ac69d454174/Discovery/Web-Content/common.txt",
    ],
}


def _get(url: str, timeout: int = 60):
    request = urllib.request.Request(url, headers={"User-Agent": "build-pin/1.0"})
    return urllib.request.urlopen(request, timeout=timeout)


def sha256_of(url: str) -> str:
    digest = hashlib.sha256()
    with _get(url, timeout=600) as response:
        for chunk in iter(lambda: response.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


# Upstream never published these; the Dockerfile step skips the tool there.
UNPUBLISHED = {
    f"{GH}/projectdiscovery/naabu/releases/download/v2.3.3/naabu_2.3.3_linux_arm64.zip",
}

# Values the Dockerfiles assign to the variables inside fetch-verified URLs.
VARIABLES = {
    "PD_ARCH": AMD_ARM, "ARCH_SUFFIX": AMD_ARM, "KR_ARCH": AMD_ARM,
    "FX_ARCH": X86_AARCH, "DARCH": X86_AARCH, "GL_ARCH": ("x64", "arm64"),
    "TV_ARCH": ("64bit", "ARM64"), "ARCH": AMD_ARM,
}
DOCKERFILES = {
    "backend/docker/build-checksums.sha256": ["backend/Dockerfile", "backend/Dockerfile.scanner"],
    "aegis-vanguard/docker/build-checksums.sha256": ["aegis-vanguard/Dockerfile"],
}


def dockerfile_urls(path: Path) -> set[str]:
    """Concrete URLs a Dockerfile can pass to fetch-verified, for every architecture."""
    import itertools
    import re

    text = path.read_text()
    args = dict(re.findall(r"^\s*ARG\s+(\w+)=(\S+)", text, re.M))
    urls = set()
    for template in re.findall(r'fetch-verified\s+(?:\\\s*)?"?(https://[^"\s]+)"?', text):
        for name, value in args.items():
            template = template.replace("${" + name + "}", value)
        names = [n for n in VARIABLES if ("${" + n + "}" if not n.startswith("$(") else n) in template]
        for values in itertools.product(*(VARIABLES[n] for n in names)):
            url = template
            for name, value in zip(names, values):
                url = url.replace("${" + name + "}" if not name.startswith("$(") else name, value)
            urls.add(url)
    return urls


_published: dict[str, dict[str, str]] = {}


def _checksum_file(url: str) -> dict[str, str]:
    if url not in _published:
        table: dict[str, str] = {}
        try:
            with _get(url) as response:
                for line in response.read().decode("utf-8", "replace").splitlines():
                    parts = line.split()
                    if len(parts) >= 2 and len(parts[0]) == 64:
                        table[parts[-1].lstrip("*")] = parts[0].lower()
        except (urllib.error.URLError, OSError, ValueError):
            pass
        _published[url] = table
    return _published[url]


_go_index: dict[str, str] | None = None


def published_sha(url: str) -> str | None:
    global _go_index
    name = url.rsplit("/", 1)[1]
    if url.startswith("https://go.dev/dl/"):
        if _go_index is None:
            with _get("https://go.dev/dl/?mode=json&include=all") as response:
                _go_index = {f["filename"]: f["sha256"] for release in json.load(response)
                             for f in release.get("files", [])}
        return _go_index.get(name)
    if "/releases/download/" not in url:
        return None
    base = url.rsplit("/", 1)[0]
    stem = name.split("_linux")[0].split("_Linux")[0]
    version = base.rsplit("/", 1)[1].lstrip("v")
    tool = stem.split("_")[0]
    for candidate in (f"{tool}_{version}_checksums.txt", f"{stem}_checksums.txt",
                      "checksums.txt", f"{tool}_checksums.txt", "sha256sums.txt"):
        found = _checksum_file(f"{base}/{candidate}").get(name)
        if found:
            return found
    return None


def pin(url: str) -> tuple[str, str, str]:
    try:
        computed = sha256_of(url)
    except urllib.error.HTTPError as exc:
        return url, "", f"missing ({exc.code})"
    except (urllib.error.URLError, OSError) as exc:
        return url, "", f"unreachable ({exc})"
    published = published_sha(url)
    if published and published != computed:
        raise SystemExit(f"Checksum mismatch for {url}: published {published}, downloaded {computed}")
    return url, computed, "publisher" if published else "computed"


def write(manifest: str, rows: list[tuple[str, str, str]]) -> None:
    lines = [
        "# SHA-256 pins for build-time downloads, checked by fetch-verified.",
        "# Generated by scripts/pin_build_downloads.py; edit there, not here.",
        "# Format: <sha256> <url> <evidence>  (publisher | computed)",
    ]
    lines += [f"{sha} {url} {evidence}" for url, sha, evidence in rows if sha]
    path = ROOT / manifest
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n")


def check() -> int:
    missing = []
    for manifest, urls in URLS.items():
        path = ROOT / manifest
        pinned = {line.split()[1] for line in path.read_text().splitlines()
                  if line and not line.startswith("#")} if path.exists() else set()
        missing += [f"{manifest}: {url}" for url in urls
                    if url not in pinned and url not in UNPUBLISHED]
        for dockerfile in DOCKERFILES[manifest]:
            missing += [f"{dockerfile}: {url}" for url in sorted(dockerfile_urls(ROOT / dockerfile))
                        if url not in pinned and url not in UNPUBLISHED]
    if missing:
        print("Unpinned downloads:\n" + "\n".join(missing))
        return 1
    print("download manifests: complete")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.check:
        return check()
    unique = sorted({url for urls in URLS.values() for url in urls})
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        results = {url: row for url, *row in pool.map(pin, unique)}
    for url in unique:
        sha, evidence = results[url]
        print(f"{evidence:10} {url}")
    for manifest, urls in URLS.items():
        write(manifest, [(url, *results[url]) for url in urls])
    return 0


if __name__ == "__main__":
    sys.exit(main())
