"""Import a commit-stamped JS/TS source manifest into the Neo4j graph.

Usage: PYTHONPATH=backend python -m app.services.graph_source_ingest manifest.json
Optional bundle mappings are a JSON array passed with --mappings. Each mapping
must identify a JS URL, a source path, and evidence ('source-map' or
'build-manifest'). Code is never linked to an observed bundle by name alone.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from pathlib import Path

from neo4j import GraphDatabase

from app.services.graph_identity import canonical_script_url, script_key, source_file_key


SCHEMA = [
    "CREATE CONSTRAINT source_repo_key IF NOT EXISTS FOR (n:SourceRepository) REQUIRE n.repo_key IS UNIQUE",
    "CREATE CONSTRAINT source_commit_key IF NOT EXISTS FOR (n:SourceCommit) REQUIRE n.commit_key IS UNIQUE",
    "CREATE CONSTRAINT source_file_id IF NOT EXISTS FOR (n:SourceFile) REQUIRE n.file_id IS UNIQUE",
    "CREATE CONSTRAINT code_symbol_id IF NOT EXISTS FOR (n:CodeSymbol) REQUIRE n.symbol_id IS UNIQUE",
    "CREATE CONSTRAINT source_route_id IF NOT EXISTS FOR (n:SourceRoute) REQUIRE n.route_id IS UNIQUE",
    "CREATE CONSTRAINT package_version_key IF NOT EXISTS FOR (n:PackageVersion) REQUIRE n.package_key IS UNIQUE",
    "CREATE INDEX source_file_org_path IF NOT EXISTS FOR (n:SourceFile) ON (n.organization_id, n.path)",
    "CREATE TEXT INDEX source_file_path_text IF NOT EXISTS FOR (n:SourceFile) ON (n.path)",
    "CREATE INDEX source_route_org_path IF NOT EXISTS FOR (n:SourceRoute) ON (n.organization_id, n.path)",
    "CREATE TEXT INDEX source_route_path_text IF NOT EXISTS FOR (n:SourceRoute) ON (n.path)",
]


def _key(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:32]


def _batches(rows: list, size: int = 200):
    for start in range(0, len(rows), size):
        yield rows[start:start + size]


def ingest_manifest(driver, manifest: dict, mappings: list[dict] | None = None) -> dict:
    """Idempotently add source files, symbols, imports and verified bundle links."""
    if manifest.get("schema_version") != 1:
        raise ValueError("Unsupported source graph manifest version")
    org_id = int(manifest["organization_id"])
    if org_id < 1:
        raise ValueError("organization_id must be positive")
    repository = str(manifest["repository"]).strip()
    commit = str(manifest["commit"]).strip()
    if not repository or len(commit) not in {40, 64} or not all(c in "0123456789abcdef" for c in commit.lower()):
        raise ValueError("A repository and full Git commit are required")
    repo_key = f"{org_id}:{repository}"
    commit_key = f"{repo_key}:{commit}"
    files = []
    for item in manifest.get("files", []):
        path = str(item.get("path") or "").strip()
        if not path or path.startswith("/") or "\\" in path or ".." in Path(path).parts:
            raise ValueError(f"Invalid source path: {path}")
        sha256 = str(item.get("sha256") or "")
        if not re.fullmatch(r"[0-9a-f]{64}", sha256):
            raise ValueError(f"Invalid source hash: {path}")
        files.append({
            "file_id": source_file_key(org_id, repository, commit, path),
            "path": path,
            "sha256": sha256,
            "language": str(item.get("language") or ""),
            "symbols": item.get("symbols") or [],
            "imports": item.get("imports") or [],
            "routes": item.get("routes") or [],
        })
    known_paths = {item["path"] for item in files}
    file_rows = [{k: f[k] for k in ("file_id", "path", "sha256", "language")} for f in files]
    symbol_rows = []
    route_rows = []
    local_imports = []
    package_imports = []
    for item in files:
        for symbol in item["symbols"]:
            name = str(symbol.get("name") or "")[:200]
            if not name:
                continue
            kind = str(symbol.get("kind") or "symbol")[:40]
            line = int(symbol.get("line") or 1)
            if line < 1:
                raise ValueError("Symbol line must be positive")
            symbol_rows.append({"file_id": item["file_id"], "name": name,
                                "kind": kind, "line": line,
                                "symbol_id": _key(f"{item['file_id']}:{name}:{kind}:{line}")})
        for route in item["routes"]:
            path = str(route.get("path") or "")[:500]
            method = str(route.get("method") or "").upper()[:16]
            if not path.startswith("/") or method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
                raise ValueError("Invalid source route")
            route_rows.append({"file_id": item["file_id"], "path": path,
                               "method": method,
                               "route_id": _key(f"{item['file_id']}:{method}:{path}")})
        for imp in item["imports"]:
            target = imp.get("resolved_path")
            specifier = str(imp.get("specifier") or "")[:300]
            if target and target in known_paths:
                local_imports.append({"from_id": item["file_id"],
                                      "to_id": source_file_key(org_id, repository, commit, target),
                                      "specifier": specifier})
            elif imp.get("package_name") and imp.get("version"):
                name = str(imp["package_name"])[:200]
                version = str(imp["version"])[:100]
                package_imports.append({"file_id": item["file_id"], "name": name,
                                        "version": version,
                                        "package_key": f"npm:{name}@{version}"})

    verified_mappings = []
    for mapping in mappings or manifest.get("bundle_mappings") or []:
        evidence = mapping.get("evidence")
        path = mapping.get("source_path")
        url = canonical_script_url(mapping.get("script_url"))
        if evidence not in {"source-map", "build-manifest"} or path not in known_paths or not url:
            raise ValueError("Bundle mappings require a known source path, URL and verified evidence")
        verified_mappings.append({"script_id": script_key(org_id, url),
                                  "file_id": source_file_key(org_id, repository, commit, path),
                                  "evidence": evidence})

    with driver.session() as session:
        for query in SCHEMA:
            session.run(query).consume()
        session.run("""
            MERGE (r:SourceRepository {repo_key: $repo_key})
            SET r.organization_id = $org_id, r.name = $repository
            MERGE (c:SourceCommit {commit_key: $commit_key})
            ON CREATE SET c.ingested_at = datetime()
            SET c.organization_id = $org_id, c.sha = $commit
            MERGE (r)-[:HAS_COMMIT]->(c)
        """, repo_key=repo_key, org_id=org_id, repository=repository,
             commit_key=commit_key, commit=commit).consume()
        for batch in _batches(file_rows):
            session.run("""
                MATCH (c:SourceCommit {commit_key: $commit_key})
                UNWIND $rows AS row
                MERGE (f:SourceFile {file_id: row.file_id})
                SET f.organization_id = $org_id, f.path = row.path,
                    f.sha256 = row.sha256, f.language = row.language,
                    f.repository = $repository, f.commit = $commit
                MERGE (c)-[:CONTAINS_FILE]->(f)
            """, commit_key=commit_key, org_id=org_id, repository=repository,
                 commit=commit, rows=batch).consume()
        for batch in _batches(symbol_rows):
            session.run("""
                UNWIND $rows AS row
                MATCH (f:SourceFile {file_id: row.file_id, organization_id: $org_id})
                MERGE (s:CodeSymbol {symbol_id: row.symbol_id})
                SET s.organization_id = $org_id, s.name = row.name,
                    s.kind = row.kind, s.line = row.line
                MERGE (f)-[:DECLARES]->(s)
            """, org_id=org_id, rows=batch).consume()
        for batch in _batches(route_rows):
            session.run("""
                UNWIND $rows AS row
                MATCH (f:SourceFile {file_id: row.file_id, organization_id: $org_id})
                MERGE (r:SourceRoute {route_id: row.route_id})
                SET r.organization_id = $org_id, r.path = row.path,
                    r.method = row.method
                MERGE (f)-[:IMPLEMENTS_ROUTE]->(r)
            """, org_id=org_id, rows=batch).consume()
        for batch in _batches(local_imports):
            session.run("""
                UNWIND $rows AS row
                MATCH (f:SourceFile {file_id: row.from_id, organization_id: $org_id})
                MATCH (target:SourceFile {file_id: row.to_id, organization_id: $org_id})
                MERGE (f)-[r:IMPORTS_FILE {specifier: row.specifier}]->(target)
            """, org_id=org_id, rows=batch).consume()
        for batch in _batches(package_imports):
            session.run("""
                UNWIND $rows AS row
                MATCH (f:SourceFile {file_id: row.file_id, organization_id: $org_id})
                MERGE (p:PackageVersion {package_key: row.package_key})
                SET p.name = row.name, p.version = row.version, p.ecosystem = 'npm'
                MERGE (f)-[:USES_PACKAGE]->(p)
            """, org_id=org_id, rows=batch).consume()
        for batch in _batches(verified_mappings):
            session.run("""
                UNWIND $rows AS row
                MATCH (j:JSResource {script_id: row.script_id, organization_id: $org_id})
                MATCH (f:SourceFile {file_id: row.file_id, organization_id: $org_id})
                MERGE (j)-[r:MAPS_TO_SOURCE {commit: $commit}]->(f)
                SET r.evidence = row.evidence
            """, org_id=org_id, commit=commit, rows=batch).consume()
    return {"files": len(files), "symbols": len(symbol_rows),
            "routes": len(route_rows),
            "local_imports": len(local_imports), "package_imports": len(package_imports),
            "bundle_mappings": len(verified_mappings)}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--mappings", type=Path)
    args = parser.parse_args()
    uri = os.environ.get("NEO4J_URI")
    password = os.environ.get("NEO4J_PASSWORD")
    if not uri or not password:
        parser.error("Set NEO4J_URI and NEO4J_PASSWORD")
    manifest = json.loads(args.manifest.read_text())
    mappings = json.loads(args.mappings.read_text()) if args.mappings else None
    with GraphDatabase.driver(uri, auth=(os.environ.get("NEO4J_USER", "neo4j"), password)) as driver:
        driver.verify_connectivity()
        print(json.dumps(ingest_manifest(driver, manifest, mappings)))


if __name__ == "__main__":
    main()
