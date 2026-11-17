"""Read target JavaScript like a reviewer reads source code.

Recon tools summarize scripts (endpoints, sinks, secrets, Retire.js matches);
this module lets the model read the code itself:

* :func:`reflow` re-flows minified bundles into one statement per line with
  brace indentation, without breaking strings, template literals, regex
  literals, or comments.
* :class:`ScriptStore` is a per-session, size-bounded set of readable files:
  fetched scripts, PROWL-captured scripts, and original sources recovered from
  same-origin source maps (``node_modules`` skipped).
* :func:`search_store` runs a guarded regex across every loaded file and
  returns hunks with context lines.

Text is redacted with :func:`content_shield.redact_sensitive` when a file is
materialized, so neither paging nor regex search can reveal (or be used as an
oracle for) a secret. The raw bytes stay in the evidence store.

Network I/O lives in ``tools.py`` (``ASMToolsManager._http_exchange``) so scope
checks and the pilot request budget always apply; this module is pure.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import unquote_to_bytes, urljoin, urlsplit

from app.services.agent.content_shield import redact_sensitive

# --- bounds -----------------------------------------------------------------

MAX_FILES = 300                      # files kept per session
MAX_TOTAL_CHARS = 16 * 1024 * 1024   # stored text per session
MAX_FILE_CHARS = 6 * 1024 * 1024     # one script or original source
MAX_SCRIPT_FETCH_BYTES = 6 * 1024 * 1024
MAX_SOURCE_MAP_BYTES = 12 * 1024 * 1024
MAX_SOURCES_PER_MAP = 400
MAX_LINE_CHARS = 240                 # longer lines are wrapped
MAX_INDENT_LEVELS = 24
MAX_READ_LINES = 500
DEFAULT_READ_LINES = 200
MAX_PATTERN_CHARS = 256
MAX_CONTEXT_LINES = 8
MAX_SEARCH_MATCHES = 200
SEARCH_TIME_BUDGET_S = 4.0
OUTPUT_CHAR_BUDGET = 16000


# --- reflow -------------------------------------------------------------------

_PLAIN_RUN = re.compile(r"[^\"'`/{}();,\[\]\s\\]+")
_WORD_END = re.compile(r"([A-Za-z_$][\w$]*)$")
# A ``/`` after these keywords starts a regex literal, not a division.
_REGEX_KEYWORDS = frozenset({
    "return", "typeof", "instanceof", "case", "do", "else", "in", "of", "new",
    "delete", "void", "throw", "yield", "await",
})
# After ``}`` these keep the same line: `}).x`, `},`, `} else`, `} while (...)`.
_CONTINUES_EXPRESSION = re.compile(r"[)\],;.(:?|&+=`]|(?:else|catch|finally|while)\b")


def looks_minified(text: str) -> bool:
    """True when most characters sit on very long lines (bundler output)."""
    if len(text) < 1024:
        return False
    long_chars = sum(len(line) for line in text.split("\n") if len(line) > 400)
    return long_chars > 0.3 * len(text)


def _regex_allowed(last: str) -> bool:
    """Whether a ``/`` after token ``last`` starts a regex literal (vs. division)."""
    if not last or last in {"(", "[", "{", "}", ",", ";", "/"}:
        return True
    if last in {")", "]", "str", "regex", "tmpl", "x"}:
        return False
    word = _WORD_END.search(last)
    if word:
        return word.group(1) in _REGEX_KEYWORDS
    # Numbers and member access end an operand; operators (= + ! & | ? : ...) do not.
    return not (last[-1].isdigit() or last[-1] == ".")


def _scan_string(text: str, i: int) -> int:
    """Return the index just past the quoted string starting at ``i``."""
    quote, n = text[i], len(text)
    j = i + 1
    while j < n:
        c = text[j]
        if c == "\\":
            j += 2
            continue
        if c == quote or c == "\n":
            return j + 1
        j += 1
    return n


def _scan_regex(text: str, i: int) -> int:
    n, j, in_class = len(text), i + 1, False
    while j < n:
        c = text[j]
        if c == "\\":
            j += 2
            continue
        if c == "\n":
            return j
        if in_class:
            in_class = c != "]"
        elif c == "[":
            in_class = True
        elif c == "/":
            j += 1
            while j < n and (text[j].isalnum() or text[j] in "_$"):
                j += 1
            return j
        j += 1
    return n


def _scan_template_chunk(text: str, i: int) -> Tuple[int, bool]:
    """Scan template text from ``i``; return (end, opened_substitution)."""
    n, j = len(text), i
    while j < n:
        c = text[j]
        if c == "\\":
            j += 2
            continue
        if c == "`":
            return j + 1, False
        if c == "$" and j + 1 < n and text[j + 1] == "{":
            return j + 2, True
        j += 1
    return n, False


class _Writer:
    def __init__(self) -> None:
        self.lines: List[str] = []
        self.cur: List[str] = []
        self.depth = 0

    def put(self, s: str) -> None:
        if not s:
            return
        if not self.cur:
            self.cur.append("  " * min(self.depth, MAX_INDENT_LEVELS))
            s = s.lstrip(" ")
            if not s:
                return
        # Verbatim tokens (comments, template text) may hold newlines.
        if "\n" in s:
            parts = s.split("\n")
            self.cur.append(parts[0])
            for part in parts[1:]:
                self.newline(force=True)
                self.cur.append(part)
            return
        self.cur.append(s)

    def space(self) -> None:
        if self.cur and not self.cur[-1].endswith(" "):
            self.cur.append(" ")

    def newline(self, force: bool = False) -> None:
        line = "".join(self.cur).rstrip()
        if line.strip() or force:
            self.lines.append(line)
        self.cur = []

    def done(self) -> List[str]:
        if self.cur:
            self.newline()
        return self.lines


def _next_significant(text: str, i: int) -> str:
    n = len(text)
    while i < n and text[i] in " \t\r\n":
        i += 1
    return text[i:i + 8]


def reflow(text: str) -> List[str]:
    """Re-flow minified JavaScript into readable lines. Never raises on bad input.

    One statement per line, a line break after ``{`` and around ``}``, a break
    after commas at the top level of a block (object literals, declarations),
    and two-space indentation by brace depth. Strings, template literals, regex
    literals and comments are copied verbatim.
    """
    out = _Writer()
    n = len(text)
    i = 0
    last = ""             # last significant token, for regex-vs-division
    parens = 0            # ()/[] depth within the current brace block
    paren_stack: List[int] = []
    brace_level = 0
    template_stack: List[int] = []  # brace_level at each open ${

    def read_template(start: int) -> int:
        nonlocal last
        end, opened = _scan_template_chunk(text, start)
        out.put(text[start:end])
        if opened:
            template_stack.append(brace_level)
            last = "("
        else:
            last = "tmpl"
        return end

    while i < n:
        c = text[i]
        m = _PLAIN_RUN.match(text, i)
        if m:
            out.put(m.group(0))
            last = m.group(0)
            i = m.end()
            continue
        if c in " \t\r\n":
            j = i
            while j < n and text[j] in " \t\r\n":
                j += 1
            if "\n" in text[i:j] and parens == 0:
                out.newline()
            else:
                out.space()
            i = j
            continue
        if c in "\"'":
            j = _scan_string(text, i)
            out.put(text[i:j])
            last, i = "str", j
            continue
        if c == "`":
            out.put("`")
            i = read_template(i + 1)
            continue
        if c == "\\":
            out.put(text[i:i + 2])
            last, i = "x", i + 2
            continue
        if c == "/":
            nxt = text[i + 1] if i + 1 < n else ""
            if nxt == "/":
                j = text.find("\n", i)
                j = n if j < 0 else j
                out.put(text[i:j])
                out.newline()
                i = j
                continue
            if nxt == "*":
                j = text.find("*/", i + 2)
                j = n if j < 0 else j + 2
                out.put(text[i:j])
                i = j
                continue
            if _regex_allowed(last):
                j = _scan_regex(text, i)
                out.put(text[i:j])
                last, i = "regex", j
                continue
            out.put("/")
            last, i = "/", i + 1
            continue
        if c == "{":
            out.put("{")
            brace_level += 1
            paren_stack.append(parens)
            parens = 0
            out.depth += 1
            out.newline()
            last, i = "{", i + 1
            continue
        if c == "}":
            if template_stack and template_stack[-1] == brace_level:
                template_stack.pop()
                out.put("}")
                i = read_template(i + 1)
                continue
            out.newline()
            brace_level = max(0, brace_level - 1)
            parens = paren_stack.pop() if paren_stack else 0
            out.depth = max(0, out.depth - 1)
            out.put("}")
            i += 1
            ahead = _next_significant(text, i)
            if _CONTINUES_EXPRESSION.match(ahead):
                if ahead[:1].isalpha():
                    out.space()
            else:
                out.newline()
            last = "}"
            continue
        if c in "([":
            out.put(c)
            parens += 1
            last, i = c, i + 1
            continue
        if c in ")]":
            out.put(c)
            parens = max(0, parens - 1)
            last, i = c, i + 1
            continue
        if c == ";":
            out.put(";")
            if parens == 0:
                out.newline()
            else:
                out.space()
            last, i = ";", i + 1
            continue
        if c == ",":
            out.put(",")
            if parens == 0 and brace_level > 0:
                out.newline()
            last, i = ",", i + 1
            continue
        out.put(c)  # unreachable for well-formed input; keep any stray char
        last, i = c, i + 1
    return out.done()


def wrap_long_lines(lines: Iterable[str], limit: int = MAX_LINE_CHARS) -> List[str]:
    """Split lines longer than ``limit`` so every line is cheap to show and search."""
    wrapped: List[str] = []
    for line in lines:
        if len(line) <= limit:
            wrapped.append(line)
            continue
        indent = line[: len(line) - len(line.lstrip(" "))][: 2 * MAX_INDENT_LEVELS]
        body = line[len(indent):]
        step = max(40, limit - len(indent))
        for start in range(0, len(body), step):
            wrapped.append(indent + body[start:start + step])
    return wrapped


def readable_lines(text: str) -> Tuple[List[str], bool]:
    """Return display lines and whether the text was re-flowed from minified."""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    if looks_minified(text):
        return wrap_long_lines(reflow(text)), True
    return wrap_long_lines(text.split("\n")), False


# --- source maps ----------------------------------------------------------------

_SOURCE_MAP_COMMENT = re.compile(r"(?://|/\*)\s*[#@]\s*sourceMappingURL\s*=\s*([^\s'\"*]+)")
_XSSI_PREFIX = ")]}'"


def find_source_map_ref(text: str, headers: Optional[Dict[str, Any]] = None) -> str:
    """The script's declared source map reference (header first, then trailing comment)."""
    for key, value in (headers or {}).items():
        if str(key).lower() in ("sourcemap", "x-sourcemap") and str(value).strip():
            return str(value).strip()
    tail = text[-4096:] if text else ""
    matches = _SOURCE_MAP_COMMENT.findall(tail)
    return matches[-1].strip() if matches else ""


def decode_data_uri(ref: str) -> Optional[str]:
    """Decode an inline ``data:`` source map; None if it is not one or is invalid."""
    if not ref.lower().startswith("data:") or "," not in ref:
        return None
    meta, payload = ref[5:].split(",", 1)
    try:
        raw = (base64.b64decode(payload, validate=False) if ";base64" in meta.lower()
               else unquote_to_bytes(payload))
    except (binascii.Error, ValueError):
        return None
    if len(raw) > MAX_SOURCE_MAP_BYTES:
        return None
    return raw.decode("utf-8", errors="replace")


def resolve_source_map_url(script_url: str, ref: str) -> str:
    return urljoin(script_url, ref)


def script_key(url: str) -> str:
    """Store key for a script URL: cache-busting query and fragment dropped (as PROWL does)."""
    parts = urlsplit(str(url or "").strip())
    if not parts.scheme or not parts.netloc:
        return str(url or "").strip()
    return f"{parts.scheme.lower()}://{parts.netloc.lower()}{parts.path or '/'}"


def same_origin(a: str, b: str) -> bool:
    def key(url: str):
        p = urlsplit(url)
        if p.scheme not in ("http", "https") or not p.hostname or p.username or p.password:
            return None
        return p.scheme, p.hostname.lower().rstrip("."), p.port or (443 if p.scheme == "https" else 80)

    ka = key(a)
    return ka is not None and ka == key(b)


def normalize_source_path(path: str, source_root: str = "") -> str:
    """``webpack://app/./src/api.ts`` → ``app/src/api.ts``."""
    value = f"{source_root.rstrip('/')}/{path}" if source_root and "://" not in path else path
    value = re.sub(r"^[A-Za-z][\w+.-]*://", "", value)
    value = value.split("?", 1)[0]
    parts: List[str] = []
    for part in value.replace("\\", "/").split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if parts:
                parts.pop()
            continue
        parts.append(part)
    return "/".join(parts) or path


_NODE_MODULES = re.compile(r"(?:^|/)node_modules(?:/|$)")


def is_vendored(path: str) -> bool:
    return bool(_NODE_MODULES.search(path.replace("\\", "/")))


@dataclass
class SourceMapSources:
    sources: List[Tuple[str, str]] = field(default_factory=list)
    skipped_node_modules: int = 0
    without_content: int = 0
    over_limit: int = 0


def parse_source_map(data: str) -> SourceMapSources:
    """Extract (path, content) pairs from a v3 source map, including index maps.

    Raises ValueError when the document is not a source map.
    """
    text = (data or "").lstrip("\ufeff")
    if text.startswith(_XSSI_PREFIX):
        text = text.split("\n", 1)[1] if "\n" in text else ""
    try:
        doc = json.loads(text)
    except ValueError as exc:
        raise ValueError("Source map is not valid JSON") from exc
    if not isinstance(doc, dict) or ("sources" not in doc and "sections" not in doc):
        raise ValueError("Document is not a source map (no sources or sections)")
    result = SourceMapSources()
    seen: set = set()

    def visit(node: Dict[str, Any], depth: int = 0) -> None:
        if depth > 4 or not isinstance(node, dict):
            return
        for section in node.get("sections") or []:
            if isinstance(section, dict):
                visit(section.get("map") or {}, depth + 1)
        sources = node.get("sources") or []
        contents = node.get("sourcesContent") or []
        root = str(node.get("sourceRoot") or "")
        if not isinstance(sources, list):
            return
        for index, raw_path in enumerate(sources):
            path = normalize_source_path(str(raw_path or f"source-{index}"), root)
            if is_vendored(path):
                result.skipped_node_modules += 1
                continue
            content = contents[index] if isinstance(contents, list) and index < len(contents) else None
            if not isinstance(content, str) or not content.strip():
                result.without_content += 1
                continue
            if path in seen:
                continue
            if len(result.sources) >= MAX_SOURCES_PER_MAP:
                result.over_limit += 1
                continue
            seen.add(path)
            result.sources.append((path, content))

    visit(doc)
    return result


# --- store ------------------------------------------------------------------------

@dataclass
class ScriptFile:
    file_id: str
    key: str
    url: str
    name: str
    kind: str                     # script | inline | original_source
    raw: Optional[str] = None     # pending text until first read/search
    lines: Optional[List[str]] = None
    chars: int = 0
    sha256: str = ""
    reflowed: bool = False
    redactions: Dict[str, int] = field(default_factory=dict)
    evidence_id: str = ""
    origin: str = ""              # fetched | prowl_inspect_js | source_map
    parent_id: str = ""
    source_map_ref: str = ""
    source_map_url: str = ""
    source_map_state: str = ""    # "" | pending | loaded | none | cross_origin | failed: ...
    source_map_children: List[str] = field(default_factory=list)

    def materialize(self) -> List[str]:
        if self.lines is None:
            redacted, counts = redact_sensitive(self.raw or "")
            self.redactions = counts
            self.lines, self.reflowed = readable_lines(redacted)
            self.raw = None
        return self.lines

    def summary(self) -> Dict[str, Any]:
        row: Dict[str, Any] = {
            "file": self.file_id, "kind": self.kind, "name": self.name,
            "chars": self.chars,
        }
        if self.lines is not None:
            row["lines"] = len(self.lines)
            row["reflowed"] = self.reflowed
        if self.url and self.url != self.name:
            row["url"] = self.url
        if self.parent_id:
            row["from_source_map_of"] = self.parent_id
        if self.source_map_state:
            row["source_map"] = self.source_map_state
        if self.evidence_id:
            row["evidence_id"] = self.evidence_id
        return row


class ScriptStore:
    """Per-session, bounded set of readable script files (oldest evicted first)."""

    def __init__(self, max_files: int = MAX_FILES, max_total_chars: int = MAX_TOTAL_CHARS):
        self.max_files = max_files
        self.max_total_chars = max_total_chars
        self.files: "OrderedDict[str, ScriptFile]" = OrderedDict()
        self.by_key: Dict[str, str] = {}
        self.total_chars = 0
        self.evicted = 0
        self.failed_urls: Dict[str, str] = {}
        self._counter = 0

    def __len__(self) -> int:
        return len(self.files)

    def add(self, *, key: str, url: str, name: str, kind: str, text: str,
            evidence_id: str = "", origin: str = "", parent_id: str = "",
            source_map_ref: str = "") -> Tuple[Optional[ScriptFile], str]:
        """Add or refresh a file. Returns (file, note); file is None if refused."""
        if not isinstance(text, str) or not text.strip():
            return None, "empty"
        note = ""
        if len(text) > MAX_FILE_CHARS:
            text = text[:MAX_FILE_CHARS]
            note = f"truncated to {MAX_FILE_CHARS} chars"
        digest = hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()
        existing_id = self.by_key.get(key)
        if existing_id and existing_id in self.files:
            existing = self.files[existing_id]
            if existing.sha256 == digest:
                self.files.move_to_end(existing_id)
                if evidence_id and not existing.evidence_id:
                    existing.evidence_id = evidence_id
                return existing, "unchanged"
            self._remove(existing_id)
        self._counter += 1
        entry = ScriptFile(
            file_id=f"js{self._counter}", key=key, url=url, name=name, kind=kind,
            raw=text, chars=len(text), sha256=digest, evidence_id=evidence_id,
            origin=origin, parent_id=parent_id, source_map_ref=source_map_ref,
            source_map_state="pending" if source_map_ref else "",
        )
        self.files[entry.file_id] = entry
        self.by_key[key] = entry.file_id
        self.total_chars += entry.chars
        self._enforce(keep=entry.file_id)
        return entry, note

    def _remove(self, file_id: str) -> None:
        entry = self.files.pop(file_id, None)
        if entry is None:
            return
        self.total_chars -= entry.chars
        if self.by_key.get(entry.key) == file_id:
            self.by_key.pop(entry.key, None)

    def _enforce(self, keep: str) -> None:
        while len(self.files) > self.max_files or self.total_chars > self.max_total_chars:
            victim = next((fid for fid in self.files if fid != keep), None)
            if victim is None:
                break
            self._remove(victim)
            self.evicted += 1

    def resolve(self, ref: str) -> Tuple[Optional[ScriptFile], List[str]]:
        """Find a file by id, key/URL, or a unique name/URL suffix. Returns (file, candidates)."""
        ref = str(ref or "").strip()
        if not ref:
            return None, []
        if ref in self.files:
            return self.files[ref], []
        if ref in self.by_key and self.by_key[ref] in self.files:
            return self.files[self.by_key[ref]], []
        for entry in self.files.values():
            if ref in (entry.url, entry.name):
                return entry, []
        tail = ref.lstrip("./")
        hits = [e for e in self.files.values()
                if e.name.endswith(tail) or e.url.split("?", 1)[0].endswith(tail)]
        if len(hits) == 1:
            return hits[0], []
        return None, [e.file_id + " " + e.name for e in hits[:12]]

    def select(self, file_filter: str = "") -> List[ScriptFile]:
        flt = str(file_filter or "").strip()
        if not flt:
            return list(self.files.values())
        wanted = {part.strip() for part in re.split(r"[\s,]+", flt) if part.strip()}
        rows = []
        for entry in self.files.values():
            if (entry.file_id in wanted or any(w in entry.name or w in entry.url for w in wanted)):
                rows.append(entry)
        return rows

    def materialize(self, entries: Optional[Iterable[ScriptFile]] = None) -> None:
        for entry in list(entries if entries is not None else self.files.values()):
            entry.materialize()

    def listing(self, limit: int = 80) -> Dict[str, Any]:
        rows = [entry.summary() for entry in list(self.files.values())[-limit:]]
        return {
            "files": rows, "file_count": len(self.files), "total_chars": self.total_chars,
            "limits": {"max_files": self.max_files, "max_total_chars": self.max_total_chars},
            "evicted": self.evicted,
        }


def add_source_map_sources(store: ScriptStore, parent: ScriptFile, map_url: str,
                           parsed: SourceMapSources, evidence_id: str = "") -> List[ScriptFile]:
    added = []
    for path, content in parsed.sources:
        entry, _note = store.add(
            key=f"{map_url}::{path}", url=map_url, name=path, kind="original_source",
            text=content, evidence_id=evidence_id, origin="source_map", parent_id=parent.file_id,
        )
        if entry is not None:
            added.append(entry)
    parent.source_map_children = [e.file_id for e in added]
    return added


# --- rendering ------------------------------------------------------------------------

def render_page(entry: ScriptFile, start_line: int = 1, max_lines: int = DEFAULT_READ_LINES,
                char_budget: int = OUTPUT_CHAR_BUDGET) -> Dict[str, Any]:
    lines = entry.materialize()
    total = len(lines)
    start = max(1, int(start_line or 1))
    count = max(1, min(int(max_lines or DEFAULT_READ_LINES), MAX_READ_LINES))
    width = len(str(total))
    shown: List[str] = []
    used = 0
    end = start - 1
    for number in range(start, min(total, start + count - 1) + 1):
        row = f"{number:>{width}}| {lines[number - 1]}"
        if shown and used + len(row) + 1 > char_budget:
            break
        shown.append(row)
        used += len(row) + 1
        end = number
    return {
        "start_line": start, "end_line": end, "total_lines": total,
        "next_start_line": end + 1 if end < total else None,
        "code": "\n".join(shown),
    }


# --- search -----------------------------------------------------------------------------

# A quantified group that itself contains a quantifier: (a+)+, (\w*x)*, (a{2,})+ ...
_NESTED_QUANTIFIER = re.compile(r"\((?:[^()\\]|\\.)*[*+}](?:[^()\\]|\\.)*\)\s*(?:[*+]|\{\d*,)")
_BACKREFERENCE = re.compile(r"\\[1-9]|\(\?P=")


def compile_search_pattern(pattern: str, *, ignore_case: bool = False,
                           literal: bool = False) -> re.Pattern:
    """Compile a model-supplied pattern with guards against catastrophic backtracking."""
    pattern = str(pattern or "")
    if not pattern:
        raise ValueError("pattern is required")
    if len(pattern) > MAX_PATTERN_CHARS:
        raise ValueError(f"pattern longer than {MAX_PATTERN_CHARS} characters")
    if literal:
        pattern = re.escape(pattern)
    else:
        if _NESTED_QUANTIFIER.search(pattern):
            raise ValueError("nested quantifiers like (a+)+ are not allowed; simplify the pattern")
        if _BACKREFERENCE.search(pattern):
            raise ValueError("backreferences are not allowed")
    try:
        return re.compile(pattern, re.IGNORECASE if ignore_case else 0)
    except re.error as exc:
        raise ValueError(f"invalid regex: {exc}; pass literal=true to search plain text") from exc


def search_store(store: ScriptStore, pattern: str, *, file_filter: str = "",
                 context_lines: int = 2, max_matches: int = 40, ignore_case: bool = False,
                 literal: bool = False, char_budget: int = OUTPUT_CHAR_BUDGET,
                 time_budget_s: float = SEARCH_TIME_BUDGET_S) -> Dict[str, Any]:
    """Search every selected file line by line; return hunks with context lines."""
    regex = compile_search_pattern(pattern, ignore_case=ignore_case, literal=literal)
    context = max(0, min(int(context_lines or 0), MAX_CONTEXT_LINES))
    limit = max(1, min(int(max_matches or 40), MAX_SEARCH_MATCHES))
    # Original (source-mapped) files read best, so their hits come first.
    entries = sorted(store.select(file_filter), key=lambda e: e.kind != "original_source")
    deadline = time.monotonic() + time_budget_s
    hunks: List[Dict[str, Any]] = []
    total = 0
    files_with_matches = 0
    used = 0
    truncated = timed_out = False
    searched = shown = 0
    for entry in entries:
        lines = entry.materialize()
        searched += 1
        hits: List[int] = []
        for index, line in enumerate(lines):
            if index % 2000 == 0 and time.monotonic() > deadline:
                timed_out = True
                break
            if regex.search(line):
                hits.append(index)
        if hits:
            files_with_matches += 1
        total += len(hits)
        # Merge hits whose context windows overlap into one hunk.
        groups: List[List[int]] = []
        for hit in hits:
            if groups and hit - groups[-1][-1] <= 2 * context + 1:
                groups[-1].append(hit)
            else:
                groups.append([hit])
        width = len(str(len(lines)))
        for group in groups:
            if truncated:
                break
            lo, hi = max(0, group[0] - context), min(len(lines) - 1, group[-1] + context)
            marks = set(group)
            rows = [f"{n + 1:>{width}}{'>' if n in marks else '|'} {lines[n]}" for n in range(lo, hi + 1)]
            text = "\n".join(rows)
            if shown + len(group) > limit or (hunks and used + len(text) > char_budget):
                truncated = True
                break
            hunks.append({"file": entry.file_id, "name": entry.name,
                          "match_lines": [g + 1 for g in group], "context": text})
            used += len(text) + len(entry.name) + 40
            shown += len(group)
        if timed_out:
            break
    return {
        "pattern": pattern, "files_searched": searched, "files_total": len(entries),
        "files_with_matches": files_with_matches, "total_matches": total,
        "matches_shown": shown,
        "truncated": truncated, "timed_out": timed_out, "hunks": hunks,
    }


def render_search(result: Dict[str, Any]) -> str:
    head = (f"search /{result['pattern']}/ — {result['total_matches']} matching lines in "
            f"{result['files_with_matches']} of {result['files_searched']} files searched")
    notes = []
    if result.get("truncated"):
        notes.append("output truncated: narrow with file= or a tighter pattern")
    if result.get("timed_out"):
        notes.append("time budget reached before every file was searched")
    if result.get("files_searched", 0) < result.get("files_total", 0):
        notes.append(f"{result['files_total'] - result['files_searched']} files not searched")
    lines = [head + (" (" + "; ".join(notes) + ")" if notes else "")]
    if result.get("loaded"):
        lines.append("loaded this call: " + ", ".join(result["loaded"]))
    for hunk in result["hunks"]:
        lines.append(f"\n== {hunk['file']} {hunk['name']} (lines {', '.join(map(str, hunk['match_lines']))})")
        lines.append(hunk["context"])
    if result["hunks"]:
        lines.append("\nRead more with read_script(file=<file>, start_line=<line>).")
    return "\n".join(lines)


__all__ = [
    "MAX_FILES", "MAX_TOTAL_CHARS", "ScriptFile", "ScriptStore", "SourceMapSources",
    "add_source_map_sources", "compile_search_pattern", "decode_data_uri",
    "find_source_map_ref", "is_vendored", "looks_minified", "normalize_source_path",
    "parse_source_map", "readable_lines", "reflow", "render_page", "render_search",
    "resolve_source_map_url", "same_origin", "script_key", "search_store", "wrap_long_lines",
]
