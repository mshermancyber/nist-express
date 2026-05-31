"""Clarification-question suggester. Heuristic-first: a battery of
rule-based checks emits questions without spending tokens. Calls the
LLM only when the digest hints there might be non-obvious gaps the
rules can't catch."""

from __future__ import annotations

import json
from typing import Any, Dict, List

from lib import llm


def _deterministic(digest: Dict[str, Any]) -> List[str]:
    qs: List[str] = []
    tags = digest.get("sensitive_tags") or []
    if tags and not digest.get("confidential"):
        qs.append("Sensitive data tags are present but the assessment is not marked confidential — is that intentional?")
    if "PCI" in tags and "PCI DSS" not in (digest.get("frameworks") or []):
        qs.append("PCI data declared without PCI DSS in compliance scope — confirm coverage strategy.")
    if "PHI" in tags and "HIPAA" not in (digest.get("frameworks") or []):
        qs.append("PHI declared without HIPAA in compliance scope — confirm coverage strategy.")
    if digest.get("rto") == "15 Minutes" and not digest.get("multi_region"):
        qs.append("Aggressive 15-minute RTO without multi-region deployment — is the recovery plan validated?")
    if digest.get("rpo") == "No Data Loss" and digest.get("rto") in ("24 Hours", "72 Hours"):
        qs.append("Zero-data-loss RPO with relaxed RTO is unusual — confirm both targets.")
    if digest.get("category") == "High" and digest.get("integration_count", 0) == 0:
        qs.append("High-impact system with no declared integrations — confirm there really are no external interfaces.")
    if "AI" in (digest.get("ai_related_frameworks") or []) and not digest.get("dpia_emitted"):
        qs.append("AI risk frameworks in scope but no DPIA emitted — does the system process personal data?")
    return qs[:3]


def suggest(digest: Dict[str, Any], existing: List[str], options: Dict[str, Any]) -> Dict[str, Any]:
    det = _deterministic(digest)
    # If we got at least 2 deterministic suggestions and AI isn't configured, return them.
    if len(det) >= 2 or not llm.configured():
        return {"questions": det, "source": "deterministic", "tokens_used": 0}

    cache_key = llm.cached_key(str(digest.get("package_hash") or ""), "clarify", "|".join(sorted(existing)))
    hit = llm.cache_get(cache_key)
    if hit:
        return {**hit, "source": "cache"}

    user_payload = (
        "Return up to 3 additional clarification questions a Security Architect would ask. "
        "One per line. No numbering. Do not repeat any of the EXISTING questions below.\n\n"
        "EXISTING:\n" + "\n".join(f"- {x}" for x in existing) + "\n\nDIGEST:\n"
        + json.dumps(digest, separators=(",", ":"))[:2500]
    )
    try:
        max_tokens = int(options.get("max_tokens") or 150)
        content, tokens = llm.call_llm(user_payload, max_tokens=max_tokens, temperature=0.3)
        qs = [line.strip(" -*1234567890.").strip() for line in content.split("\n") if line.strip()]
        qs = [q for q in qs if q][:3]
        out = {"questions": det + qs, "source": "ai", "tokens_used": tokens}
        llm.cache_put(cache_key, out)
        return out
    except Exception:
        return {"questions": det, "source": "deterministic-fallback", "tokens_used": 0}
