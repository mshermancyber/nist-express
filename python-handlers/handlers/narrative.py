"""Executive-narrative drafter. Pre-fills a deterministic template
from the digest; calls the LLM only to refine the single paragraph
(saves ~70% tokens compared to letting the LLM author from scratch).
"""

from __future__ import annotations

import json
from typing import Any, Dict

from lib import llm


def _deterministic_paragraph(d: Dict[str, Any]) -> str:
    parts = []
    parts.append(d.get("one_liner") or f"{d.get('app_name', 'The system')} is under ARB review.")
    parts.append(
        f"It is categorised {d.get('category', 'Moderate')} per FIPS 199 and "
        f"runs on {d.get('hosting', 'AWS')} with a {d.get('availability_tier', 'Tier 2')} availability posture."
    )
    if d.get("top_risks"):
        parts.append("Top residual risks include " + "; ".join(d["top_risks"][:2]) + ".")
    parts.append(
        f"The ARB recommendation is: {d.get('advice', 'Proceed With Conditions')}. "
        f"Estimated monthly cost: ${d.get('cost_low', 0):,}–${d.get('cost_high', 0):,}."
    )
    return " ".join(parts)


def draft(digest: Dict[str, Any], options: Dict[str, Any]) -> Dict[str, Any]:
    base = _deterministic_paragraph(digest)
    # If no AI configured, return the template.
    if not llm.configured():
        return {"narrative": base, "source": "deterministic", "tokens_used": 0}

    cache_key = llm.cached_key(str(digest.get("package_hash") or ""), "narrative", "exec")
    hit = llm.cache_get(cache_key)
    if hit:
        return {**hit, "source": "cache"}

    user_payload = (
        "DRAFT (use as base — refine for tone, do not change facts):\n"
        + base
        + "\n\nDIGEST:\n"
        + json.dumps(digest, separators=(",", ":"))[:3000]
        + "\n\nReturn a single paragraph (≤120 words) suitable for an ARB executive summary."
    )
    try:
        max_tokens = int(options.get("max_tokens") or 200)
        content, tokens = llm.call_llm(user_payload, max_tokens=max_tokens, temperature=0.2)
        out = {"narrative": content or base, "source": "ai", "tokens_used": tokens}
        llm.cache_put(cache_key, out)
        return out
    except Exception:
        return {"narrative": base, "source": "deterministic-fallback", "tokens_used": 0}
