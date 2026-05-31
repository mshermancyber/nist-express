"""Chat handler — answer questions about an ARB package with as few
LLM tokens as possible."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional

from lib import llm


# Deterministic FAQ. The point is to answer common questions
# WITHOUT spending tokens on the LLM.
FAQ_PATTERNS: List[Dict[str, Any]] = [
    {
        "match": re.compile(r"how many controls|control count|ssp size", re.I),
        "answer": lambda d: f"{d.get('ssp_count', 0)} NIST 800-53 controls are in the SSP, spanning families {', '.join(sorted(set(d.get('ssp_families', []))))}.",
    },
    {
        "match": re.compile(r"category|categori[sz]ation|fips 199", re.I),
        "answer": lambda d: f"FIPS 199 category: {d.get('category', '?')}. C={d.get('confidentiality', '?')}, I={d.get('integrity', '?')}, A={d.get('availability', '?')}.",
    },
    {
        "match": re.compile(r"cost|budget|how much", re.I),
        "answer": lambda d: f"Tier {d.get('cost_tier', '?')}: ${d.get('cost_low', 0):,} – ${d.get('cost_high', 0):,}/mo. Top drivers: {', '.join(d.get('cost_top_drivers') or [])}.",
    },
    {
        "match": re.compile(r"posture|risk posture|recommendation|go.?no.?go", re.I),
        "answer": lambda d: f"Posture: {d.get('posture', '?')}. ARB recommendation: {d.get('advice', '?')}.",
    },
    {
        "match": re.compile(r"residual|top risk|critical risk", re.I),
        "answer": lambda d: "Top residual risks: " + "; ".join(d.get("top_risks", []) or ["none flagged"]),
    },
    {
        "match": re.compile(r"compliance|gap|coverage|framework", re.I),
        "answer": lambda d: (
            f"Compliance coverage — {d.get('compliance_full', 0)} Full / "
            f"{d.get('compliance_partial', 0)} Partial / {d.get('compliance_gap', 0)} Gap "
            f"across {len(d.get('frameworks', []))} frameworks: {', '.join(d.get('frameworks', []))}."
        ),
    },
    {
        "match": re.compile(r"diff|what changed|version", re.I),
        "answer": lambda d: " ".join(d.get("diff_highlights", []) or ["No prior version — this is v1."]),
    },
    {
        "match": re.compile(r"architecture|component|service|aws|azure|gcp", re.I),
        "answer": lambda d: f"{d.get('component_count', 0)} components across {len(d.get('layers', []))} layers ({', '.join(d.get('layers', []))}).",
    },
    {
        "match": re.compile(r"recovery|rto|rpo|availability|tier", re.I),
        "answer": lambda d: f"RTO {d.get('rto', '?')}, RPO {d.get('rpo', '?')}, availability tier {d.get('availability_tier', '?')}. {d.get('failover', '')}",
    },
    {
        "match": re.compile(r"privacy|pii|gdpr|dpia|linddun", re.I),
        "answer": lambda d: f"{d.get('linddun_findings', 0)} LINDDUN findings. DPIA: {d.get('dpia_conclusion', 'not emitted')}.",
    },
    {
        "match": re.compile(r"sbom|kev|vulnerab", re.I),
        "answer": lambda d: f"SBOM: {d.get('sbom_components', 0)} components, {d.get('sbom_vulns', 0)} vulnerabilities ({d.get('sbom_kev', 0)} on CISA KEV).",
    },
    {
        "match": re.compile(r"fedramp|cmmc|fedramp baseline", re.I),
        "answer": lambda d: f"FedRAMP baseline: {d.get('fedramp_baseline', 'not in scope')}; {d.get('fedramp_baseline_count', 0)} controls in baseline; POA&M items: {d.get('fedramp_poam_count', 0)}.",
    },
    {
        "match": re.compile(r"fair|ale|monte ?carlo|annualized|portfolio risk", re.I),
        "answer": lambda d: f"FAIR portfolio ALE: p50 ${d.get('fair_p50', 0):,}, p90 ${d.get('fair_p90', 0):,} (mean ${d.get('fair_mean', 0):,}).",
    },
    {
        "match": re.compile(r"mitre|att&?ck|capec|kill chain", re.I),
        "answer": lambda d: f"{d.get('mitre_count', 0)} MITRE ATT&CK mappings; {d.get('capec_count', 0)} CAPEC references; kill-chain stages covered: {', '.join(d.get('kill_chain_stages') or [])}.",
    },
    {
        "match": re.compile(r"approval|approver|sign", re.I),
        "answer": lambda d: d.get("approval_status") or "No approval request open.",
    },
]


def _try_deterministic(digest: Dict[str, Any], question: str) -> Optional[str]:
    for entry in FAQ_PATTERNS:
        if entry["match"].search(question):
            try:
                return entry["answer"](digest)
            except Exception:
                continue
    return None


def _build_user_payload(digest: Dict[str, Any], question: str) -> str:
    # Compact JSON; truncate at AI_MAX_PROMPT_TOKENS for prompt-cache fit.
    text = "PACKAGE_DIGEST:\n" + json.dumps(digest, separators=(",", ":")) + "\n\nQUESTION:\n" + question
    import os
    max_prompt = int(os.environ.get("AI_MAX_PROMPT_TOKENS", "1024"))
    return llm.fit_prompt(text, max_prompt)


def answer(digest: Dict[str, Any], question: str, options: Dict[str, Any]) -> Dict[str, Any]:
    # 1) Deterministic
    det = _try_deterministic(digest, question)
    if det:
        return {"answer": det, "source": "deterministic", "tokens_used": 0}

    # 2) Cache (only when AI is configured)
    if not llm.configured():
        return {
            "answer": f"AI is not configured and the FAQ has no answer for this question: {question[:240]}",
            "source": "deterministic",
            "tokens_used": 0,
        }

    package_hash = str(digest.get("package_hash") or "")
    cache_key = llm.cached_key(package_hash, "chat", question)
    hit = llm.cache_get(cache_key)
    if hit:
        return {**hit, "source": "cache"}

    # 3) Tight LLM call with hardened anti-hallucination guards
    try:
        max_tokens = int(options.get("max_tokens") or 300)
        content, tokens = llm.call_llm(
            _build_user_payload(digest, question),
            max_tokens=max_tokens,
            temperature=0.0,            # Maximally deterministic
        )
        content = llm.cleanup_answer(content)
        if _looks_authoritative(content):
            return {"answer": "Not stated in the package.", "source": "ai-rejected-authority", "tokens_used": tokens}
        if _references_unknown_controls(content, digest):
            return {"answer": "Not stated in the package.", "source": "ai-rejected-grounding", "tokens_used": tokens}
        out = {"answer": content, "source": "ai", "tokens_used": tokens}
        llm.cache_put(cache_key, out)
        return out
    except Exception as e:
        return {"answer": f"AI call failed: {e}", "source": "ai-error", "tokens_used": 0}


_AUTH_PATTERNS = [
    re.compile(r"\bi (?:hereby )?approve\b", re.I),
    re.compile(r"\b(?:deny|reject)(?:ed)? (?:this|the) (?:system|package|arb)\b", re.I),
    re.compile(r"\bATO (?:is )?granted\b", re.I),
    re.compile(r"\bcategori[sz]ation (?:is|should be) (?:low|moderate|high)\b", re.I),
]
def _looks_authoritative(s: str) -> bool:
    return any(p.search(s) for p in _AUTH_PATTERNS)


_ID_PATTERN = re.compile(r"\b([A-Z]{2})-\d+(?:\(\d+\))?\b")
def _references_unknown_controls(s: str, digest: Dict[str, Any]) -> bool:
    """Reject answers that cite control families that aren't in the
    package's SSP. (Per-id grounding is enforced server-side in TS.)"""
    families = set(digest.get("ssp_families") or [])
    if not families:
        return False
    for m in _ID_PATTERN.finditer(s):
        if m.group(1) not in families:
            return True
    return False
