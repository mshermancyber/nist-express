"""OpenAI-compatible chat-completions client with prompt-cache aware
token budgeting and a small LRU response cache."""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import time
from collections import OrderedDict
from typing import Any, Dict, List, Optional, Tuple

import requests

try:
    import tiktoken
    _ENC = tiktoken.get_encoding("cl100k_base")
    def token_count(text: str) -> int:
        return len(_ENC.encode(text))
except Exception:  # tiktoken not available — heuristic fallback
    def token_count(text: str) -> int:
        return max(1, len(text) // 4)


# Stable system prompt — placing this FIRST in every request maximises
# prompt-cache hit rate on providers that support it. Do not edit
# this string lightly: every change invalidates the cache.
SYSTEM_PRIMER = (
    "You are a Principal Security Architect assisting with Architecture "
    "Review Board artefacts.\n\n"
    "Anti-hallucination rules (highest priority):\n"
    "- DO NOT hallucinate. Never invent facts, control identifiers, "
    "components, frameworks, numbers, dates, names, or quotations.\n"
    "- VALIDATE every claim against the structured package data the user "
    "supplies. If a claim is not grounded in a specific field, do not make "
    "it.\n"
    "- If the package does not contain the answer, reply exactly: "
    '"Not stated in the package." Do not guess, infer, or extrapolate.\n'
    "- Do not draw on your training data — only the package provided in "
    "this turn.\n"
    "- If two fields conflict, surface the conflict; do not pick a side.\n\n"
    "Style: concise, neutral, assessor's voice. No preamble. No markdown "
    "headings unless asked."
)


class _LRU(OrderedDict[str, Dict[str, Any]]):
    def __init__(self, capacity: int = 256):
        super().__init__()
        self.capacity = capacity
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            v = OrderedDict.get(self, key)  # type: ignore[arg-type]
            if v is None:
                return None
            self.move_to_end(key)
            return v

    def put(self, key: str, value: Dict[str, Any]) -> None:
        with self._lock:
            if key in self:
                self.move_to_end(key)
            self[key] = value
            while len(self) > self.capacity:
                self.popitem(last=False)


_response_cache = _LRU(256)


def _hash_key(parts: List[str]) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update(p.encode("utf-8"))
        h.update(b"\0")
    return h.hexdigest()


def cached_key(package_hash: str, kind: str, question: str) -> str:
    return _hash_key([package_hash or "", kind, question])


def cache_get(key: str) -> Optional[Dict[str, Any]]:
    return _response_cache.get(key)


def cache_put(key: str, value: Dict[str, Any]) -> None:
    _response_cache.put(key, value)


def fit_prompt(text: str, max_tokens: int) -> str:
    """Identity — we intentionally do NOT truncate context server-side.
    The model needs the rich digest to answer accurately. Provider-side
    context-window errors will surface naturally if the operator sends
    something genuinely oversized; the cleanup work this service does
    is on the OUTPUT, not the input."""
    return text


def cleanup_answer(s: str) -> str:
    """Post-process a model response: strip preambles like
    'Sure, here is…', remove trailing offer-of-help boilerplate, and
    collapse excessive blank lines. This is the cleanup work the
    Python sidecar exists to do; the model still gets the full
    package context as input."""
    s = (s or "").strip()
    if not s:
        return s
    s = re.sub(r"^(sure|of course|absolutely|certainly|here(?:'s| is)|here you go)[,:.]?\s*", "", s, flags=re.I)
    s = re.sub(r"\n+(let me know|hope this helps|please reach out|happy to)[^\n]*$", "", s, flags=re.I)
    s = re.sub(r"\n{3,}", "\n\n", s)
    return s.strip()


def parse_bulleted(s: str, max_items: int = 6) -> List[str]:
    """Coerce a free-form list into bullets. Used by the clarify
    handler so the API contract is stable even when the model's output
    style drifts."""
    items: List[str] = []
    for line in (s or "").splitlines():
        line = line.strip()
        if not line:
            continue
        line = re.sub(r"^[\-*•\d\.\)\s]+", "", line).strip()
        if not line:
            continue
        items.append(line)
        if len(items) >= max_items:
            break
    return items


def call_llm(
    user_payload: str,
    *,
    extra_system: Optional[str] = None,
    max_tokens: int = 300,
    temperature: float = 0.2,
) -> Tuple[str, int]:
    """Return (content, total_tokens_used). Raises on failure."""
    base = os.environ.get("AI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
    key = os.environ.get("AI_API_KEY")
    model = os.environ.get("AI_MODEL", "gpt-4o-mini")
    timeout = float(os.environ.get("AI_TIMEOUT_S", "30"))

    headers = {"content-type": "application/json"}
    if key:
        headers["authorization"] = f"Bearer {key}"

    system = SYSTEM_PRIMER + ("\n" + extra_system if extra_system else "")
    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user_payload},
        ],
        "temperature": temperature,
        "max_tokens": max_tokens,
        "stream": False,
    }
    t0 = time.time()
    r = requests.post(
        f"{base}/chat/completions",
        headers=headers,
        data=json.dumps(body).encode("utf-8"),
        timeout=timeout,
    )
    r.raise_for_status()
    data = r.json()
    content = (data.get("choices") or [{}])[0].get("message", {}).get("content", "")
    usage = data.get("usage") or {}
    total = int(usage.get("total_tokens") or (token_count(system) + token_count(user_payload) + token_count(content)))
    # Trace timing only when LOG_LEVEL=trace style env is set
    if os.environ.get("PY_LOG_TRACE") == "1":
        print(json.dumps({"event": "ai", "ms": int((time.time() - t0) * 1000), "tokens": total, "model": model}))
    return content.strip(), total


def configured() -> bool:
    base = os.environ.get("AI_BASE_URL", "https://api.openai.com/v1")
    key = os.environ.get("AI_API_KEY")
    is_localhost = any(p in base for p in ("localhost", "127.0.0.1", "0.0.0.0"))
    return bool(key) or is_localhost
