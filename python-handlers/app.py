"""Flask sidecar that handles AI work for the TypeScript ARB platform.

The point of this service is to **minimise tokens** sent to the LLM.
Strategy:

1. Deterministic-first — the FAQ in handlers.chat.deterministic
   answers common questions without calling the AI.
2. Stable system-prompt prefix — increases prompt-cache hit-rate on
   OpenAI / Anthropic compatible endpoints.
3. Token-aware truncation via tiktoken so prompts always fit the
   model's prompt-cache window.
4. LRU response cache keyed by (package_hash, question_hash).
5. Tight max_tokens caps on every call.

Configure via env:
  PY_AI_PORT       (default 14042)
  AI_BASE_URL      (default https://api.openai.com/v1)
  AI_API_KEY       (Bearer, optional for localhost endpoints like Ollama)
  AI_MODEL         (default gpt-4o-mini)
  AI_TIMEOUT_S     (default 30)
  AI_MAX_PROMPT_TOKENS (default 1024)
"""

from __future__ import annotations

import os
from flask import Flask, jsonify, request

from handlers import chat as chat_handler
from handlers import narrative as narrative_handler
from handlers import clarify as clarify_handler

app = Flask(__name__)


@app.route("/healthz", methods=["GET"])
def healthz():
    return jsonify({"status": "ok"})


@app.route("/chat", methods=["POST"])
def chat():
    body = request.get_json(silent=True) or {}
    digest = body.get("package_digest") or {}
    question = (body.get("question") or "").strip()
    if not question:
        return jsonify({"error": "question required"}), 400
    out = chat_handler.answer(digest, question, body.get("options") or {})
    return jsonify(out)


@app.route("/narrative", methods=["POST"])
def narrative():
    body = request.get_json(silent=True) or {}
    digest = body.get("package_digest") or {}
    out = narrative_handler.draft(digest, body.get("options") or {})
    return jsonify(out)


@app.route("/clarify", methods=["POST"])
def clarify():
    body = request.get_json(silent=True) or {}
    digest = body.get("package_digest") or {}
    existing = body.get("existing") or []
    out = clarify_handler.suggest(digest, existing, body.get("options") or {})
    return jsonify(out)


if __name__ == "__main__":
    port = int(os.environ.get("PY_AI_PORT", "14042"))
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
