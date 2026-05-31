# Python AI handler service

A Flask sidecar that does the heavy preprocessing for AI calls so the
TypeScript platform can pay **fewer tokens per request** when an LLM is
in the loop. The platform calls this service first; the service:

1. Tries to answer **deterministically** (no AI call).
2. If AI is needed, distils the package down to a small structured
   context, applies a stable cacheable prefix so the provider's
   prompt-cache fires, and constrains the model with a tight system
   prompt + low max-tokens.
3. Returns the answer along with `tokens_used` and a `source` of
   `deterministic` / `cache` / `ai`.

The TypeScript platform falls back to calling the LLM directly when
`PY_AI_URL` is not set, so this service is **optional**.

## Endpoints

| Path | Purpose |
|---|---|
| `GET  /healthz` | Liveness |
| `POST /chat` | Answer a question about a package |
| `POST /narrative` | Draft / refine the executive narrative |
| `POST /clarify` | Suggest additional clarification questions |

All POSTs accept:

```json
{ "package_digest": { ... }, "question": "...", "options": { ... } }
```

`package_digest` is a small, AI-shaped subset of the ArbPackage —
the TypeScript side computes it via `engine/aiContext.ts` so the
network payload stays under ~30 KB.

## Run

```bash
cd python-handlers
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
PY_AI_PORT=14042 AI_BASE_URL=https://api.openai.com/v1 AI_API_KEY=sk-... AI_MODEL=gpt-4o-mini \
  python app.py
```

Then on the platform side:

```bash
PY_AI_URL=http://127.0.0.1:14042 ./scripts/start.sh
```

## Token-economy strategy

- **Stable system prompt prefix.** A frozen 600-char system prompt is
  emitted first, so the provider's prompt cache treats successive
  requests as cache-eligible.
- **Deterministic-first.** ~20 FAQ patterns answer common questions
  with no LLM call (`source: "deterministic"`).
- **Tight context.** The digest never exceeds the model's prompt-cache
  threshold (≈ 1024 tokens for OpenAI). Long sections are truncated
  with `tiktoken`.
- **Response cache.** Identical (package_hash, question) pairs are
  returned from a small LRU without re-calling the AI.
- **Bounded output.** `max_tokens` defaults to 300 (chat), 200
  (narrative), 150 (clarify).
