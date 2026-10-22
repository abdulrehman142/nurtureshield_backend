# NurtureShield

Standalone URL-only security analysis service shared by the NurtureShield
browser extension and the NurtureNet frontend.

## API

`POST /api/v1/nurtureshield/analyze` accepts:

```json
{"url": "https://example.com/path"}
```

It returns the submitted URL, `malicious`/`legitimate` classification,
malicious probability, risk level, and descriptive URL characteristics.

The endpoint validates allowed origins from `NURTURESHIELD_ALLOWED_ORIGINS`.
Chrome extension origins must also be listed in
`NURTURESHIELD_EXTENSION_IDS`. Server-to-server callers may use the optional
`NURTURESHIELD_INTERNAL_API_KEY`. Analysis requests are limited by the
configurable in-memory `NURTURESHIELD_RATE_LIMIT_REQUESTS` and
`NURTURESHIELD_RATE_LIMIT_WINDOW_SECONDS` settings, and request bodies are
limited by `NURTURESHIELD_MAX_REQUEST_BODY_BYTES`. The limiter is scoped to a
running process and is application-level abuse protection, not volumetric DDoS
protection; Render or another edge provider should provide that layer.

Responses include a generated `X-Request-ID` and conservative JSON API headers.
Request IDs may be used for server-side correlation, but submitted URLs and
authentication secrets are not logged.

## Inference contract

The service loads the fixed
[`hist_gradient_boosting.joblib`](models/hist_gradient_boosting.joblib) artifact
and validates it against
[`final_model_config.json`](models/final_model_config.json) before use.

- Model: `HistGradientBoostingClassifier`
- Features: exactly 31
- Schema: `nurtureshield-corrected-v1`
- Threshold: `0.30`
- Legitimate class: `0`
- Malicious class: `1`
- `uses_https`: not present

The extractor strips exactly one leading `http://` or `https://` before lexical
feature calculation. It performs only local parsing and counting. It never
resolves, requests, opens, scrapes, downloads, or executes the submitted URL.
Training augmentation is not performed at runtime.

## Development

```sh
NurtureShield/backend/.venv/bin/python -m pip install -r NurtureShield/backend/requirements.txt
NurtureShield/backend/.venv/bin/python -m uvicorn NurtureShield.backend.app:app \
  --host 127.0.0.1 --port 8010 --reload
NurtureShield/backend/.venv/bin/python -m pytest NurtureShield/backend/tests -q
```
