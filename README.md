# NurtureShield backend

Standalone URL-only inference service for the NurtureShield browser extension
and NurtureNet frontend.

## Run

From the repository root:

```sh
NurtureShield/backend/.venv/bin/python -m uvicorn NurtureShield.backend.app:app \
  --host 127.0.0.1 --port 8010 --reload
```

Create the environment with the pinned runtime dependencies first:

```sh
NurtureShield/backend/.venv/bin/python -m pip install -r NurtureShield/backend/requirements.txt
```

The service exposes `POST /api/v1/nurtureshield/analyze` and `GET /health`.
Configure origins and optional internal authentication with
[`NurtureShield/backend/.env.example`](.env.example).
The same file documents the request-body and per-process rate-limit settings.
These limits reduce ordinary application abuse; infrastructure or edge
protection is still required for volumetric DDoS attacks.

The predictor only parses submitted text locally. It never resolves, requests,
opens, scrapes, downloads, or executes the submitted target URL.

## Tests

```sh
NurtureShield/backend/.venv/bin/python -m pytest NurtureShield/backend/tests -q
```
