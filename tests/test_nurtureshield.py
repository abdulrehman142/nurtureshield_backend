import json
import socket
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

import app as application
from app import app
from nurtureshield.features import (
    FEATURE_NAMES,
    SCHEMA_VERSION,
    canonicalize_url,
    extract_url_features,
)
from nurtureshield.service import MODEL_DIR, Predictor, result_for


def test_corrected_feature_contract():
    assert len(FEATURE_NAMES) == 31
    assert "uses_https" not in FEATURE_NAMES
    assert SCHEMA_VERSION == "nurtureshield-corrected-v1"
    assert canonicalize_url("HTTPS://Example.com/path") == "Example.com/path"
    assert extract_url_features("example.com") == extract_url_features("https://example.com")


def test_configured_artifacts_and_threshold():
    config = json.loads((MODEL_DIR / "final_model_config.json").read_text())
    assert config["feature_count"] == 31
    assert config["threshold"] == 0.30
    assert config["canonicalization_version"] == SCHEMA_VERSION
    assert config["uses_https_removed"] is True
    assert (MODEL_DIR / "hist_gradient_boosting.joblib").is_file()


def test_model_inference_does_not_use_network(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("target network access attempted")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    result = Predictor().predict("https://example.com")
    assert 0 <= result["malicious_probability"] <= 1


@pytest.mark.parametrize(
    "probability, prediction",
    [(0.2999, "legitimate"), (0.30, "malicious"), (1.0, "malicious")],
)
def test_threshold(probability, prediction):
    assert (
        result_for(
            "example.com",
            extract_url_features("example.com"),
            probability,
            0.30,
        )["prediction"]
        == prediction
    )


def test_api_returns_analysis_and_rejects_invalid_urls():
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/nurtureshield/analyze",
            json={"url": "https://example.com"},
            headers={"Origin": "http://localhost:3000"},
        )
        assert response.status_code == 200
        assert set(response.json()) == {
            "url",
            "prediction",
            "malicious_probability",
            "risk_level",
            "observed_characteristics",
        }
        invalid = client.post(
            "/api/v1/nurtureshield/analyze",
            json={"url": "javascript:alert(1)"},
            headers={"Origin": "http://localhost:3000"},
        )
        assert invalid.status_code == 422


def test_api_rejects_unapproved_origin():
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/nurtureshield/analyze",
            json={"url": "example.com"},
            headers={"Origin": "https://evil.example"},
        )
        assert response.status_code == 403


def test_api_security_headers_and_safe_validation_errors():
    with TestClient(app) as client:
        oversized = client.post(
            "/api/v1/nurtureshield/analyze",
            content=b"x" * 17000,
            headers={"Origin": "http://localhost:3000", "Content-Type": "application/json"},
        )
        assert oversized.status_code == 413
        assert oversized.headers["cache-control"] == "no-store"
        assert oversized.headers["x-content-type-options"] == "nosniff"
        assert oversized.headers["x-request-id"]

        malformed = client.post(
            "/api/v1/nurtureshield/analyze",
            content=b"{not-json}",
            headers={"Origin": "http://localhost:3000", "Content-Type": "application/json"},
        )
        assert malformed.status_code == 422
        assert malformed.json() == {"detail": "Invalid request."}
        assert "Traceback" not in malformed.text


def test_rate_limit_returns_retry_after(monkeypatch):
    monkeypatch.setattr(application, "RATE_LIMIT_REQUESTS", 1)
    monkeypatch.setattr(application, "_rate_limit_buckets", {})
    with TestClient(app) as client:
        headers = {"Origin": "http://localhost:3000"}
        assert client.post(
            "/api/v1/nurtureshield/analyze",
            json={"url": "example.com"},
            headers=headers,
        ).status_code == 200
        limited = client.post(
            "/api/v1/nurtureshield/analyze",
            json={"url": "example.com"},
            headers=headers,
        )
        assert limited.status_code == 429
        assert limited.headers["retry-after"]
        assert limited.json() == {"detail": "Too many checks. Please wait and try again."}


def test_internal_key_is_exact_and_not_reflected(monkeypatch):
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("NURTURESHIELD_INTERNAL_API_KEY", "test-only-secret")
    monkeypatch.setattr(application, "_rate_limit_buckets", {})
    with TestClient(app) as client:
        denied = client.post(
            "/api/v1/nurtureshield/analyze",
            json={"url": "example.com"},
            headers={"X-NurtureShield-API-Key": "wrong"},
        )
        assert denied.status_code == 403
        accepted = client.post(
            "/api/v1/nurtureshield/analyze",
            json={"url": "example.com"},
            headers={"X-NurtureShield-API-Key": "test-only-secret"},
        )
        assert accepted.status_code == 200
        assert "test-only-secret" not in accepted.text


def test_extension_ids_are_exactly_allowlisted():
    allowed = "a" * 32
    with pytest.MonkeyPatch.context() as patch:
        patch.setenv("NURTURESHIELD_EXTENSION_IDS", allowed)
        assert application._extension_origin_allowed(f"chrome-extension://{allowed}")
        assert not application._extension_origin_allowed(
            f"chrome-extension://{'b' * 32}"
        )
