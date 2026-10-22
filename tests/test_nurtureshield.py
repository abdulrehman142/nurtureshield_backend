import json
import socket
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from NurtureShield.backend.app import app
from NurtureShield.backend.nurtureshield.features import (
    FEATURE_NAMES,
    SCHEMA_VERSION,
    canonicalize_url,
    extract_url_features,
)
from NurtureShield.backend.nurtureshield.service import MODEL_DIR, Predictor, result_for


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
