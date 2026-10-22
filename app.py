"""Standalone NurtureShield API application."""

from __future__ import annotations

import hmac
import logging
import os
import re
from contextlib import asynccontextmanager
from ipaddress import ip_address
from typing import Literal
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict, Field, field_validator

from .nurtureshield.service import ModelUnavailable, predictor

logger = logging.getLogger(__name__)
MAX_URL_LENGTH = 8192
DEFAULT_ORIGINS = "http://localhost:3000,http://127.0.0.1:3000"


def _origins() -> set[str]:
    return {
        value.strip()
        for value in os.getenv("NURTURESHIELD_ALLOWED_ORIGINS", DEFAULT_ORIGINS).split(",")
        if value.strip()
    }


def _extension_origin_allowed(origin: str) -> bool:
    match = re.fullmatch(r"chrome-extension://([a-p]{32})", origin)
    if not match:
        return False
    allowed = {
        value.strip()
        for value in os.getenv("NURTURESHIELD_EXTENSION_IDS", "").split(",")
        if re.fullmatch(r"[a-p]{32}", value.strip())
    }
    return match.group(1) in allowed


def _check_access(request: Request) -> None:
    origin = request.headers.get("origin", "")
    if origin and (origin in _origins() or _extension_origin_allowed(origin)):
        return
    configured_key = os.getenv("NURTURESHIELD_INTERNAL_API_KEY", "")
    supplied_key = request.headers.get("x-nurtureshield-api-key", "")
    if configured_key and hmac.compare_digest(supplied_key, configured_key):
        return
    if not origin and not configured_key and os.getenv("APP_ENV", "development") != "production":
        return
    raise HTTPException(403, "Request origin or API key is not allowed.")


class AnalyzeInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: str = Field(strict=True, min_length=1, max_length=MAX_URL_LENGTH)

    @field_validator("url")
    @classmethod
    def valid_url(cls, value: str) -> str:
        value = value.strip()
        if not value or any(
            c.isspace() or ord(c) < 32 or ord(c) == 127 for c in value
        ) or "\\" in value:
            raise ValueError("Enter a URL without spaces or control characters.")
        try:
            parsed = urlsplit(value if "://" in value else "//" + value)
            if parsed.scheme and parsed.scheme.lower() not in ("http", "https"):
                raise ValueError()
            host = parsed.hostname
            if not host:
                raise ValueError()
            if parsed.port is not None and not 1 <= parsed.port <= 65535:
                raise ValueError()
            try:
                ip_address(host)
            except ValueError:
                labels = host.rstrip(".").encode("idna").decode("ascii").split(".")
                if len(labels) < 2 or any(
                    not re.fullmatch(
                        r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label
                    )
                    for label in labels
                ):
                    raise ValueError()
                if all(label.isdigit() for label in labels):
                    raise ValueError()
        except (ValueError, UnicodeError):
            raise ValueError("Enter a valid HTTP(S) URL or domain name.") from None
        return value


class Analysis(BaseModel):
    url: str
    prediction: Literal["malicious", "legitimate"]
    malicious_probability: float = Field(ge=0, le=1)
    risk_level: Literal["high", "elevated", "moderate", "low"]
    observed_characteristics: list[str]


@asynccontextmanager
async def lifespan(_: FastAPI):
    yield


app = FastAPI(
    title="NurtureShield API",
    version="1.0.0",
    description="Local-only URL structure analysis.",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=list(_origins()),
    allow_origin_regex=r"chrome-extension://[a-p]{32}",
    allow_credentials=False,
    allow_methods=["POST", "OPTIONS"],
    allow_headers=["content-type", "x-nurtureshield-api-key"],
)


@app.get("/health")
def health():
    return {"status": "ok", "service": "nurtureshield"}


@app.post("/api/v1/nurtureshield/analyze", response_model=Analysis)
def analyze(body: AnalyzeInput, request: Request):
    _check_access(request)
    try:
        return predictor.predict(body.url)
    except ModelUnavailable:
        logger.error("NurtureShield model loading failed.")
        raise HTTPException(
            503, "NurtureShield is temporarily unavailable. Please try again later."
        ) from None
    except Exception:
        logger.error("NurtureShield inference failed.")
        raise HTTPException(500, "The link could not be analyzed. Please try again.") from None
