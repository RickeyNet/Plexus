from typing import cast

import netcontrol.app as app_module
from fastapi import Request


class DummyRequest:
    def __init__(self, headers: dict[str, str]):
        normalized = {k.lower(): v for k, v in headers.items()}

        class HeaderMap(dict):
            def get(self, key, default=None):
                return super().get(str(key).lower(), default)

        self.headers = HeaderMap(normalized)


def _request_with_headers(headers: dict[str, str]) -> DummyRequest:
    return DummyRequest(headers)


def test_validate_startup_config_requires_token(monkeypatch):
    monkeypatch.setattr(app_module, "APP_API_TOKEN", "")
    monkeypatch.setattr(app_module, "_env_flag", lambda *_args, **_kwargs: True)

    try:
        app_module._validate_startup_config()
        assert False, "Expected RuntimeError when API token is required but missing"
    except RuntimeError as exc:
        assert "APP_REQUIRE_API_TOKEN" in str(exc)


def test_extract_api_token_prefers_x_api_token_header():
    req = _request_with_headers(
        {
            "X-API-Token": "token-123",
            "Authorization": "Bearer token-456",
        }
    )
    token = app_module._extract_api_token(cast(Request, req))
    assert token == "token-123"


def test_extract_api_token_uses_bearer_fallback():
    req = _request_with_headers({"Authorization": "Bearer token-456"})
    token = app_module._extract_api_token(cast(Request, req))
    assert token == "token-456"
