"""Tests for json_output helpers."""

from __future__ import annotations

import json

from pydantic import BaseModel

from deep_code_security.shared.json_output import (
    serialize_model,
    serialize_models,
    to_json_dict,
    to_json_string,
)


class SampleModel(BaseModel):
    name: str
    value: int


class TestSerializeModel:
    def test_returns_dict(self) -> None:
        m = SampleModel(name="test", value=42)
        result = serialize_model(m)
        assert isinstance(result, dict)
        assert result["name"] == "test"
        assert result["value"] == 42

    def test_json_compatible(self) -> None:
        m = SampleModel(name="hello", value=1)
        result = serialize_model(m)
        # Should be JSON serializable
        json.dumps(result)


class TestSerializeModels:
    def test_empty_list(self) -> None:
        assert serialize_models([]) == []

    def test_list_of_models(self) -> None:
        models = [SampleModel(name=f"m{i}", value=i) for i in range(3)]
        result = serialize_models(models)
        assert len(result) == 3
        assert result[0]["name"] == "m0"
        assert result[2]["value"] == 2


class TestToJsonDict:
    def test_model_returns_dict(self) -> None:
        m = SampleModel(name="x", value=7)
        result = to_json_dict(m)
        assert isinstance(result, dict)
        assert result["name"] == "x"

    def test_list_of_models(self) -> None:
        models = [SampleModel(name="a", value=1), SampleModel(name="b", value=2)]
        result = to_json_dict(models)
        assert isinstance(result, list)
        assert len(result) == 2

    def test_plain_dict_passthrough(self) -> None:
        d = {"key": "value", "num": 99}
        result = to_json_dict(d)
        assert result == d

    def test_nested_list(self) -> None:
        models = [SampleModel(name="c", value=3)]
        result = to_json_dict(models)
        assert result[0]["name"] == "c"


class TestToJsonString:
    def test_returns_string(self) -> None:
        m = SampleModel(name="test", value=5)
        result = to_json_string(m)
        assert isinstance(result, str)

    def test_valid_json(self) -> None:
        m = SampleModel(name="json_test", value=100)
        result = to_json_string(m)
        parsed = json.loads(result)
        assert parsed["name"] == "json_test"
        assert parsed["value"] == 100

    def test_list_of_models(self) -> None:
        models = [SampleModel(name="a", value=1)]
        result = to_json_string(models)
        parsed = json.loads(result)
        assert isinstance(parsed, list)
        assert parsed[0]["name"] == "a"

    def test_plain_dict(self) -> None:
        d = {"key": "val"}
        result = to_json_string(d)
        parsed = json.loads(result)
        assert parsed == d


# ---------------------------------------------------------------------------
# shared.__init__ lazy getter tests
# ---------------------------------------------------------------------------


class TestSharedInitGetters:
    """Tests for lazy getter functions in shared/__init__.py."""

    def test_get_formatter_returns_formatter(self) -> None:
        """get_formatter() proxies to shared.formatters."""
        import deep_code_security.shared as shared

        formatter = shared.get_formatter("json")
        assert formatter is not None

    def test_get_supported_formats_returns_list(self) -> None:
        """get_supported_formats() returns a non-empty list of strings."""
        import deep_code_security.shared as shared

        formats = shared.get_supported_formats()
        assert isinstance(formats, list)
        assert "json" in formats


# ---------------------------------------------------------------------------
# Language module coverage
# ---------------------------------------------------------------------------


class TestLanguageHelpers:
    """Tests for is_supported() and get_supported_extensions() in shared.language."""

    def test_is_supported_python_file(self) -> None:
        from pathlib import Path

        from deep_code_security.shared.language import is_supported

        assert is_supported(Path("foo.py")) is True

    def test_get_supported_extensions_returns_sorted_list(self) -> None:
        from deep_code_security.shared.language import get_supported_extensions

        exts = get_supported_extensions()
        assert isinstance(exts, list)
        assert exts == sorted(exts)
        assert ".py" in exts
