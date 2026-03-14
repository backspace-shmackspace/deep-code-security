"""Tests for formatter registry."""

from __future__ import annotations

import pytest

from deep_code_security.shared.formatters import (
    _FORMATTERS,
    get_formatter,
    get_supported_formats,
    register_formatter,
)
from deep_code_security.shared.formatters.html import HtmlFormatter
from deep_code_security.shared.formatters.json import JsonFormatter
from deep_code_security.shared.formatters.sarif import SarifFormatter
from deep_code_security.shared.formatters.text import TextFormatter


class TestGetFormatter:
    def test_get_formatter_text(self):
        fmt = get_formatter("text")
        assert isinstance(fmt, TextFormatter)

    def test_get_formatter_json(self):
        fmt = get_formatter("json")
        assert isinstance(fmt, JsonFormatter)

    def test_get_formatter_sarif(self):
        fmt = get_formatter("sarif")
        assert isinstance(fmt, SarifFormatter)

    def test_get_formatter_html(self):
        fmt = get_formatter("html")
        assert isinstance(fmt, HtmlFormatter)

    def test_get_formatter_unknown_raises(self):
        with pytest.raises(ValueError, match="Unknown output format"):
            get_formatter("xml")


class TestRegisterFormatter:
    def test_register_custom_formatter(self):
        class CustomFormatter:
            def format_hunt(self, data, target_path=""):
                return "custom"

            def format_full_scan(self, data, target_path=""):
                return "custom"

        # Register and retrieve
        register_formatter("custom_test", CustomFormatter)
        try:
            fmt = get_formatter("custom_test")
            assert isinstance(fmt, CustomFormatter)
        finally:
            # Cleanup
            _FORMATTERS.pop("custom_test", None)

    def test_register_duplicate_raises(self):
        with pytest.raises(ValueError, match="already registered"):
            register_formatter("text", TextFormatter)

    def test_register_invalid_class_raises(self):
        class BadFormatter:
            pass

        with pytest.raises(TypeError, match="must implement format_hunt"):
            register_formatter("bad_test", BadFormatter)


class TestGetSupportedFormats:
    def test_get_supported_formats(self):
        formats = get_supported_formats()
        assert formats == ["html", "json", "sarif", "text"]
