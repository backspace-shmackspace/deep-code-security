"""Tests for consent management."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from deep_code_security.fuzzer.consent import (
    has_stored_consent,
    record_consent,
    revoke_consent,
    verify_consent,
)
from deep_code_security.fuzzer.exceptions import ConsentRequiredError


class TestConsent:
    def test_verify_consent_with_flag(self) -> None:
        """Consent flag bypasses the check."""
        verify_consent(consent_flag=True)  # Should not raise

    def test_verify_consent_no_consent(self, tmp_path: Path) -> None:
        """Without consent, raises ConsentRequiredError."""
        with patch("deep_code_security.fuzzer.consent.CONSENT_FILE", tmp_path / "nope.json"):
            with patch(
                "deep_code_security.fuzzer.consent._OLD_CONSENT_FILE", tmp_path / "old_nope.json"
            ):
                with pytest.raises(ConsentRequiredError):
                    verify_consent(consent_flag=False)

    def test_record_and_check(self, tmp_path: Path) -> None:
        consent_file = tmp_path / "consent.json"
        consent_dir = tmp_path
        with patch("deep_code_security.fuzzer.consent.CONSENT_FILE", consent_file):
            with patch("deep_code_security.fuzzer.consent.CONSENT_DIR", consent_dir):
                record_consent()
                assert consent_file.exists()
                data = json.loads(consent_file.read_text())
                assert data["consented"] is True

    def test_revoke_consent(self, tmp_path: Path) -> None:
        consent_file = tmp_path / "consent.json"
        consent_file.write_text('{"consented": true}')
        with patch("deep_code_security.fuzzer.consent.CONSENT_FILE", consent_file):
            revoke_consent()
            assert not consent_file.exists()

    def test_migration_from_old_path(self, tmp_path: Path) -> None:
        """Consent migrates from old fuzzy-wuzzy path."""
        old_dir = tmp_path / "old"
        old_dir.mkdir()
        old_file = old_dir / "consent.json"
        old_file.write_text('{"consented": true, "version": "1.0"}')

        new_dir = tmp_path / "new"
        new_file = new_dir / "consent.json"

        with patch("deep_code_security.fuzzer.consent._OLD_CONSENT_FILE", old_file):
            with patch("deep_code_security.fuzzer.consent.CONSENT_FILE", new_file):
                with patch("deep_code_security.fuzzer.consent.CONSENT_DIR", new_dir):
                    result = has_stored_consent()
                    assert result is True
                    assert new_file.exists()
                    # Old file should still exist (copy, not move)
                    assert old_file.exists()

    def test_no_migration_if_new_exists(self, tmp_path: Path) -> None:
        old_file = tmp_path / "old" / "consent.json"
        new_file = tmp_path / "new" / "consent.json"
        new_file.parent.mkdir(parents=True)
        new_file.write_text('{"consented": true}')

        with patch("deep_code_security.fuzzer.consent._OLD_CONSENT_FILE", old_file):
            with patch("deep_code_security.fuzzer.consent.CONSENT_FILE", new_file):
                result = has_stored_consent()
                assert result is True

    def test_no_crash_if_old_missing(self, tmp_path: Path) -> None:
        old_file = tmp_path / "nonexistent" / "consent.json"
        new_file = tmp_path / "also_nonexistent" / "consent.json"

        with patch("deep_code_security.fuzzer.consent._OLD_CONSENT_FILE", old_file):
            with patch("deep_code_security.fuzzer.consent.CONSENT_FILE", new_file):
                result = has_stored_consent()
                assert result is False
