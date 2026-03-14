"""Consent management for API source code transmission.

Consent is stored in ~/.config/deep-code-security/consent.json.
Migration from the old fuzzy-wuzzy consent path is handled automatically
on first access.
"""

from __future__ import annotations

import json
import logging
import shutil
import tempfile
import time
from pathlib import Path

from deep_code_security.fuzzer.exceptions import ConsentRequiredError

__all__ = [
    "CONSENT_DIR",
    "CONSENT_FILE",
    "has_stored_consent",
    "record_consent",
    "revoke_consent",
    "verify_consent",
]

logger = logging.getLogger(__name__)

CONSENT_DIR = Path.home() / ".config" / "deep-code-security"
CONSENT_FILE = CONSENT_DIR / "consent.json"

# Legacy path from fuzzy-wuzzy
_OLD_CONSENT_DIR = Path.home() / ".config" / "fuzzy-wuzzy"
_OLD_CONSENT_FILE = _OLD_CONSENT_DIR / "consent.json"


def _migrate_consent() -> None:
    """Migrate consent from the old fuzzy-wuzzy path if needed.

    Uses copy-then-rename for atomicity. Does not remove the old file.
    """
    if _OLD_CONSENT_FILE.exists() and not CONSENT_FILE.exists():
        try:
            CONSENT_DIR.mkdir(parents=True, exist_ok=True)
            # Atomic copy via temp file + rename
            fd, tmp_path = tempfile.mkstemp(dir=str(CONSENT_DIR), suffix=".tmp")
            try:
                import os

                os.close(fd)
                shutil.copy2(str(_OLD_CONSENT_FILE), tmp_path)
                Path(tmp_path).rename(CONSENT_FILE)
            except Exception:
                # Clean up temp file on failure
                try:
                    Path(tmp_path).unlink(missing_ok=True)
                except OSError:
                    pass
                raise
            logger.info(
                "Migrated consent from fuzzy-wuzzy to deep-code-security. "
                "You may remove %s manually.",
                _OLD_CONSENT_FILE,
            )
        except Exception as e:
            logger.warning("Failed to migrate consent from old path: %s", e)


def has_stored_consent() -> bool:
    """Check if consent has been stored.

    Returns:
        True if consent.json exists and contains consented=True.
    """
    _migrate_consent()
    if CONSENT_FILE.exists():
        try:
            with open(CONSENT_FILE) as f:
                data = json.load(f)
            return bool(data.get("consented", False))
        except Exception:
            pass
    return False


def verify_consent(consent_flag: bool) -> None:
    """Verify that the user has consented to source code transmission.

    Args:
        consent_flag: If True, consent is given via CLI flag.

    Raises:
        ConsentRequiredError: If consent has not been given.
    """
    if consent_flag:
        logger.debug("Consent bypassed via --consent flag")
        return

    if has_stored_consent():
        logger.debug("Stored consent found")
        return

    raise ConsentRequiredError(
        "This tool sends your source code to the Anthropic API for analysis.\n"
        "Anthropic's API data is not used for model training.\n"
        "See: https://docs.anthropic.com/en/docs/legal/privacy\n\n"
        "To consent, run with --consent flag (records consent for future runs).\n"
        "To preview what would be sent, use --dry-run."
    )


def record_consent() -> None:
    """Record user consent to disk."""
    CONSENT_DIR.mkdir(parents=True, exist_ok=True)
    consent_data = {
        "consented": True,
        "timestamp": time.time(),
        "version": "1.0",
    }
    # Atomic write via temp + rename
    fd, tmp_path = tempfile.mkstemp(dir=str(CONSENT_DIR), suffix=".tmp")
    try:
        import os

        os.close(fd)
        Path(tmp_path).write_text(json.dumps(consent_data, indent=2), encoding="utf-8")
        Path(tmp_path).rename(CONSENT_FILE)
    except Exception:
        try:
            Path(tmp_path).unlink(missing_ok=True)
        except OSError:
            pass
        raise
    logger.info("Consent recorded to %s", CONSENT_FILE)


def revoke_consent() -> None:
    """Revoke stored consent."""
    if CONSENT_FILE.exists():
        CONSENT_FILE.unlink()
        logger.info("Consent revoked")
