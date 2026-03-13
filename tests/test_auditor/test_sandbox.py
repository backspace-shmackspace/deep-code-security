"""Tests for the NoOp sandbox and sandbox protocols."""

from __future__ import annotations

from deep_code_security.auditor.noop import NoOpExploitGenerator, NoOpSandbox
from deep_code_security.auditor.protocols import ExploitGeneratorProtocol, SandboxProvider


class TestNoOpSandbox:
    """Tests for NoOpSandbox."""

    def test_is_not_available(self) -> None:
        """NoOp sandbox always reports as unavailable."""
        sandbox = NoOpSandbox()
        assert sandbox.is_available() is False

    def test_run_exploit_raises(self) -> None:
        """NoOp sandbox raises RuntimeError if run_exploit is called."""
        import pytest
        sandbox = NoOpSandbox()
        with pytest.raises(RuntimeError, match="NoOpSandbox"):
            sandbox.run_exploit("python", "/tmp", "print('hello')")

    def test_build_images_returns_false(self) -> None:
        """NoOp sandbox build_images returns False."""
        sandbox = NoOpSandbox()
        assert sandbox.build_images() is False

    def test_satisfies_protocol(self) -> None:
        """NoOpSandbox satisfies the SandboxProvider protocol."""
        sandbox = NoOpSandbox()
        assert isinstance(sandbox, SandboxProvider)


class TestNoOpExploitGenerator:
    """Tests for NoOpExploitGenerator."""

    def test_generates_placeholder_script(self, sample_raw_finding) -> None:
        """NoOp generator returns a placeholder script."""
        gen = NoOpExploitGenerator()
        script, hash_ = gen.generate_exploit(sample_raw_finding)
        assert "NoOp" in script or "NO_EXPLOIT_GENERATOR" in script
        assert len(hash_) == 64  # SHA-256

    def test_hash_is_deterministic(self, sample_raw_finding) -> None:
        """Same placeholder script produces same hash."""
        gen = NoOpExploitGenerator()
        _, hash1 = gen.generate_exploit(sample_raw_finding)
        _, hash2 = gen.generate_exploit(sample_raw_finding)
        assert hash1 == hash2

    def test_satisfies_protocol(self) -> None:
        """NoOpExploitGenerator satisfies the ExploitGeneratorProtocol."""
        gen = NoOpExploitGenerator()
        assert isinstance(gen, ExploitGeneratorProtocol)
