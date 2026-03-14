"""Corpus storage with crash deduplication and input management."""

from __future__ import annotations

import hashlib
import json
import logging
import re
import time
from pathlib import Path

from deep_code_security.fuzzer.corpus.serialization import (
    load_from_file,
    save_to_file,
)
from deep_code_security.fuzzer.models import FuzzInput, FuzzResult

__all__ = ["CorpusManager", "crash_signature", "parse_traceback_location"]

logger = logging.getLogger(__name__)

_TRACEBACK_FILE_RE = re.compile(r'File "([^"]+)", line (\d+)')


def _input_hash(fuzz_input: FuzzInput) -> str:
    key = json.dumps(
        {
            "target_function": fuzz_input.target_function,
            "args": list(fuzz_input.args),
            "kwargs": fuzz_input.kwargs,
        },
        sort_keys=True,
    )
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def parse_traceback_location(traceback: str | None) -> tuple[str, int]:
    """Parse the crash location from a Python traceback string."""
    if not traceback:
        return ("unknown", 0)

    matches = _TRACEBACK_FILE_RE.findall(traceback)
    if not matches:
        return ("unknown", 0)

    file_path, line_str = matches[-1]
    return (file_path, int(line_str))


def crash_signature(result: FuzzResult) -> str:
    """Compute a crash signature for deduplication."""
    exc_type = (result.exception or "").split(":", 1)[0].strip()

    file_path, line_number = parse_traceback_location(result.traceback)
    if file_path != "unknown":
        tb_line = f'File "{file_path}", line {line_number}'
    else:
        tb_line = ""

    return f"{exc_type}|{tb_line}"


_crash_signature = crash_signature


class CorpusManager:
    """Manages the corpus of interesting fuzz inputs."""

    def __init__(self, corpus_dir: str | Path) -> None:
        self.corpus_dir = Path(corpus_dir)
        self.corpus_dir.mkdir(parents=True, exist_ok=True)

        self._interesting_dir = self.corpus_dir / "interesting"
        self._crashes_dir = self.corpus_dir / "crashes"
        self._interesting_dir.mkdir(exist_ok=True)
        self._crashes_dir.mkdir(exist_ok=True)

        self._input_hashes: set[str] = set()
        self._crash_signatures: set[str] = set()

        self._load_existing()

    def _load_existing(self) -> None:
        for path in self._interesting_dir.glob("*.json"):
            try:
                result = load_from_file(path)
                self._input_hashes.add(_input_hash(result.input))
            except Exception as e:
                logger.warning("Failed to load corpus entry %s: %s", path, e)

        for path in self._crashes_dir.glob("*.json"):
            try:
                result = load_from_file(path)
                self._crash_signatures.add(_crash_signature(result))
                self._input_hashes.add(_input_hash(result.input))
            except Exception as e:
                logger.warning("Failed to load crash entry %s: %s", path, e)

        logger.debug(
            "Loaded corpus: %d interesting inputs, %d unique crashes",
            len(self._input_hashes),
            len(self._crash_signatures),
        )

    def add_interesting(self, result: FuzzResult) -> bool:
        input_hash = _input_hash(result.input)
        if input_hash in self._input_hashes:
            logger.debug("Duplicate input, not storing: %s", input_hash)
            return False

        self._input_hashes.add(input_hash)
        filename = f"interesting_{input_hash}_{int(time.time())}.json"
        path = self._interesting_dir / filename

        try:
            save_to_file(result, path)
            logger.debug("Stored interesting input: %s", filename)
            return True
        except Exception as e:
            logger.error("Failed to store interesting input: %s", e)
            return False

    def add_crash(self, result: FuzzResult) -> bool:
        sig = _crash_signature(result)
        if sig in self._crash_signatures:
            logger.debug("Duplicate crash signature, not storing: %s", sig[:50])
            return False

        self._crash_signatures.add(sig)
        self._input_hashes.add(_input_hash(result.input))

        input_hash = _input_hash(result.input)
        filename = f"crash_{input_hash}_{int(time.time())}.json"
        path = self._crashes_dir / filename

        try:
            save_to_file(result, path)
            logger.info(
                "NEW CRASH stored: %s -> %s",
                result.input.target_function,
                (result.exception or "")[:100],
            )
            return True
        except Exception as e:
            logger.error("Failed to store crash: %s", e)
            return False

    def get_all_crashes(self) -> list[FuzzResult]:
        crashes = []
        for path in sorted(self._crashes_dir.glob("*.json")):
            try:
                result = load_from_file(path)
                crashes.append(result)
            except Exception as e:
                logger.warning("Failed to load crash %s: %s", path, e)
        return crashes

    def get_all_interesting(self) -> list[FuzzResult]:
        results = []
        for path in sorted(self._interesting_dir.glob("*.json")):
            try:
                result = load_from_file(path)
                results.append(result)
            except Exception as e:
                logger.warning("Failed to load interesting input %s: %s", path, e)
        return results

    def get_summary(self) -> dict:
        crash_files = list(self._crashes_dir.glob("*.json"))
        interesting_files = list(self._interesting_dir.glob("*.json"))

        return {
            "total_inputs": len(self._input_hashes),
            "crash_count": len(self._crash_signatures),
            "interesting_count": len(interesting_files),
            "crash_files": len(crash_files),
            "coverage_percent": 0.0,
        }

    def load_seed_corpus(self, seed_dir: str | Path) -> int:
        seed_dir = Path(seed_dir)
        if not seed_dir.exists():
            logger.warning("Seed corpus directory not found: %s", seed_dir)
            return 0

        count = 0
        for path in seed_dir.glob("*.json"):
            try:
                result = load_from_file(path)
                if self.add_interesting(result):
                    count += 1
            except Exception as e:
                logger.warning("Failed to load seed %s: %s", path, e)

        logger.info("Loaded %d seed inputs from %s", count, seed_dir)
        return count
