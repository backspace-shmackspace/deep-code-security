"""Tests for the C language registry loading and query compilation."""

from __future__ import annotations

from pathlib import Path

import pytest

from deep_code_security.hunter.parser import TreeSitterParser
from deep_code_security.hunter.registry import clear_registry_cache, load_registry
from deep_code_security.hunter.source_sink_finder import find_sinks, find_sources
from deep_code_security.shared.language import Language

REGISTRY_DIR = Path(__file__).parent.parent.parent / "registries"


@pytest.fixture(autouse=True)
def clear_cache():
    """Clear the registry cache before each test."""
    clear_registry_cache()
    yield
    clear_registry_cache()


@pytest.fixture
def c_parser() -> TreeSitterParser:
    return TreeSitterParser()


@pytest.fixture
def c_lang_obj(c_parser):
    """Get C language object for query compilation."""
    return c_parser.get_language_object(Language.C)


@pytest.fixture
def c_registry(c_parser):
    """Load the C registry with compiled queries."""
    lang_obj = c_parser.get_language_object(Language.C)
    return load_registry(Language.C, REGISTRY_DIR, lang_obj)


class TestCRegistryLoad:
    """Tests for C registry loading and structure."""

    def test_c_registry_loads(self, c_registry) -> None:
        """C registry loads successfully."""
        assert c_registry is not None
        assert c_registry.language == Language.C

    def test_c_registry_version(self, c_registry) -> None:
        """C registry version is 2.0.0."""
        assert c_registry.version == "2.0.0"

    def test_c_registry_source_categories(self, c_registry) -> None:
        """C registry has expected source categories."""
        assert "cli_input" in c_registry.sources
        assert "env_input" in c_registry.sources

    def test_c_registry_sink_categories(self, c_registry) -> None:
        """C registry has all expected sink categories."""
        expected_categories = {
            "command_injection",
            "buffer_overflow",
            "format_string",
            "path_traversal",
            "memory_corruption",
            "integer_overflow",
            "dangerous_function",
        }
        assert expected_categories.issubset(set(c_registry.sinks.keys()))

    def test_c_registry_sanitizers(self, c_registry) -> None:
        """C registry has expected sanitizer patterns."""
        sanitizer_patterns = [s.pattern for s in c_registry.sanitizers]
        expected = ["snprintf", "strncpy", "strlcpy", "strlcat", "strncat", "memcpy_s", "strcpy_s"]
        for pattern in expected:
            assert pattern in sanitizer_patterns, f"Missing sanitizer: {pattern}"

    def test_c_all_queries_compile(self, c_registry) -> None:
        """Every source and sink entry has a compiled query."""
        for category, entries in c_registry.sources.items():
            for entry in entries:
                assert entry.compiled_query is not None, (
                    f"Source {entry.pattern!r} in {category} has no compiled query"
                )
        for category, entries in c_registry.sinks.items():
            for entry in entries:
                assert entry.compiled_query is not None, (
                    f"Sink {entry.pattern!r} in {category} has no compiled query"
                )


class TestCSourceQueries:
    """Tests that source queries match expected C patterns."""

    def test_argv_source_found(self, c_parser, c_registry) -> None:
        """argv is detected as a source in main()."""
        code = """\
#include <stdio.h>
int main(int argc, char *argv[]) {
    printf("%s", argv[1]);
    return 0;
}
"""
        tree = c_parser.parse_string(code, Language.C)
        lang_obj = c_parser.get_language_object(Language.C)
        sources = find_sources(tree, c_registry, lang_obj, "/test.c")
        patterns = [s.function for s in sources]
        assert "argv" in patterns

    def test_gets_source_found(self, c_parser, c_registry) -> None:
        """gets() is detected as a source."""
        code = """\
#include <stdio.h>
void foo(void) {
    char buf[64];
    gets(buf);
}
"""
        tree = c_parser.parse_string(code, Language.C)
        lang_obj = c_parser.get_language_object(Language.C)
        sources = find_sources(tree, c_registry, lang_obj, "/test.c")
        patterns = [s.function for s in sources]
        assert "gets" in patterns

    def test_fgets_source_found(self, c_parser, c_registry) -> None:
        """fgets() is detected as a source."""
        code = """\
#include <stdio.h>
void foo(void) {
    char buf[256];
    fgets(buf, sizeof(buf), stdin);
}
"""
        tree = c_parser.parse_string(code, Language.C)
        lang_obj = c_parser.get_language_object(Language.C)
        sources = find_sources(tree, c_registry, lang_obj, "/test.c")
        patterns = [s.function for s in sources]
        assert "fgets" in patterns

    def test_getenv_source_found(self, c_parser, c_registry) -> None:
        """getenv() is detected as a source."""
        code = """\
#include <stdlib.h>
void foo(void) {
    char *path = getenv("PATH");
}
"""
        tree = c_parser.parse_string(code, Language.C)
        lang_obj = c_parser.get_language_object(Language.C)
        sources = find_sources(tree, c_registry, lang_obj, "/test.c")
        patterns = [s.function for s in sources]
        assert "getenv" in patterns


class TestCSinkQueries:
    """Tests that sink queries match expected C patterns."""

    def test_system_sink_found(self, c_parser, c_registry) -> None:
        """system() is detected as a command_injection sink."""
        code = """\
#include <stdlib.h>
void foo(void) {
    system("ls");
}
"""
        tree = c_parser.parse_string(code, Language.C)
        lang_obj = c_parser.get_language_object(Language.C)
        sinks = find_sinks(tree, c_registry, lang_obj, "/test.c")
        sink_funcs = [s.function for s in sinks]
        assert "system" in sink_funcs

    def test_strcpy_sink_found(self, c_parser, c_registry) -> None:
        """strcpy() is detected as a buffer_overflow sink."""
        code = """\
#include <string.h>
void foo(void) {
    char dst[64];
    strcpy(dst, "hello");
}
"""
        tree = c_parser.parse_string(code, Language.C)
        lang_obj = c_parser.get_language_object(Language.C)
        sinks = find_sinks(tree, c_registry, lang_obj, "/test.c")
        sink_funcs = [s.function for s in sinks]
        assert "strcpy" in sink_funcs

    def test_printf_sink_found(self, c_parser, c_registry) -> None:
        """printf() is detected as a format_string sink."""
        code = """\
#include <stdio.h>
void foo(void) {
    printf("hello %s", "world");
}
"""
        tree = c_parser.parse_string(code, Language.C)
        lang_obj = c_parser.get_language_object(Language.C)
        sinks = find_sinks(tree, c_registry, lang_obj, "/test.c")
        sink_funcs = [s.function for s in sinks]
        assert "printf" in sink_funcs

    def test_memcpy_sink_found(self, c_parser, c_registry) -> None:
        """memcpy() is detected as a memory_corruption sink."""
        code = """\
#include <string.h>
void foo(void) {
    char dst[64], src[64];
    memcpy(dst, src, 64);
}
"""
        tree = c_parser.parse_string(code, Language.C)
        lang_obj = c_parser.get_language_object(Language.C)
        sinks = find_sinks(tree, c_registry, lang_obj, "/test.c")
        sink_funcs = [s.function for s in sinks]
        assert "memcpy" in sink_funcs

    def test_malloc_sink_found(self, c_parser, c_registry) -> None:
        """malloc() is detected as an integer_overflow sink."""
        code = """\
#include <stdlib.h>
void foo(void) {
    int *p = malloc(100);
}
"""
        tree = c_parser.parse_string(code, Language.C)
        lang_obj = c_parser.get_language_object(Language.C)
        sinks = find_sinks(tree, c_registry, lang_obj, "/test.c")
        sink_funcs = [s.function for s in sinks]
        assert "malloc" in sink_funcs

    def test_gets_sink_found(self, c_parser, c_registry) -> None:
        """gets() is detected as a dangerous_function sink."""
        code = """\
#include <stdio.h>
void foo(void) {
    char buf[64];
    gets(buf);
}
"""
        tree = c_parser.parse_string(code, Language.C)
        lang_obj = c_parser.get_language_object(Language.C)
        sinks = find_sinks(tree, c_registry, lang_obj, "/test.c")
        sink_funcs = [s.function for s in sinks]
        assert "gets" in sink_funcs

    def test_mktemp_sink_found(self, c_parser, c_registry) -> None:
        """mktemp() is detected as a dangerous_function sink."""
        code = """\
#include <stdlib.h>
void foo(void) {
    char template[] = "/tmp/myXXXXXX";
    mktemp(template);
}
"""
        tree = c_parser.parse_string(code, Language.C)
        lang_obj = c_parser.get_language_object(Language.C)
        sinks = find_sinks(tree, c_registry, lang_obj, "/test.c")
        sink_funcs = [s.function for s in sinks]
        assert "mktemp" in sink_funcs

    def test_fopen_sink_found(self, c_parser, c_registry) -> None:
        """fopen() is detected as a path_traversal sink."""
        code = """\
#include <stdio.h>
void foo(void) {
    FILE *f = fopen("/tmp/test", "r");
}
"""
        tree = c_parser.parse_string(code, Language.C)
        lang_obj = c_parser.get_language_object(Language.C)
        sinks = find_sinks(tree, c_registry, lang_obj, "/test.c")
        sink_funcs = [s.function for s in sinks]
        assert "fopen" in sink_funcs
