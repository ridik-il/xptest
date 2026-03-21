"""Shared pytest fixtures and path constants."""

from __future__ import annotations

from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"
XRD_PATH = str(FIXTURES_DIR / "xrd.yaml")
SAMPLE_BUNDLE = str(Path(__file__).parent.parent / "schemas" / "sample-bundle")


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES_DIR


@pytest.fixture
def xrd_path() -> str:
    return XRD_PATH


@pytest.fixture
def sample_bundle() -> str:
    return SAMPLE_BUNDLE
