from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def rules_dir() -> Path:
    return ROOT / "rules"


@pytest.fixture
def sample_dir() -> Path:
    return ROOT / "sample_logs"
