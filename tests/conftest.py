from __future__ import annotations

import os
from pathlib import Path

import pytest
from sqlalchemy import create_engine

from minisiem.db import Base

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def rules_dir() -> Path:
    return ROOT / "rules"


@pytest.fixture
def sample_dir() -> Path:
    return ROOT / "sample_logs"


@pytest.fixture
def database_url(tmp_path) -> str:
    """A SQLite file by default; PostgreSQL when TEST_DATABASE_URL is set (as in CI).

    With PostgreSQL every test starts from empty tables.
    """
    url = os.environ.get("TEST_DATABASE_URL")
    if not url:
        return f"sqlite:///{tmp_path / 'test.db'}"
    engine = create_engine(url)
    Base.metadata.drop_all(engine)
    engine.dispose()
    return url
