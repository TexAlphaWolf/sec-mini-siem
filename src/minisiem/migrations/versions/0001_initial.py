"""Initial schema: events and alerts.

Revision ID: 0001
Revises:
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "events",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("ts", sa.DateTime(), nullable=False),
        sa.Column("source", sa.String(32), nullable=False),
        sa.Column("host", sa.String(255), nullable=False),
        sa.Column("event_type", sa.String(64), nullable=False),
        sa.Column("src_ip", sa.String(64), nullable=True),
        sa.Column("username", sa.String(128), nullable=True),
        sa.Column("raw", sa.Text(), nullable=False),
        sa.Column("fields", sa.JSON(), nullable=False),
    )
    op.create_index("ix_events_ts", "events", ["ts"])
    op.create_index("ix_events_event_type", "events", ["event_type"])
    op.create_index("ix_events_src_ip", "events", ["src_ip"])

    op.create_table(
        "alerts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("ts", sa.DateTime(), nullable=False),
        sa.Column("rule_id", sa.String(128), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("src_ip", sa.String(64), nullable=True),
        sa.Column("group_key", sa.String(255), nullable=True),
        sa.Column("event_count", sa.Integer(), nullable=False),
        sa.Column("tags", sa.JSON(), nullable=False),
        sa.Column("details", sa.JSON(), nullable=False),
    )
    op.create_index("ix_alerts_ts", "alerts", ["ts"])
    op.create_index("ix_alerts_rule_id", "alerts", ["rule_id"])
    op.create_index("ix_alerts_severity", "alerts", ["severity"])
    op.create_index("ix_alerts_src_ip", "alerts", ["src_ip"])


def downgrade() -> None:
    op.drop_table("alerts")
    op.drop_table("events")
