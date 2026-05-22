from openclaw_governance_proxy.database import sqlite_wal_enabled


def test_sqlite_wal_enabled(app):
    assert isinstance(sqlite_wal_enabled(), bool)
