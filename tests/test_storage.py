from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from robot_trials.storage import connect, initialize, inspect_schema, transaction


class StorageTests(unittest.TestCase):
    def test_initialize_is_repeatable(self) -> None:
        connection = sqlite3.connect(":memory:", isolation_level=None)
        connection.row_factory = sqlite3.Row
        try:
            initialize(connection)
            initialize(connection)
            summary = inspect_schema(connection)
        finally:
            connection.close()
        self.assertEqual(summary["missing_tables"], [])
        self.assertEqual(summary["schema_version"], "3")

    def test_transaction_rolls_back_on_error(self) -> None:
        connection = sqlite3.connect(":memory:", isolation_level=None)
        connection.execute("CREATE TABLE items(value TEXT NOT NULL)")
        with self.assertRaises(RuntimeError):
            with transaction(connection):
                connection.execute("INSERT INTO items(value) VALUES('x')")
                raise RuntimeError("stop")
        count = connection.execute("SELECT count(*) FROM items").fetchone()[0]
        connection.close()
        self.assertEqual(count, 0)

    def test_connect_enables_foreign_keys(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            connection = connect(Path(directory) / "test.sqlite3")
            try:
                self.assertEqual(connection.execute("PRAGMA foreign_keys").fetchone()[0], 1)
            finally:
                connection.close()

    def test_migrates_legacy_analysis_jobs_to_fencing_schema(self) -> None:
        connection = sqlite3.connect(":memory:", isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.executescript(
            """
            CREATE TABLE schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            INSERT INTO schema_meta VALUES('schema_version','2');
            CREATE TABLE batches (batch_id TEXT PRIMARY KEY);
            CREATE TABLE analysis_jobs (
                job_id INTEGER PRIMARY KEY AUTOINCREMENT,
                batch_id TEXT NOT NULL,
                batch_revision INTEGER NOT NULL,
                state TEXT NOT NULL CHECK (state IN ('queued','leased','succeeded','failed')),
                attempts INTEGER NOT NULL DEFAULT 0,
                available_at TEXT NOT NULL,
                lease_owner TEXT,
                lease_expires_at TEXT,
                last_error TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            INSERT INTO batches VALUES('b1');
            INSERT INTO analysis_jobs(batch_id,batch_revision,state,attempts,available_at,
                                      lease_owner,lease_expires_at,last_error,created_at,updated_at)
            VALUES('b1',3,'leased',2,'2026-09-24T08:00:00Z','old-worker',
                   '2026-09-24T08:00:30Z','旧错误','2026-09-24T08:00:00Z','2026-09-24T08:00:00Z');
            """
        )
        initialize(connection)
        row = connection.execute("SELECT * FROM analysis_jobs WHERE job_id=1").fetchone()
        self.assertEqual(row["state"], "leased")
        self.assertIsNone(row["lease_token"])
        self.assertEqual(row["max_attempts"], 3)
        self.assertEqual(row["attempts_json"], "[]")
        self.assertEqual(row["lease_owner"], "old-worker")
        self.assertEqual(
            connection.execute("SELECT value FROM schema_meta WHERE key='schema_version'").fetchone()[0], "3"
        )
        connection.close()


if __name__ == "__main__":
    unittest.main()
