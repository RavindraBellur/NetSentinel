"""Restoring a backup must never lose the recent changes still in SQLite's write-ahead log."""
import os
import sqlite3
import tempfile
import unittest

from tests import _env  # noqa: F401
from netscan import backup, store


def make(path, n):
    c = sqlite3.connect(path)
    c.execute("PRAGMA journal_mode=WAL"); c.execute("PRAGMA wal_autocheckpoint=0")
    c.execute("create table incidents(id)"); c.execute("create table samples(id)")
    c.executemany("insert into incidents values(?)", [(i,) for i in range(n)])
    c.commit()
    return c


class Restore(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.live, self.bk = os.path.join(self.dir, "live.db"), os.path.join(self.dir, "backup.db")
        self.saved = store.DB_PATH
        store.DB_PATH = self.live

    def tearDown(self):
        store.DB_PATH = self.saved

    def count(self, path):
        c = sqlite3.connect(path)
        try:
            return c.execute("select count(*) from incidents").fetchone()[0]
        finally:
            c.close()

    def test_needs_confirm(self):
        self.assertFalse(backup.restore(self.bk, confirm=False)[0])

    def test_refuses_foreign_file(self):
        c = sqlite3.connect(self.bk); c.execute("create table other(x)"); c.commit(); c.close()
        self.assertFalse(backup.restore(self.bk, confirm=True)[0])

    def test_safety_copy_keeps_wal_data(self):
        c = make(self.bk, 5); c.execute("PRAGMA wal_checkpoint(TRUNCATE)"); c.close()
        holder = make(self.live, 100)            # console running, all 100 rows still in the WAL
        ok, msg = backup.restore(self.bk, confirm=True)
        holder.close()
        self.assertTrue(ok, msg)
        keep = [f for f in os.listdir(self.dir) if ".pre-restore-" in f and not f.endswith(("-wal", "-shm"))]
        self.assertEqual(len(keep), 1)
        self.assertEqual(self.count(os.path.join(self.dir, keep[0])), 100)
        self.assertEqual(self.count(self.live), 5)


if __name__ == "__main__":
    unittest.main()
