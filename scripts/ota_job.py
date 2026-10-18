"""One locked, crash-durable host transaction; persisted evidence is not freshness."""
import fcntl
import json
import os
from pathlib import Path
import sqlite3
import stat
import time

from ota_common import Error
from ota_compression import Package


def fsync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_exclusive(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    fsync_directory(Path(path).parent)


class JobStore:
    def __init__(self, directory):
        self.directory = Path(directory)
        info = self.directory.lstat()
        if (not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700
                or info.st_uid != os.getuid()):
            raise Error("job must be an owned nonsymlink 0700 directory")
        self.lock = os.open(self.directory / "lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.db = sqlite3.connect(self.directory / "job.sqlite")
            os.chmod(self.directory / "job.sqlite", 0o600)
            self.db.execute("PRAGMA synchronous=FULL")
            self.db.execute("PRAGMA journal_mode=DELETE")
        except BaseException:
            os.close(self.lock)
            raise

    @classmethod
    def create(cls, directory, package, owner, targets, policy):
        if (len(owner) != 32 or not any(owner) or not targets or len(targets) > 32
                or len(set(targets)) != len(targets)
                or any(len(t) != 32 or not any(t) for t in targets)):
            raise ValueError("one owner and 1..32 distinct full targets required")
        Path(directory).mkdir(mode=0o700, parents=False)
        job = cls(directory)
        try:
            write_exclusive(job.directory / "package.bin", package.encode())
            with job.db:
                job.db.executescript("""
                    CREATE TABLE meta(key TEXT PRIMARY KEY, value BLOB NOT NULL);
                    CREATE TABLE targets(key BLOB PRIMARY KEY, status BLOB, outcome TEXT NOT NULL DEFAULT 'new');
                    CREATE TABLE operations(id INTEGER PRIMARY KEY, target BLOB, kind INTEGER, body BLOB,
                        state TEXT NOT NULL, started REAL NOT NULL);
                """)
                values = {"schema": b"4", "owner": owner, "package": package.digest,
                          "policy": json.dumps(policy, sort_keys=True).encode(),
                          "attempt": str(1 + int.from_bytes(os.urandom(4), "big") % 0x7FFFFFFF).encode(),
                          "request": b"0"}
                job.db.executemany("INSERT INTO meta VALUES(?,?)", values.items())
                job.db.executemany("INSERT INTO targets(key) VALUES(?)", [(t,) for t in targets])
            fsync_directory(job.directory)
            return job
        except BaseException:
            job.close()
            raise

    @classmethod
    def open(cls, directory):
        info = (Path(directory) / "job.sqlite").lstat()
        if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_uid != os.getuid()):
            raise Error("job database must be an owned nonsymlink 0600 file")
        job = cls(directory)
        try:
            if job.get("schema") != b"4" or job.package.digest != job.get("package"):
                raise Error("job schema/package identity mismatch")
            return job
        except BaseException:
            job.close()
            raise

    @property
    def package(self):
        return Package.open(self.directory / "package.bin")

    @property
    def owner(self):
        return self.get("owner")

    @property
    def targets(self):
        return [row[0] for row in self.db.execute("SELECT key FROM targets ORDER BY rowid")]

    @property
    def policy(self):
        return json.loads(self.get("policy"))

    def get(self, key):
        row = self.db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        if row is None:
            raise Error("incomplete host job")
        return row[0]

    def allocate(self, key, maximum):
        with self.db:
            value = int(self.get(key)) + 1
            if value > maximum:
                raise Error(f"{key} space exhausted; no wrap fallback")
            self.db.execute("UPDATE meta SET value=? WHERE key=?", (str(value).encode(), key))
        return value

    def attempt(self):
        return self.allocate("attempt", 0xFFFFFFFF)

    def request(self):
        # Fresh query nonces prevent replays even when the routing ID cycles.
        with self.db:
            value = int(self.get("request")) % 65535 + 1
            self.db.execute("UPDATE meta SET value=? WHERE key='request'", (str(value).encode(),))
        return value

    def intent(self, target, kind, body):
        with self.db:
            cursor = self.db.execute("INSERT INTO operations(target,kind,body,state,started) VALUES(?,?,?,'uncertain',?)",
                                     (target, int(kind), body, time.time()))
        return cursor.lastrowid

    def resolve(self, operation, state):
        with self.db:
            self.db.execute("UPDATE operations SET state=? WHERE id=?", (state, operation))

    def status(self, status):
        with self.db:
            self.db.execute("UPDATE targets SET status=?,outcome=? WHERE key=?",
                            (status.signed, status.phase.name.lower(), status.target))

    def previous_status(self, target):
        row = self.db.execute("SELECT status FROM targets WHERE key=?", (target,)).fetchone()
        return None if row is None else row[0]

    def uncertain(self, target, kind):
        return self.db.execute("SELECT id FROM operations WHERE target=? AND kind=? AND state='uncertain'",
                               (target, int(kind))).fetchall()

    def close(self):
        if self.db is not None:
            self.db.close()
            self.db = None
        if self.lock is not None:
            os.close(self.lock)
            self.lock = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
