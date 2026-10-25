"""Optional persistence for parsed packets.

``design.md`` § 6.  A persistor stores *parsed rows*, not raw frames:

* ``store(column, data, previous_id)`` appends one field and returns a unique
  record id.  Passing ``previous_id`` links the field into the same logical
  row.
* ``store_full(dict)`` is the convenience wrapper that walks a parsed packet
  and chains ``store`` calls.
* ``retrieve(id, location)`` returns the reassembled row, or ``None``.
* ``persist()`` / ``resume()`` move everything to and from disk.

Persistence is entirely optional — a session with no persistor keeps nothing.
"""

from __future__ import annotations

import json
import logging
import pickle
import sqlite3
import threading
import uuid
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List, Optional

import pandas as pd

log = logging.getLogger(__name__)

__all__ = [
    "Persistor",
    "PicklePersistor",
    "JSONLPersistor",
    "SQLitePersistor",
    "ArrowPlasmaPersistor",
]


class Persistor(ABC):
    """Abstract store for parsed packets."""

    def __init__(self, path: Optional[Any] = None) -> None:
        self.path = Path(path) if path is not None else None
        self._columns: List[str] = []
        self._rows: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()
        log.debug(
            "%s initialised with path=%s (no file touched yet)",
            type(self).__name__,
            self.path,
        )

    # -- schema --------------------------------------------------------
    def register(self, column_name: str) -> None:
        """Declare a column so it appears even if a row omits it."""
        if column_name not in self._columns:
            self._columns.append(column_name)
            log.debug(
                "registered new column %r as index %d (%d column(s) total)",
                column_name,
                len(self._columns) - 1,
                len(self._columns),
            )
        else:
            log.debug("column %r already registered; schema unchanged", column_name)

    def columns(self) -> List[str]:
        return list(self._columns)

    # -- writing -------------------------------------------------------
    @abstractmethod
    def store(self, column: str, data: Any, previous_id: Optional[str] = None) -> str:
        """Append ``data`` under ``column``; return the record id."""
        raise NotImplementedError

    def store_full(self, data: Dict[str, Any]) -> Optional[str]:
        """Store every field of a parsed packet as one linked row."""
        record_id: Optional[str] = None
        for column, value in data.items():
            self.register(column)
            record_id = self.store(column, value, previous_id=record_id)
            log.debug(
                "chained field %r onto record %s (%d of %d field(s))",
                column,
                record_id,
                len(self._rows.get(str(record_id), {})),
                len(data),
            )
        return record_id

    # -- reading -------------------------------------------------------
    @abstractmethod
    def history(self) -> pd.DataFrame:
        """All stored rows as a DataFrame."""
        raise NotImplementedError

    def retrieve(self, id: Any, location: Optional[Any] = None) -> Optional[Dict[str, Any]]:
        """The reassembled row for ``id``, or ``None`` if it is unknown."""
        if location is not None:
            self.path = Path(location)
            log.debug("retrieve() auto-resuming from %s before lookup", self.path)
            self.resume()
        with self._lock:
            row = self._rows.get(str(id))
            log.debug(
                "looked up record %s under the store lock: %s",
                id,
                "found" if row is not None else "absent",
            )
        if row is None:
            log.debug("record %s is unknown to %s; returning None", id, type(self).__name__)
            return None
        return dict(row)

    # -- disk ----------------------------------------------------------
    @abstractmethod
    def persist(self, path: Optional[Any] = None) -> None:
        raise NotImplementedError

    @abstractmethod
    def resume(self, path: Optional[Any] = None) -> None:
        raise NotImplementedError

    # -- helpers -------------------------------------------------------
    def _resolve(self, path: Optional[Any]) -> Optional[Path]:
        target = Path(path) if path is not None else self.path
        if target is not None:
            self.path = target
            log.debug("resolved target path to %s for %s", target, type(self).__name__)
        else:
            log.debug(
                "no path argument and no configured path; %s has nowhere to write",
                type(self).__name__,
            )
        return target

    def _frame(self) -> pd.DataFrame:
        with self._lock:
            rows = [dict(row) for row in self._rows.values()]
            columns = list(self._columns)
            log.debug(
                "snapshotted %d row(s) and %d declared column(s) under the store lock",
                len(rows),
                len(columns),
            )
        for row in rows:
            for key in row:
                if key not in columns:
                    columns.append(key)
                    log.debug("column %r appears only in data; appending after declared ones", key)
        frame = pd.DataFrame(rows, columns=columns)
        log.debug("built DataFrame with shape %s", frame.shape)
        return frame


class _InMemoryPersistor(Persistor):
    """Shared implementation: rows live in a dict keyed by record id."""

    def store(self, column: str, data: Any, previous_id: Optional[str] = None) -> str:
        self.register(column)
        with self._lock:
            record_id = str(previous_id) if previous_id is not None else uuid.uuid4().hex
            self._rows.setdefault(record_id, {})[column] = data
            log.debug(
                "stored column %r on record %s under the store lock (%s)",
                column,
                record_id,
                "extending previous_id" if previous_id is not None else "minted a new id",
            )
        return record_id

    def history(self) -> pd.DataFrame:
        return self._frame()


class PicklePersistor(_InMemoryPersistor):
    """Whole-history pickle dump."""

    def __init__(self, path: Optional[Any] = None) -> None:
        super().__init__(path)
        if self.path is not None and self.path.exists():
            log.debug("pickle store at %s already exists; resuming it", self.path)
            self.resume()
        else:
            log.debug("pickle store at %s does not exist yet; starting empty", self.path)

    def persist(self, path: Optional[Any] = None) -> None:
        target = self._resolve(path)
        if target is None:
            log.warning("persist() called on %s with no path", type(self).__name__)
            raise ValueError("no path configured for persist()")
        target.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            payload = {"columns": list(self._columns), "rows": dict(self._rows)}
            log.debug(
                "pickling %d row(s) over %d column(s) under the store lock",
                len(payload["rows"]),
                len(payload["columns"]),
            )
        with open(target, "wb") as handle:
            pickle.dump(payload, handle)
            log.debug("opened %s for binary write and dumped the payload", target)

    def resume(self, path: Optional[Any] = None) -> None:
        target = self._resolve(path)
        if target is None or not target.exists():
            log.debug("nothing to resume: pickle target %s is unset or missing", target)
            return
        with open(target, "rb") as handle:
            payload = pickle.load(handle)
            log.debug("opened %s for binary read and unpickled the payload", target)
        with self._lock:
            self._columns = list(payload.get("columns", []))
            self._rows = dict(payload.get("rows", {}))
            log.debug(
                "replaced store state with %d row(s) and %d column(s) from %s",
                len(self._rows),
                len(self._columns),
                target,
            )


class JSONLPersistor(_InMemoryPersistor):
    """One JSON object per record, appended as it is stored."""

    def __init__(self, path: Optional[Any] = None) -> None:
        super().__init__(path)
        if self.path is not None and self.path.exists():
            log.debug("JSONL log at %s already exists; resuming it", self.path)
            self.resume()
        else:
            log.debug("JSONL log at %s does not exist yet; starting empty", self.path)

    def store(self, column: str, data: Any, previous_id: Optional[str] = None) -> str:
        record_id = super().store(column, data, previous_id=previous_id)
        if previous_id is None:
            # A brand-new record starts a new line.
            log.debug("record %s is new (no previous_id); appending its id line", record_id)
            self._append_line({"id": record_id})
        else:
            log.debug(
                "field %r extends record %s (previous_id=%s); no new line needed",
                column,
                record_id,
                previous_id,
            )
        return record_id

    def _append_line(self, payload: Dict[str, Any]) -> None:
        if self.path is None:
            log.debug("no JSONL path configured; dropping %d key(s) on the floor", len(payload))
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, default=str) + "\n")
            log.debug("opened %s for append and wrote %d key(s)", self.path, len(payload))

    def persist(self, path: Optional[Any] = None) -> None:
        """Rewrite the whole log so it matches the current in-memory state."""
        target = self._resolve(path)
        if target is None:
            log.warning("persist() called on %s with no path", type(self).__name__)
            raise ValueError("no path configured for persist()")
        target.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            rows = {str(k): dict(v) for k, v in self._rows.items()}
            log.debug("rewriting the whole JSONL log with %d row(s)", len(rows))
        with open(target, "w", encoding="utf-8") as handle:
            for record_id, row in rows.items():
                handle.write(json.dumps({"id": record_id, **row}, default=str) + "\n")
                log.debug(
                    "wrote record %s with %d field(s) to %s",
                    record_id,
                    len(row),
                    target,
                )

    def resume(self, path: Optional[Any] = None) -> None:
        target = self._resolve(path)
        if target is None or not target.exists():
            log.debug("nothing to resume: JSONL target %s is unset or missing", target)
            return
        with self._lock:
            self._rows = {}
            self._columns = []
            log.debug("cleared in-memory rows and columns before replaying %s", target)
        with open(target, encoding="utf-8") as handle:
            log.debug("opened %s for read; replaying one JSON object per line", target)
            for line in handle:
                line = line.strip()
                if not line:
                    log.debug("skipping a blank line in %s", target)
                    continue
                record = json.loads(line)
                record_id = str(record.pop("id", uuid.uuid4().hex))
                with self._lock:
                    self._rows[record_id] = record
                    log.debug("restored record %s with %d field(s)", record_id, len(record))
                    for key in record:
                        if key not in self._columns:
                            self._columns.append(key)
                            log.debug("column %r first seen while replaying %s", key, target)
        log.debug(
            "replayed %d record(s) and %d column(s) from %s",
            len(self._rows),
            len(self._columns),
            target,
        )

    def history(self) -> pd.DataFrame:
        if self.path is not None and self.path.exists() and not self._rows:
            log.debug("memory is empty but %s exists; resuming before building history", self.path)
            self.resume()
        return self._frame()


class SQLitePersistor(_InMemoryPersistor):
    """A tiny key/value table: ``(record_id, column, value)``."""

    _SCHEMA = (
        "CREATE TABLE IF NOT EXISTS records ("
        "  record_id TEXT NOT NULL,"
        "  column_name TEXT NOT NULL,"
        "  value TEXT,"
        "  PRIMARY KEY (record_id, column_name)"
        ")"
    )

    def __init__(self, path: Optional[Any] = None) -> None:
        super().__init__(path)
        if self.path is not None:
            log.debug("sqlite store configured at %s; ensuring schema", self.path)
            self._ensure_schema()
            if self.path.exists():
                log.debug("sqlite database %s exists; resuming its rows", self.path)
                self.resume()
            else:
                log.debug("sqlite database %s is new; starting empty", self.path)
        else:
            log.debug("no sqlite path configured; %s stays in memory only", type(self).__name__)

    def _connect(self) -> sqlite3.Connection:
        assert self.path is not None
        self.path.parent.mkdir(parents=True, exist_ok=True)
        log.debug("opening sqlite connection to %s", self.path)
        return sqlite3.connect(str(self.path))

    def _ensure_schema(self) -> None:
        with self._connect() as conn:
            conn.execute(self._SCHEMA)
            log.debug("issued CREATE TABLE IF NOT EXISTS records against %s", self.path)

    def store(self, column: str, data: Any, previous_id: Optional[str] = None) -> str:
        record_id = super().store(column, data, previous_id=previous_id)
        if self.path is not None:
            self._ensure_schema()
            with self._connect() as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO records VALUES (?, ?, ?)",
                    (record_id, column, json.dumps(data, default=str)),
                )
                log.debug("upserted record %s column %r into %s", record_id, column, self.path)
        else:
            log.debug("record %s column %r kept in memory only", record_id, column)
        return record_id

    def persist(self, path: Optional[Any] = None) -> None:
        target = self._resolve(path)
        if target is None:
            log.warning("persist() called on %s with no path", type(self).__name__)
            raise ValueError("no path configured for persist()")
        self._ensure_schema()
        with self._lock:
            rows = {str(k): dict(v) for k, v in self._rows.items()}
            log.debug("persisting %d row(s) to sqlite at %s", len(rows), target)
        with self._connect() as conn:
            conn.execute("DELETE FROM records")
            log.debug("cleared the records table in %s before rewriting it", target)
            for record_id, row in rows.items():
                for column, value in row.items():
                    conn.execute(
                        "INSERT OR REPLACE INTO records VALUES (?, ?, ?)",
                        (record_id, column, json.dumps(value, default=str)),
                    )
                    log.debug("re-inserted record %s column %r into %s", record_id, column, target)

    def resume(self, path: Optional[Any] = None) -> None:
        target = self._resolve(path)
        if target is None or not target.exists():
            log.debug("nothing to resume: sqlite target %s is unset or missing", target)
            return
        self._ensure_schema()
        with self._connect() as conn:
            cursor = conn.execute("SELECT record_id, column_name, value FROM records")
            fetched = cursor.fetchall()
            log.debug("read %d (record_id, column, value) row(s) from %s", len(fetched), target)
        with self._lock:
            self._rows = {}
            self._columns = []
            for record_id, column, value in fetched:
                try:
                    decoded = json.loads(value)
                except (TypeError, ValueError):
                    log.debug(
                        "value for record %s column %r at %s is not JSON; keeping it verbatim",
                        record_id,
                        column,
                        target,
                    )
                    decoded = value
                self._rows.setdefault(str(record_id), {})[column] = decoded
                if column not in self._columns:
                    self._columns.append(column)
                    log.debug("column %r first seen while resuming %s", column, target)
            log.debug(
                "rehydrated %d record(s) and %d column(s) from %s",
                len(self._rows),
                len(self._columns),
                target,
            )


class ArrowPlasmaPersistor(_InMemoryPersistor):
    """Arrow/Parquet backend.  ``pyarrow`` is imported only when used."""

    def persist(self, path: Optional[Any] = None) -> None:
        target = self._resolve(path)
        if target is None:
            log.warning("persist() called on %s with no path", type(self).__name__)
            raise ValueError("no path configured for persist()")
        import pyarrow as pa  # lazy
        import pyarrow.parquet as pq  # lazy

        target.parent.mkdir(parents=True, exist_ok=True)
        frame = self._frame()
        pq.write_table(pa.Table.from_pandas(frame, preserve_index=False), str(target))
        log.debug("wrote a %s parquet table to %s", frame.shape, target)

    def resume(self, path: Optional[Any] = None) -> None:
        target = self._resolve(path)
        if target is None or not target.exists():
            log.debug("nothing to resume: parquet target %s is unset or missing", target)
            return
        import pyarrow.parquet as pq  # lazy

        frame = pq.read_table(str(target)).to_pandas()
        log.debug("read a %s parquet table from %s", frame.shape, target)
        with self._lock:
            self._rows = {}
            self._columns = list(frame.columns)
            log.debug("reset store to %d column(s) from %s", len(self._columns), target)
            for _, row in frame.iterrows():
                record_id = uuid.uuid4().hex
                self._rows[record_id] = {column: row[column] for column in frame.columns}
                log.debug(
                    "rehydrated anonymous record %s covering %d column(s)",
                    record_id,
                    len(frame.columns),
                )
