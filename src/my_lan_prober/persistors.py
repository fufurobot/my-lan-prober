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
import pickle
import sqlite3
import threading
import uuid
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List, Optional

import pandas as pd

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

    # -- schema --------------------------------------------------------
    def register(self, column_name: str) -> None:
        """Declare a column so it appears even if a row omits it."""
        if column_name not in self._columns:
            self._columns.append(column_name)

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
            self.resume()
        with self._lock:
            row = self._rows.get(str(id))
        return dict(row) if row is not None else None

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
        return target

    def _frame(self) -> pd.DataFrame:
        with self._lock:
            rows = [dict(row) for row in self._rows.values()]
            columns = list(self._columns)
        for row in rows:
            for key in row:
                if key not in columns:
                    columns.append(key)
        return pd.DataFrame(rows, columns=columns)


class _InMemoryPersistor(Persistor):
    """Shared implementation: rows live in a dict keyed by record id."""

    def store(self, column: str, data: Any, previous_id: Optional[str] = None) -> str:
        self.register(column)
        with self._lock:
            record_id = str(previous_id) if previous_id is not None else uuid.uuid4().hex
            self._rows.setdefault(record_id, {})[column] = data
        return record_id

    def history(self) -> pd.DataFrame:
        return self._frame()


class PicklePersistor(_InMemoryPersistor):
    """Whole-history pickle dump."""

    def __init__(self, path: Optional[Any] = None) -> None:
        super().__init__(path)
        if self.path is not None and self.path.exists():
            self.resume()

    def persist(self, path: Optional[Any] = None) -> None:
        target = self._resolve(path)
        if target is None:
            raise ValueError("no path configured for persist()")
        target.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            payload = {"columns": list(self._columns), "rows": dict(self._rows)}
        with open(target, "wb") as handle:
            pickle.dump(payload, handle)

    def resume(self, path: Optional[Any] = None) -> None:
        target = self._resolve(path)
        if target is None or not target.exists():
            return
        with open(target, "rb") as handle:
            payload = pickle.load(handle)
        with self._lock:
            self._columns = list(payload.get("columns", []))
            self._rows = dict(payload.get("rows", {}))


class JSONLPersistor(_InMemoryPersistor):
    """One JSON object per record, appended as it is stored."""

    def __init__(self, path: Optional[Any] = None) -> None:
        super().__init__(path)
        if self.path is not None and self.path.exists():
            self.resume()

    def store(self, column: str, data: Any, previous_id: Optional[str] = None) -> str:
        record_id = super().store(column, data, previous_id=previous_id)
        if previous_id is None:
            # A brand-new record starts a new line.
            self._append_line({"id": record_id})
        return record_id

    def _append_line(self, payload: Dict[str, Any]) -> None:
        if self.path is None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, default=str) + "\n")

    def persist(self, path: Optional[Any] = None) -> None:
        """Rewrite the whole log so it matches the current in-memory state."""
        target = self._resolve(path)
        if target is None:
            raise ValueError("no path configured for persist()")
        target.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            rows = {str(k): dict(v) for k, v in self._rows.items()}
        with open(target, "w", encoding="utf-8") as handle:
            for record_id, row in rows.items():
                handle.write(json.dumps({"id": record_id, **row}, default=str) + "\n")

    def resume(self, path: Optional[Any] = None) -> None:
        target = self._resolve(path)
        if target is None or not target.exists():
            return
        with self._lock:
            self._rows = {}
            self._columns = []
        with open(target, encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                record = json.loads(line)
                record_id = str(record.pop("id", uuid.uuid4().hex))
                with self._lock:
                    self._rows[record_id] = record
                    for key in record:
                        if key not in self._columns:
                            self._columns.append(key)

    def history(self) -> pd.DataFrame:
        if self.path is not None and self.path.exists() and not self._rows:
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
            self._ensure_schema()
            if self.path.exists():
                self.resume()

    def _connect(self) -> sqlite3.Connection:
        assert self.path is not None
        self.path.parent.mkdir(parents=True, exist_ok=True)
        return sqlite3.connect(str(self.path))

    def _ensure_schema(self) -> None:
        with self._connect() as conn:
            conn.execute(self._SCHEMA)

    def store(self, column: str, data: Any, previous_id: Optional[str] = None) -> str:
        record_id = super().store(column, data, previous_id=previous_id)
        if self.path is not None:
            self._ensure_schema()
            with self._connect() as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO records VALUES (?, ?, ?)",
                    (record_id, column, json.dumps(data, default=str)),
                )
        return record_id

    def persist(self, path: Optional[Any] = None) -> None:
        target = self._resolve(path)
        if target is None:
            raise ValueError("no path configured for persist()")
        self._ensure_schema()
        with self._lock:
            rows = {str(k): dict(v) for k, v in self._rows.items()}
        with self._connect() as conn:
            conn.execute("DELETE FROM records")
            for record_id, row in rows.items():
                for column, value in row.items():
                    conn.execute(
                        "INSERT OR REPLACE INTO records VALUES (?, ?, ?)",
                        (record_id, column, json.dumps(value, default=str)),
                    )

    def resume(self, path: Optional[Any] = None) -> None:
        target = self._resolve(path)
        if target is None or not target.exists():
            return
        self._ensure_schema()
        with self._connect() as conn:
            cursor = conn.execute("SELECT record_id, column_name, value FROM records")
            fetched = cursor.fetchall()
        with self._lock:
            self._rows = {}
            self._columns = []
            for record_id, column, value in fetched:
                try:
                    decoded = json.loads(value)
                except (TypeError, ValueError):
                    decoded = value
                self._rows.setdefault(str(record_id), {})[column] = decoded
                if column not in self._columns:
                    self._columns.append(column)


class ArrowPlasmaPersistor(_InMemoryPersistor):
    """Arrow/Parquet backend.  ``pyarrow`` is imported only when used."""

    def persist(self, path: Optional[Any] = None) -> None:
        target = self._resolve(path)
        if target is None:
            raise ValueError("no path configured for persist()")
        import pyarrow as pa  # lazy
        import pyarrow.parquet as pq  # lazy

        target.parent.mkdir(parents=True, exist_ok=True)
        frame = self._frame()
        pq.write_table(pa.Table.from_pandas(frame, preserve_index=False), str(target))

    def resume(self, path: Optional[Any] = None) -> None:
        target = self._resolve(path)
        if target is None or not target.exists():
            return
        import pyarrow.parquet as pq  # lazy

        frame = pq.read_table(str(target)).to_pandas()
        with self._lock:
            self._rows = {}
            self._columns = list(frame.columns)
            for _, row in frame.iterrows():
                record_id = uuid.uuid4().hex
                self._rows[record_id] = {column: row[column] for column in frame.columns}
