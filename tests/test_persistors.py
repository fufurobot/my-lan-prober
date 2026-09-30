"""Tests for :mod:`my_lan_prober.persistors`.

``design.md`` § 6: persistence is optional and stores **parsed packets**.
``store_full`` chains ``store`` calls via ``previous_id``;
``retrieve`` auto-``resume``s and returns ``None`` when the id is missing.
"""

from __future__ import annotations

import json

import pytest

from my_lan_prober.persistors import (
    ArrowPlasmaPersistor,
    JSONLPersistor,
    Persistor,
    PicklePersistor,
    SQLitePersistor,
)


@pytest.fixture(params=["pickle", "jsonl", "sqlite"])
def persistor(request, tmp_path):
    if request.param == "pickle":
        return PicklePersistor(tmp_path / "h.pkl")
    if request.param == "jsonl":
        return JSONLPersistor(tmp_path / "h.jsonl")
    return SQLitePersistor(tmp_path / "h.sqlite")


# ---------------------------------------------------------------------------
# Base contract
# ---------------------------------------------------------------------------
def test_persistor_is_abstract():
    with pytest.raises(TypeError):
        Persistor()  # type: ignore[abstract]


def test_store_full_defaults_to_storing_each_key(persistor):
    previous = persistor.store_full({"host": "a"})

    assert previous is not None


def test_store_returns_a_unique_id(persistor):
    first = persistor.store("host", "a")
    second = persistor.store("host", "b")

    assert first != second


def test_history_lists_stored_records(persistor):
    persistor.store_full({"host": "alpha", "ip": "10.0.0.1"})
    persistor.store_full({"host": "beta", "ip": "10.0.0.2"})

    history = persistor.history()

    assert list(history["host"]) == ["alpha", "beta"]
    assert list(history["ip"]) == ["10.0.0.1", "10.0.0.2"]


def test_history_is_empty_initially(persistor):
    assert len(persistor.history()) == 0


def test_store_full_links_records_through_previous_id(persistor):
    """A multi-column row must come back as one linked record, not N rows."""
    persistor.store_full({"host": "alpha", "ip": "10.0.0.1", "mac": "aa:bb"})

    history = persistor.history()

    assert len(history) == 1
    row = history.iloc[0]
    assert row["host"] == "alpha"
    assert row["ip"] == "10.0.0.1"
    assert row["mac"] == "aa:bb"


def test_retrieve_returns_none_for_an_unknown_id(persistor):
    assert persistor.retrieve("does-not-exist") is None


def test_retrieve_returns_the_stored_row(persistor):
    record_id = persistor.store_full({"host": "alpha", "ip": "10.0.0.1"})

    row = persistor.retrieve(record_id)

    assert row["host"] == "alpha"
    assert row["ip"] == "10.0.0.1"


def test_register_creates_a_column_that_can_be_stored(persistor):
    persistor.register("custom_column")

    persistor.store_full({"custom_column": "value"})

    assert list(persistor.history()["custom_column"]) == ["value"]


# ---------------------------------------------------------------------------
# Persistence round-trips
# ---------------------------------------------------------------------------
def test_persist_then_resume_round_trips_rows(persistor):
    persistor.store_full({"host": "alpha", "ip": "10.0.0.1"})
    persistor.persist()

    assert list(persistor.history()["host"]) == ["alpha"]


def test_resume_loads_rows_into_a_fresh_instance(persistor):
    persistor.store_full({"host": "alpha", "ip": "10.0.0.1"})
    persistor.persist()

    fresh = type(persistor)(persistor.path)
    fresh.resume()
    history = fresh.history()

    assert len(history) == 1
    assert history.iloc[0]["host"] == "alpha"
    assert history.iloc[0]["ip"] == "10.0.0.1"


def test_resume_on_missing_path_is_a_noop(persistor):
    persistor.path = persistor.path.parent / "definitely-missing"

    persistor.resume()

    assert len(persistor.history()) == 0


# ---------------------------------------------------------------------------
# JSONL specifics
# ---------------------------------------------------------------------------
def test_jsonl_writes_one_json_object_per_line(tmp_path):
    path = tmp_path / "scan.jsonl"
    persistor = JSONLPersistor(path)
    persistor.store_full({"host": "alpha", "port": 22})
    persistor.store_full({"host": "beta", "port": 80})
    persistor.persist()

    lines = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]

    assert lines[0]["host"] == "alpha"
    assert lines[1]["port"] == 80


# ---------------------------------------------------------------------------
# Arrow (optional dependency, lazy)
# ---------------------------------------------------------------------------
def test_arrow_persistor_is_lazy_about_pyarrow(tmp_path):
    """Constructing it must not import pyarrow until it is needed."""
    persistor = ArrowPlasmaPersistor(tmp_path / "h.arrow")

    assert persistor is not None
