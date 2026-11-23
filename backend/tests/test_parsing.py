"""Ingestion parsing helpers (regression tests for CSV/JSON quote handling)."""
from datetime import datetime

import pandas as pd
import pytest

from backend.src.ingestion.base import IngestionBase


@pytest.fixture
def parser():
    return IngestionBase(session=None)


def test_json_with_empty_string_value_survives(parser):
    # pandas has already removed CSV escaping; un-escaping again used to turn
    # '""' into '"' and silently drop the whole value.
    assert parser._parse_json_col('{"a": 1, "note": ""}') == {"a": 1, "note": ""}


def test_json_still_accepts_csv_escaped_values(parser):
    assert parser._parse_json_col('"{""a"": 1}"') == {"a": 1}


@pytest.mark.parametrize("empty", [None, "", "null", float("nan")])
def test_json_empty_values_are_none(parser, empty):
    assert parser._parse_json_col(empty) is None


def test_json_invalid_is_none(parser):
    assert parser._parse_json_col("{not json") is None


def test_csv_reader_roundtrip_keeps_empty_strings(parser, tmp_path):
    csv = tmp_path / "dailysleep.csv"
    csv.write_text('id;contributors\n1;"{""deep"":80,""note"":""""}"\n', encoding="utf-8")
    df = parser._read_csv_robust(str(csv))
    assert parser._parse_json_col(df["contributors"][0]) == {"deep": 80, "note": ""}


START = datetime(2026, 1, 1)


def test_sequence_json_items_with_empty_string(parser):
    out = parser._parse_sequence_to_timestamped_list(
        '{"items": [60, 61], "label": ""}', START, 300
    )
    assert [p["value"] for p in out] == [60, 61]
    assert out[1]["timestamp"] == (START + pd.Timedelta(seconds=300)).isoformat()


def test_sequence_csv_escaped_json(parser):
    out = parser._parse_sequence_to_timestamped_list('"{""items"": [1, 2]}"', START, 60)
    assert [p["value"] for p in out] == [1, 2]


def test_sequence_hypnogram_digit_string(parser):
    out = parser._parse_sequence_to_timestamped_list("4422", START, 300)
    assert [p["value"] for p in out] == [4, 4, 2, 2]


def test_sequence_comma_separated(parser):
    out = parser._parse_sequence_to_timestamped_list("[1.5, 2.5]", START, 60)
    assert [p["value"] for p in out] == [1.5, 2.5]
