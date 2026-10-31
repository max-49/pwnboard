from datetime import datetime, timedelta, timezone

from pwnmarket.config import Config


def end(monkeypatch, value):
    monkeypatch.setenv("COMPETITION_END", value)
    return Config.from_env().competition_end


def test_end_time_without_an_offset_is_eastern_not_utc(monkeypatch):
    got = end(monkeypatch, "2026-10-31T15:30:00")
    assert got == datetime(2026, 10, 31, 15, 30, tzinfo=timezone(timedelta(hours=-4)))
    assert got == datetime(2026, 10, 31, 19, 30, tzinfo=timezone.utc)


def test_end_time_with_an_offset_is_kept(monkeypatch):
    assert end(monkeypatch, " 2026-10-31T15:30:00+00:00 ") == datetime(2026, 10, 31, 15, 30, tzinfo=timezone.utc)


def test_empty_end_time_means_none(monkeypatch):
    assert end(monkeypatch, "") is None
