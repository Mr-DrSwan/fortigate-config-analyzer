import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from perf_metrics import PerfRecorder


def test_record_creates_file(tmp_path: Path) -> None:
    target = tmp_path / "metrics.jsonl"
    recorder = PerfRecorder(target)
    recorder.record("test_metric", 123.456)
    assert target.exists()


def test_record_writes_valid_json(tmp_path: Path) -> None:
    target = tmp_path / "metrics.jsonl"
    recorder = PerfRecorder(target)
    recorder.record("parse_all", 42.0)

    line = target.read_text(encoding="utf-8").strip()
    payload = json.loads(line)
    assert payload["metric"] == "parse_all"
    assert payload["elapsed_ms"] == 42.0
    assert "ts" in payload


def test_record_appends_multiple_entries(tmp_path: Path) -> None:
    target = tmp_path / "metrics.jsonl"
    recorder = PerfRecorder(target)
    recorder.record("step_1", 10.0)
    recorder.record("step_2", 20.0)
    recorder.record("step_3", 30.0)

    lines = [ln for ln in target.read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert len(lines) == 3
    metrics = [json.loads(ln)["metric"] for ln in lines]
    assert metrics == ["step_1", "step_2", "step_3"]


def test_record_includes_extra_fields(tmp_path: Path) -> None:
    target = tmp_path / "metrics.jsonl"
    recorder = PerfRecorder(target)
    recorder.record("load", 5.5, {"rows": 100, "device": "test-fw"})

    payload = json.loads(target.read_text(encoding="utf-8").strip())
    assert payload["rows"] == 100
    assert payload["device"] == "test-fw"


def test_record_creates_parent_directories(tmp_path: Path) -> None:
    target = tmp_path / "deep" / "nested" / "metrics.jsonl"
    recorder = PerfRecorder(target)
    recorder.record("init", 0.1)
    assert target.exists()


def test_record_elapsed_ms_is_rounded(tmp_path: Path) -> None:
    target = tmp_path / "metrics.jsonl"
    recorder = PerfRecorder(target)
    recorder.record("precise", 1.23456789)

    payload = json.loads(target.read_text(encoding="utf-8").strip())
    assert payload["elapsed_ms"] == round(1.23456789, 3)
