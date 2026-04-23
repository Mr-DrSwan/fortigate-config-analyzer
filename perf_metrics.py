import json
import time
from pathlib import Path
from typing import Dict, Optional


class PerfRecorder:
    def __init__(self, target_file: Path) -> None:
        self.target_file = target_file
        self.target_file.parent.mkdir(parents=True, exist_ok=True)

    def record(self, metric: str, elapsed_ms: float, extra: Optional[Dict[str, object]] = None) -> None:
        payload: Dict[str, object] = {
            "ts": time.time(),
            "metric": metric,
            "elapsed_ms": round(elapsed_ms, 3),
        }
        if extra:
            payload.update(extra)
        with self.target_file.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=False) + "\n")
