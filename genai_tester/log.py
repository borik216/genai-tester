from __future__ import annotations

import asyncio
import dataclasses
import json
import sys
from pathlib import Path
from types import TracebackType
from typing import IO

from genai_tester.models import LogRecord


class AsyncJSONLWriter:
    def __init__(self, path: str | None) -> None:
        self._path = Path(path) if path else None
        self._lock = asyncio.Lock()
        self._file: IO[str] | None = None

    async def __aenter__(self) -> AsyncJSONLWriter:
        if self._path:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._file = self._path.open("a", encoding="utf-8")
        else:
            self._file = sys.stdout
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        if self._path and self._file:
            self._file.close()
        self._file = None

    async def write(self, record: LogRecord) -> None:
        line = json.dumps(dataclasses.asdict(record), default=str) + "\n"
        async with self._lock:
            assert self._file is not None
            self._file.write(line)
            self._file.flush()
