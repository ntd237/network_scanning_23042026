from __future__ import annotations

import traceback
from typing import Any, Callable

from PyQt5.QtCore import QObject, QRunnable, pyqtSignal


class WorkerSignals(QObject):
    finished = pyqtSignal()
    error = pyqtSignal(str)
    result = pyqtSignal(object)
    progress = pyqtSignal(object)


class BackgroundTask(QRunnable):
    def __init__(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> None:
        super().__init__()
        self.fn = fn
        self.args = args
        self.kwargs = kwargs
        self.signals = WorkerSignals()

    def run(self) -> None:
        try:
            result = self.fn(*self.args, progress_callback=self.signals.progress.emit, **self.kwargs)
        except TypeError:
            try:
                result = self.fn(*self.args, **self.kwargs)
            except Exception as exc:  # pragma: no cover - UI safety net
                self.signals.error.emit(f"{exc}\n{traceback.format_exc()}")
                self.signals.finished.emit()
                return
        except Exception as exc:  # pragma: no cover - UI safety net
            self.signals.error.emit(f"{exc}\n{traceback.format_exc()}")
            self.signals.finished.emit()
            return
        self.signals.result.emit(result)
        self.signals.finished.emit()
