"""
thread_safe_queue.py
Thread-safe bounded queue for passing packets between threads.
Equivalent to include/thread_safe_queue.h
"""

from __future__ import annotations

import queue
import threading
from typing import Generic, Optional, TypeVar

T = TypeVar('T')


class ThreadSafeQueue(Generic[T]):
    """
    Bounded, thread-safe queue with blocking push/pop and shutdown support.
    Mirrors the C++ TSQueue / ThreadSafeQueue template.
    """

    def __init__(self, max_size: int = 10000):
        self._queue: queue.Queue = queue.Queue(maxsize=max_size)
        self._shutdown: bool = False
        self._lock = threading.Lock()
        self._not_empty = threading.Condition(self._lock)
        self._not_full  = threading.Condition(self._lock)

    # ------------------------------------------------------------------ #
    def push(self, item: T) -> None:
        """Blocking push – waits if queue is full (unless shutdown)."""
        while True:
            with self._lock:
                if self._shutdown:
                    return
                if not self._queue.full():
                    self._queue.put_nowait(item)
                    return
            # Queue is full – yield and retry
            import time
            time.sleep(0.0005)

    def try_push(self, item: T) -> bool:
        """Non-blocking push. Returns False if full or shutdown."""
        with self._lock:
            if self._shutdown or self._queue.full():
                return False
            self._queue.put_nowait(item)
            return True

    # ------------------------------------------------------------------ #
    def pop(self, timeout_ms: int = 100) -> Optional[T]:
        """
        Blocking pop with timeout.
        Returns None on timeout or shutdown.
        """
        try:
            return self._queue.get(timeout=timeout_ms / 1000.0)
        except queue.Empty:
            return None

    def pop_with_timeout(self, timeout_ms: float) -> Optional[T]:
        """Same as pop() but accepts a float millisecond timeout."""
        try:
            return self._queue.get(timeout=timeout_ms / 1000.0)
        except queue.Empty:
            return None

    # ------------------------------------------------------------------ #
    def empty(self) -> bool:
        return self._queue.empty()

    def size(self) -> int:
        return self._queue.qsize()

    def shutdown(self) -> None:
        with self._lock:
            self._shutdown = True

    def is_shutdown(self) -> bool:
        with self._lock:
            return self._shutdown
