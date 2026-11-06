"""What a machine costs the host right now: the CPU time and resident memory
of its QEMU process, read the way Task Manager reads them (stdlib only).

CPU is reported the way Hyper-V Manager does, as a percentage of the virtual
processors the machine was given: a 2-vCPU machine pegging both cores shows
100, not 200 and not 25 of an 8-core host.
"""

from __future__ import annotations

import ctypes
import os
import time
from dataclasses import dataclass
from pathlib import Path

PROCESS_QUERY_LIMITED_INFORMATION = 0x1000


@dataclass
class Sample:
    cpu_seconds: float   # user + system time the process has consumed so far
    rss_mb: int          # resident memory now
    at: float            # time.monotonic() when read


def sample(pid: int) -> Sample | None:
    """None when the process is gone or the platform gives no numbers."""
    if pid <= 0:
        return None
    try:
        if os.name == "nt":
            return _sample_windows(pid)
        return _sample_proc(pid)
    except (OSError, ValueError, IndexError, AttributeError):
        return None


def _sample_proc(pid: int) -> Sample | None:
    stat = Path(f"/proc/{pid}/stat").read_text()
    # The command name is in parentheses and may hold spaces; fields follow it.
    fields = stat[stat.rindex(")") + 2:].split()
    ticks = os.sysconf("SC_CLK_TCK")
    cpu = (int(fields[11]) + int(fields[12])) / ticks  # utime, stime
    rss_mb = 0
    for line in Path(f"/proc/{pid}/status").read_text().splitlines():
        if line.startswith("VmRSS:"):
            rss_mb = int(line.split()[1]) // 1024
            break
    return Sample(cpu_seconds=cpu, rss_mb=rss_mb, at=time.monotonic())


def _sample_windows(pid: int) -> Sample | None:
    k = ctypes.windll.kernel32
    handle = k.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return None
    try:
        class FileTime(ctypes.Structure):
            _fields_ = [("lo", ctypes.c_uint32), ("hi", ctypes.c_uint32)]

        class MemCounters(ctypes.Structure):
            _fields_ = [
                ("cb", ctypes.c_uint32), ("PageFaultCount", ctypes.c_uint32),
                ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        created, exited, kernel, user = FileTime(), FileTime(), FileTime(), FileTime()
        if not k.GetProcessTimes(handle, ctypes.byref(created), ctypes.byref(exited),
                                 ctypes.byref(kernel), ctypes.byref(user)):
            return None
        hundred_ns = ((kernel.hi << 32) + kernel.lo) + ((user.hi << 32) + user.lo)
        mem = MemCounters()
        mem.cb = ctypes.sizeof(mem)
        rss_mb = 0
        if k.K32GetProcessMemoryInfo(handle, ctypes.byref(mem), mem.cb):
            rss_mb = int(mem.WorkingSetSize // (1024 * 1024))
        return Sample(cpu_seconds=hundred_ns / 1e7, rss_mb=rss_mb, at=time.monotonic())
    finally:
        k.CloseHandle(handle)


@dataclass
class Usage:
    cpu_pct: int    # of the machine's own vCPUs, 0-100
    rss_mb: int


def cpu_percent(prev: Sample, cur: Sample, vcpus: int) -> int:
    wall = cur.at - prev.at
    if wall <= 0:
        return 0
    pct = (cur.cpu_seconds - prev.cpu_seconds) / wall / max(1, vcpus) * 100
    return max(0, min(100, int(round(pct))))


class Meter:
    """Remembers the last sample per process so the next call can report a
    rate. The first call for a process reports memory only (cpu 0)."""

    def __init__(self) -> None:
        self._last: dict[int, Sample] = {}

    def usage(self, pid: int, vcpus: int) -> Usage | None:
        cur = sample(pid)
        if cur is None:
            self._last.pop(pid, None)
            return None
        prev = self._last.get(pid)
        self._last[pid] = cur
        pct = cpu_percent(prev, cur, vcpus) if prev else 0
        return Usage(cpu_pct=pct, rss_mb=cur.rss_mb)
