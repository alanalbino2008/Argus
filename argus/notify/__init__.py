"""Outbound notifications: tell people when something important changes.

Pipeline (see ``docs/explained/15-outbound-alerts.md``)::

    alert raised --(same transaction)--> outbox row per matching channel
                                           |
    every replica: claim due rows (lease) -> render -> send (SSRF-guarded, signed) -> record
"""
