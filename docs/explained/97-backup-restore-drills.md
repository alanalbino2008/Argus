# 97. Backup restore drills

The usual way backups fail is quietly: the files exist, but on the day they are needed one turns out
to be damaged, cut short, or made with a password nobody kept. The only proof a backup works is
restoring it. Argus now does that every week, without touching anything.

## What a drill does

1. Takes the **newest backup** in the backup folder.
2. Decrypts it into a scratch folder inside Argus's data folder, using the unattended backup key, so
   no password is typed (a backup made with a different password is reported as such).
3. Checks every file against its fingerprint (as **Check a backup** always did).
4. **Opens the restored database**: SQLite's integrity check, its foreign keys, its schema revision,
   and the number of cases, captures and investigations against what the backup recorded when it was
   made.
5. Deletes the scratch folder. Nothing is restored over the live data.

## When

* Every 7 days, once there is a backup, alongside the backup schedule.
* On demand: Settings → Backups → **Test a restore** (or `POST /api/backups/drill`).

The result shows under the backup's summary ("Restores", or "Restore failed" and why), is audited
(`backup.drill`), and is exported as `argus_backup_drill_ok` (1 or 0) and
`argus_backup_drill_last_success_timestamp_seconds`. The `ArgusBackupRestoreDrillFailed` alert is
critical: until a backup restores, a lost disk means lost cases.
