# 56 — Backups and Alerts (Plain-English Guide)

> Purpose: explain how investigators keep their cases safe, and how Argus tells you (the
> owner) when something needs attention. Useful for questions like:
> * "what happens if an investigator's laptop is stolen or breaks?"
> * "how do I find out if payments or email stop working?"

## 1. Backups for investigators (Argus Personal)

Argus Personal keeps cases on the investigator's own computer. That's private, but a lost,
stolen or broken computer would mean lost cases. Backups fix that.

**Setting up** (Settings → Backups, once):

1. Choose a **folder**. Best is a folder that syncs to the cloud (OneDrive, iCloud Drive,
   Dropbox, Google Drive: Argus offers the ones it finds) or an external drive. It must be
   outside Argus's own data folder.
2. Choose a **backup password** (at least 10 characters) and keep it somewhere safe, like a
   password manager.
3. Choose how often (every 6 or 12 hours, daily or weekly) and how many to keep.

From then on Argus backs up on its own and removes the oldest beyond the number to keep.
*Back up now* makes one straight away.

**What's in a backup**: everything. Cases, evidence and its files, custody records,
settings, the audit log, and the computer's encryption key, all in one `.argusbackup` file.

**Why a cloud folder is safe**: the file is encrypted with the backup password (AES-256,
with the password strengthened by scrypt). Without the password it's unreadable, to anyone,
including the cloud provider and us. Nothing unencrypted is ever written to the backup folder.
The password itself is never stored, only a key made from it, which lets backups run
unattended. Restoring always asks for the password.

**Checking**: *Check it* opens a backup with its password and verifies every file's
fingerprint, without changing anything. It's worth doing now and then.

**Restoring** (a new computer, or going back):

1. Install Argus and sign in.
2. Settings → Backups → *Check or restore a backup*: the backup file's full path, and its
   password → *Restore it*.
3. Argus restarts with the restored data. What was there before isn't deleted: it's kept in a
   `before-restore-<date>` folder in Argus's data folder.

A backup made by a newer Argus can't be restored into an older one: update first.

**Reminders**: if backups fail (a USB drive unplugged, a full disk), Argus says so when the
investigator signs in, and tries again within the hour. If they're off, a gentle reminder
appears at most once a week.

**Even when a subscription has lapsed**, backups, checks and restores keep working.

## 2. Backups for a server

* **On PostgreSQL** (the recommended production setup): backups are your database provider's.
  Make sure they're on, with point-in-time recovery. The owner console's health shows a
  reminder.
* **On SQLite** (a small single server): set `ARGUS_BACKUP_DIR` and `ARGUS_BACKUP_PASSWORD`
  (and optionally `ARGUS_BACKUP_EVERY_HOURS`, default 24, and `ARGUS_BACKUP_KEEP`, default 14).
  By hand:

  ```bash
  argus --backup-to /mnt/backups
  argus --backup-check /mnt/backups/argus-backup-2026-11-20-090000.argusbackup
  argus --backup-restore /mnt/backups/argus-backup-2026-11-20-090000.argusbackup
  ```

  The password comes from `ARGUS_BACKUP_PASSWORD`, or is asked for. A restore takes over at
  the next start.

## 3. Alerts for you (the owner)

Every few minutes Argus checks itself, the same checks as the owner console's overview, and
emails you:

* **When something breaks**: the database, payments or the Stripe webhook, email, backups,
  disk space, background work. One email lists everything that broke and what to do about it.
  While it stays broken, there's a reminder once a day. When it's fixed, a short "Fixed" email.
  Warnings (things to look at, not broken) stay in the console.
* **Payments**: a dispute opened or lost, a failed payment (once per customer every few days).
* **New paying customers** (each one).
* **A daily summary** (off by default): new accounts, payments, credit packs, refunds,
  disputes, and the server's health, at the hour you choose.

Owner console → **Alerts**: switch each kind on or off, send alerts to another address,
send a test alert, and see the latest alerts sent. Alerts go through the mail server set up
under Email. With several servers, only one sends each alert.

Health also has two new checks: **Backups** and **Disk space** (a problem below 1 GB or 3%
free, a warning below 5 GB or 10%).
