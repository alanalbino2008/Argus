# 41 — The Case Vault (Plain-English Guide)

> Purpose: explain how Argus Personal protects an investigator's cases if their computer is lost,
> stolen or seized. Useful for questions like:
> * "if my laptop is taken at a border, can they read my sources?"
> * "what happens if I forget my passphrase?"
> * "what exactly is encrypted, and what isn't?"

## 1. Why this matters

An investigator's cases hold the most sensitive things they have: who they're investigating,
what they've found, and often who told them. On Argus Personal, all of that lives in one file on
their laptop. Without protection, anyone who copies that file can read every case.

With the **case vault** turned on, the sensitive parts of that file are encrypted, and the key
that opens them exists only in the computer's memory, only while the vault is unlocked.

## 2. Using it

* **Turn it on** in Settings → Case vault:
  1. choose a passphrase of at least 12 characters (a short sentence works well);
  2. Argus encrypts everything;
  3. Argus shows a **recovery code** once. Write it down and keep it away from the computer.
* **Locking.** The vault locks itself after 15 minutes without activity (never in the middle of
  a scan or playbook), when Argus restarts, or when you press the lock button in the top bar.
* **Unlocking.** While locked, Argus shows only an unlock screen. Enter the passphrase, or the
  recovery code if you've forgotten it.
* **Changing the passphrase** takes a moment: the data doesn't need re-encrypting.
* **A new recovery code** can be issued at any time; the old one stops working.
* **Turning it off** decrypts everything again.

## 3. If you forget the passphrase

Use the recovery code. **If both are lost, nobody can recover the cases**: not you, not Argus's
makers, not anyone else. That is what makes the vault worth having. Argus asks you to confirm you
understand this before turning it on.

## 4. How it works

* A random **data key** (256 bits) encrypts the data, with AES-256-GCM, the standard used by
  banks and governments. Every value gets its own random starting point (a *nonce*), and is
  bound to its place in the database, so encrypted values can't be moved around to confuse
  Argus.
* The data key is stored only **locked inside** two "envelopes":
  * one opened by your passphrase, through **scrypt**, a method designed to make guessing
    passphrases slow and expensive (each guess needs 128 MB of memory and about half a second);
  * one opened by the recovery code.
* **Unlocking** opens an envelope and keeps the data key in memory. **Locking** drops it.
* **Guessing is limited.** Unlock attempts are rate-limited. Failed attempts are written to the
  audit log at the next successful unlock (the audit log is itself encrypted, so it can't be
  written while locked).

## 5. What is encrypted

When the vault is on:

* **cases**: titles, purposes and summaries;
* **case contents**: notes, people and other entities, links, events;
* **evidence**: page addresses, titles, notes, manifests, the files themselves (screenshots,
  documents, captured pages), and chain-of-custody details;
* **watched accounts**: their profiles and history;
* **playbook runs**;
* **scans**: their targets and everything they found;
* **audit log details**, alerts, monitors, reports and their files, and queued notifications.

What stays readable: identifiers, dates, statuses, counts and kinds of things, so Argus can
still find and order them. Also readable are a watched account's platform and handle, needed to
avoid watching the same account twice; the account's profile itself is encrypted.

## 6. No readable leftovers

Databases don't always erase old data straight away. When a value changes, the old version can
sit in free space inside the file, or in a log file next to it. So the vault:

* **zeroes** deleted and overwritten data;
* **rebuilds** the database file after encrypting or decrypting everything;
* **empties** its log file.

A test proves it. It fills a case, turns the vault on, then reads the raw database files byte by
byte, as a thief would, and checks that none of the case's words appear anywhere.

## 7. What the vault can't do

* **While unlocked**, the cases are readable to anyone using the computer. Lock it when you step
  away; it also locks itself.
* **Old copies elsewhere.** Data written before the vault was turned on may still exist in places
  the vault can't reach: backups, or blocks an SSD has set aside internally. For the strongest
  protection, also turn on your computer's disk encryption (FileVault on a Mac, BitLocker on
  Windows, LUKS on Linux).
* **Shared database servers.** The vault is for one computer's own database (Argus Personal).
  Shared database servers (PostgreSQL) should use their own encryption at rest.

## 8. What a reviewer can check

* `argus/security/vault.py`:
  * key creation and wrapping (`create`, `open_with`);
  * the encrypted column types;
  * the recovery code.
* `argus/storage/vault_store.py`:
  * turning the vault on and off;
  * resuming an interrupted pass;
  * the file clean-up (`_compact`).
* `argus/storage/db.py`: which columns are encrypted.
* `argus/api/vault_routes.py`: the API, the `423 Locked` gate, and the limits on unlock attempts.
* `argus/api/server.py`: start-up recovery waiting for the unlock, background jobs pausing, and
  auto-lock.
* `argus/web/js/vault.js` and the Settings card: the unlock screen and controls.
* `tests/test_vault.py`:
  * every sensitive table covered;
  * keys wrapped, and recovery codes accepted however they're typed;
  * the raw files unreadable;
  * everything still working when unlocked;
  * 423 when locked;
  * wrong passphrases refused;
  * the recovery code working;
  * a restart locking it again;
  * passphrase changes;
  * turning it off;
  * an interrupted pass finishing;
  * locking waiting for running work;
  * values bound to their column.
