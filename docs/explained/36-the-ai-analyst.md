# 36 — The AI Analyst (Plain-English Guide)

> Purpose: explain what the AI analyst does, how it avoids making things up, and what happens to
> the case material it reads. Useful for questions like:
> * "can I trust what the AI says?"
> * "where does my case go when I use it?"
> * "what stops it from profiling the wrong person, or a child?"

## 1. Why this matters

A case grows quickly: notes, people, links, dozens of captured pages and documents. Reading it all
again to decide what to do next takes hours. The AI analyst reads the whole case in minutes and
does three jobs:

| Job | What you get |
|---|---|
| **Brief me** | what the case shows so far, the key findings with their sources and confidence, the gaps, the **next steps** (what to do, why, and how), and cautions |
| **Find names & dates** | the people, organisations, accounts, emails, phone numbers, websites, addresses, places, vehicles, documents and crypto wallets named in the evidence, and the dated events, each with the exact words it came from |
| **Draft a report** | a first draft in sections (summary, findings, timeline, people, limitations, method), citing its sources, for you to edit |

It is built on **Claude**, made by Anthropic.

## 2. What it reads

* The case: its title, purpose and summary, your notes, the entities and the links between them,
  the events, and the scans you linked.
* The evidence: the text of every captured web page, and files you added that contain text (plain
  text, CSV, JSON, e-mails, PDFs). Photos and other files can't be read as text; the dialog lists
  them.
* There is a size limit: up to 60,000 characters from one document, and 400,000 in one request
  (about 100 pages of dense text; adjustable with `ARGUS_ANALYST_MAX_CHARS`). Nothing is cut
  silently: the dialog names any document that was shortened or left out, and the analyst is told
  too.

## 3. Not making things up

AI can sound sure of things that aren't true. The analyst is built so you can check every claim:

* **Every piece of material is labelled.** Notes are `[N1]`, `[N2]`…, entities `[P1]`…, events
  `[T1]`…, documents `[D1]`…. The analyst must cite these labels for every fact.
* **Argus checks its citations.** A finding that cites a label that doesn't exist loses that
  citation and is marked *no source*. A report draft that cites a missing label gets a warning
  above it.
* **Every extracted name and date is checked.** The analyst must copy the exact words it found it
  in. Argus then looks for those words in the cited document. When they are there, the suggestion
  is marked **checked**. When they aren't, it is marked **unverified**, left unticked, and needs
  checking by hand.
* **Nothing is added for you.** Suggestions are a list you review. Only the ones you tick are added,
  each noting where it was found and the words it came from.
* **Fact and inference are kept apart.** The analyst is told to say "the material shows" for facts
  and "possibly" for its own inferences, and to rate each finding as confirmed, likely or possible.
* **A similar name is not the same person.** The analyst is told to point out identities that are
  assumed rather than shown.

## 4. Safety

* **Children are never profiled.** The analyst is told not to describe or extract anyone who seems
  to be under 18. Anyone it marks as a possible child is removed before you see the list; the page
  says how many were left out.
* **Evidence can't give it orders.** A captured page might contain text written to trick an AI
  ("ignore your instructions…"). The analyst is told that the material is only evidence and never to
  follow instructions inside it. Its answers are also checked as above, whatever it was told.
* **Only lawful steps.** It suggests public records, registers, archives, corroboration and asking
  people for comment, never hacking, deception, harassment or contact that could put anyone at risk.
* **No speculation about sensitive traits** (health, sexuality, religion, ethnicity, politics)
  unless the investigation is about that and the material says it.

## 5. Where the case material goes

The case material is sent to **Anthropic** to be analysed. Argus never sends it unless you say so:

* **Every request asks first.** The dialog says how much is being sent, from how many sources,
  which documents, and what it costs. Anonymous cases get a stronger warning: what you know about
  the subjects will leave the computer.
* **The chain of custody records it.** Each document sent gets a "sent for AI analysis" entry in
  its custody log, saying which job and which route. A court or editor can see exactly which
  evidence went where.
* **The audit log records the request** (which job, how much, which route), never the content.

There are two ways to reach the analyst:

| Route | How | Cost | Who sees the material |
|---|---|---|---|
| **Your own Claude key** | `ARGUS_ANTHROPIC_API_KEY` | billed by Anthropic | Anthropic only |
| **Argus Connect** | Argus Personal, signed in to an Argus account | **Argus credits**: brief and extract 10, report 20, plus 2 for every 50,000 characters beyond the first 50,000 | passes through the Argus account service, which keeps none of it, on to Anthropic |

With Argus Connect, credits are taken before the request and **refunded** if it fails or the AI
declines. The ledger records only the job ("ai/brief"), never the case.

## 6. How it works underneath

* Argus uses the newest **Claude Opus** model your key can use (or the one set in
  `ARGUS_ANALYST_MODEL`), with Claude's adaptive thinking, at the effort set in
  `ARGUS_ANALYST_EFFORT` (default `high`).
* Briefings and extractions come back as **structured data** in a fixed shape, so Argus can check
  them field by field. Reports come back as Markdown.
* Answers are streamed, so a long report doesn't time out.
* If the model declines a request on safety grounds, Anthropic's service can hand it to another
  model automatically. If every model declines, Argus says so and (with Argus Connect) refunds the
  credits.

## 7. What a reviewer can check

* `argus/intel/analyst.py`:
  * how the case becomes labelled material (`build_material`);
  * the instructions the analyst is given (`SYSTEM`, `TASK_PROMPTS`);
  * the Claude request (`run_task`);
  * the checks on its answers (`check`, `quoted`).
* `argus/api/analyst_routes.py`: the confirmation, the preview, the custody and audit records.
* `argus/api/connect_routes.py` (`connect_ai`) and `argus/accounts/connect_client.py` (`ai`): Argus
  Connect and credits.
* `argus/web/js/views/analyst.js`: the AI analyst tab.
* `tests/test_analyst.py`:
  * labelled material, and documents shortened or left out;
  * reading PDFs and text files;
  * quotes checked against sources, and possible children removed;
  * citations that don't exist being dropped;
  * the Claude request's shape;
  * refusals and broken answers;
  * the confirmation, chosen documents, custody entries, and the audit log never holding content;
  * Argus Connect charging, refunds and the ledger.
