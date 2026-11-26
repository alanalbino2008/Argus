# 113. A person's timeline, the people around them, and an AI dossier

Three views on the person's card in the People tab, each opened when you need it.

## Timeline of their online life

Built from **confirmed** findings (tick *Include candidates not yet confirmed* to add the open ones):

* when accounts were created, and first and last archived (deleted accounts included);
* when an account showed another name ("Shown as "Jane Doe" (was "Jane Smith")");
* their Telegram channel's latest post;
* when documents were created, the dates of insolvency notices and court cases, and years of birth
  given by records.

Above it, **contradictions** between confirmed findings and what is known: different towns,
different years of birth (more than a year apart), time zones three or more hours apart. A
contradiction means one finding is wrong, or one of them is not this person.

`GET /api/cases/{case}/subjects/{id}/timeline?include_open=false`

## Other people connected

People linked to the person through **confirmed** findings:

* co-authors, from their OpenAlex record (the people they published with most);
* fellow officers of companies a confirmed register record links them to;
* accounts their Telegram channel mentions.

They are listed with how they are connected and through which finding. They are never searched:
they are not the subject of the research. Look into one only with its own legitimate purpose, as a
separate person.

`GET /api/cases/{case}/subjects/{id}/associates`

## AI dossier

The AI analyst (your own Claude key, or Argus Connect credits: 10) writes a dossier on the person:

* a summary;
* what is **established** (known details and confirmed findings);
* what is **likely** (open candidates);
* the **conflicts**;
* the gaps and next steps.

Every line cites the material it rests on: known details [K], confirmed findings [C], open candidates
[P], timeline entries [T].

Before it is shown, Argus checks it:

* references that do not exist are dropped, and a line with none left is marked *no source given*;
* a line presented as established that rests only on open candidates is downgraded to *possible*.

What is sent: the known details, the confirmed findings with their reasons, the 30 best open
candidates, the timeline and any contradictions. Ruled-out candidates and the other people connected
are only counted, never named. You must confirm sending the person's material to Anthropic each time,
and an anonymous case warns that it includes what you know about its subject. Each dossier is audited
(`subject.dossier`) and kept with the person (`GET .../dossier`).

`POST /api/cases/{case}/subjects/{id}/dossier` with `{"ai_acknowledged": true}`
