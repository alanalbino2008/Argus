# 43 — Relationship Mapping and the Link Chart (Plain-English Guide)

> Purpose: explain how Argus maps the people and organisations in a case and the relationships
> between them, and what it can work out from that network. Useful for questions like:
> * "how is this director connected to that charity?"
> * "who is the go-between in this group?"
> * "what does Argus suggest, and why should I trust it?"

## 1. Why this matters

Investigations are about people: who is married to whom, who works for whom, who pays whom, who
shares a phone. A list of names doesn't show that. A **link chart** does, the way investigators
have drawn them on whiteboards for decades. Argus draws it from the case, and then helps with the
questions a chart raises.

## 2. Kinds of relationship

Every link between two people or organisations has a **kind**, in six groups. Each group has its
own colour on the chart:

| Group | Kinds |
|---|---|
| **Family** | spouse or partner, parent, sibling, relative |
| **Work** | works for, colleague, director or officer, co-director |
| **Business and money** | owns or controls, business partner, client, pays or funds |
| **Social** | friend, associate, communicates with, follows online |
| **Shared details** | shares a phone number, email, address, wallet or website; uses |
| **Other** | anything else |

A link can also record:

* **how sure** you are: confirmed, likely or possible. Shown as solid, thinner or dashed lines;
* **when** the relationship began and ended (a year, a month or a date);
* **in your words**, for example "married in 2015";
* **the evidence** that shows it.

## 3. Relationships Argus suggests

Argus reads the case's own material and suggests relationships it shows but that aren't linked
yet. **Nothing is added automatically**: each suggestion says why, and you choose.

* **Company registers** (from scans linked to the case):
  * a person who is a director or owner of a company in the case;
  * two people who sit on the same company's board. If one had left before the other joined,
    Argus says so.
* **Shared details**: two people linked to the same phone number, email, address, wallet or
  website, or with the same detail recorded about them. Argus understands labels such as
  "Mobile" or "Home address".
* **Same employer** recorded for both.
* **Named together** in the same note or document. That is only a possibility; a document naming
  everyone involved suggests nothing.

## 4. What the network shows

* **Most connected**: the people with the most relationships.
* **Go-betweens**: people who connect groups that would otherwise be apart. They are often the
  most interesting: the fixer, the accountant, the relative who links two families.
* **Groups**: clusters of people more connected to each other than to the rest.
* **Not connected yet**: people in the case with no relationships. A reminder to find out how they
  fit.

## 5. How are two people connected?

Pick two people and Argus traces the **chain of relationships** between them. For example:

* Jane Roe is a director of Hope Relief Ltd;
* Northgate Trading pays Hope Relief Ltd;
* Marta Kowalski works for Northgate Trading.

Weaker links count as longer, so the chain shown is the **best-supported** one. It is labelled
with how strong it is overall: a chain is only as strong as its weakest link. Argus also lists
the connections the two share.

## 6. Protecting children

Any person can be marked **protected**, for example a child who appears in an investigation.
Argus then:

* shows them on the link chart only as **"Protected person"**, with a shield;
* leaves them out of suggestions and of the network lists;
* for the AI analyst, removes their entry and blanks their name out of every note and document
  it reads.

The investigator still sees the name in their own case's list, marked "Protected", because they
entered it.

## 7. What a reviewer can check

* `argus/intel/relationships.py`:
  * the kinds of relationship;
  * the suggestions (`discover`);
  * the network analysis (`analyse`);
  * the chain between two people (`path`);
  * protection (`redact_protected`).
* `argus/api/network_routes.py`: the network, path and suggestion endpoints.
* `argus/api/case_routes.py`: checking a link's kind, dates and evidence.
* `argus/web/js/views/casechart.js`: the link chart.
* `tests/test_relationships.py`:
  * groups, go-betweens and loose ends;
  * the best-supported path;
  * every kind of suggestion, with its reasons;
  * protected people never named or profiled;
  * the API, including rejecting unknown kinds and badly written dates.
