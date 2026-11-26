# 115. A person's graph, and accounts that seem to share an owner

## The graph

The **Graph** section of a person's card draws:

* the person at the centre;
* what is known, each detail linked to the candidates it led to;
* the candidates: accounts confirmed as theirs, and accounts still to review;
* dashed links between candidates that share something (a picture, a link, a website, a name, bio
  wording);
* websites that several candidates link to;
* the other people connected through confirmed findings.

Click an account to open it. `GET /api/cases/{case}/subjects/{id}/graph` (`include_rejected=true` to
include ruled-out candidates).

## Groups

Argus compares every pair of candidates for:

| Signal | Groups by itself? |
| --- | --- |
| the same profile picture | yes |
| one links to the other | yes |
| a website both link to | no, shown only |
| the same name | no, shown only |
| similar bios (three or more distinctive words in common) | no, shown only |
| the same public email address | no, shown only |

Two weaker signals together also group them. A group that includes an account you confirmed points at
more of the person's accounts. An open candidate that shares a picture or a link with a confirmed
account gains an agreement in its score ("shares the same profile picture with a confirmed account").

`GET /api/cases/{case}/subjects/{id}/clusters`
