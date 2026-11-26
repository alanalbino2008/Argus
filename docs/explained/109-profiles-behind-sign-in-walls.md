# 109. Public profiles behind sign-in walls

LinkedIn, X, Facebook and Instagram profiles are often public: anyone can open them in a browser
without an account. But these networks show automated visitors (like Argus) a sign-in page instead.
Profile-viewing services read such profiles from their own servers as a logged-out visitor would.
Argus can now use one, **SocialFetch** (socialfetch.dev), with your own key.

## Setting it up

1. Create a SocialFetch account (100 free credits; paid packs after that) and an API key.
2. Enter it in Settings → Your API keys (*Profiles behind sign-in walls*), or set
   `ARGUS_SOCIALFETCH_API_KEY`. Argus Connect does not broker this source: only your own key is used.
3. Optionally change `ARGUS_SOCIALFETCH_MAX_LOOKUPS` (default 20 per scan).

Without a key nothing changes.

## What it is used for

In every person search (People tab) and every scan with the `profile_viewer` module:

* **profiles found** on LinkedIn, X, Facebook and Instagram that Argus could not read itself, for
  example those found by web search (106), linked from another profile or entered as known details;
* **a username's** X, Instagram and Facebook profiles.

What the profile shows publicly is kept and scored like any other profile:

* name;
* headline or bio;
* location and website;
* the profile picture's fingerprint, for photo matching;
* followers;
* for LinkedIn, the current employer, past positions and education.

Private and "not public" profiles are recorded as such.

| Lookup | Credits |
| --- | --- |
| LinkedIn profile | 5 |
| X, Instagram or Facebook profile | 1 |
| Failed lookups | none |

## What it never asks for

SocialFetch also sells "email finder", "phone finder" and contact lookups, follower and following
lists, stories and posts. Argus does not use them: they go beyond what the profile shows its visitors.
It also does not build its own way around sign-in walls (fake accounts, borrowed sessions, the
networks' internal interfaces): that would mean breaking those sites' access controls.

## Things to know

* SocialFetch sees which profiles are looked up, as a search engine sees what is searched. It keeps
  request logs for about 30 days (accounts that have paid can choose none). The person's sites see
  only SocialFetch, never Argus.
* Its terms make you responsible for complying with each network's own terms; check that your use
  (and your organisation's legal basis) allows it.
* Answers are live and can be wrong or incomplete; a profile is still a possibility, not an
  identification.
