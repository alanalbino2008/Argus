# 106. Public records, developer sites and web searches for people

## Research and encyclopaedic records (`public_records`, from a name)

* **ORCID**: researchers' own records: employers and education, sometimes an email address.
* **OpenAlex**: authors of published papers, with the institutions they have been at.
* **Wikidata**: public figures, with a description and year of birth.

Only records in exactly the same name are kept, as profiles carrying their facts, so the scoring
weighs them: a namesake born in another year or at another employer is marked *probably not*.

## Developer sites (`developer_footprint`, from a username)

* **Stack Overflow**: the profile with that exact name (location, website, picture).
* **npm**: the packages the username maintains, and the address their packages are published with.

## Web searches for names and usernames (`web_mentions`)

The web search (Brave Search: your own key, or Argus Connect credits) now also searches for:

* **a person's name** (three searches): on the big social networks (Facebook, Instagram, LinkedIn,
  X, TikTok, Snapchat, Threads), together with their town or employer, and in CVs and documents
  (PDF, Word);
* **a username** (two searches): anywhere, and on the big social networks.

A result counts only if the name or username really appears in it. Results that are profile pages on
a social network become **profiles** (name taken from the page title); other results are mentions.
This is how Argus finds Facebook, Instagram, LinkedIn and X profiles, whose pages are not readable
without signing in. Only the starting point of a search is searched this way, to keep credit use
predictable: 3 credits for a name, 2 for a username.
