# 108. The big social networks

## What Argus reads (`social_pages`)

For a username, and for profiles found by other means (such as a web search), Argus reads the public
profile page that **Instagram, Facebook, Threads, TikTok, Snapchat, YouTube, Telegram and Pinterest**
serve to anyone without an account, and keeps what its preview tags show:

* that the profile exists, the **name** and **bio** it shows;
* its **profile picture**, fingerprinted to match a known photo or the same picture elsewhere.

Each network's answer is recorded per username: *found*, *not found*, *sign-in wall* or an error.

## What it cannot read, and how those profiles are found instead

| Network | Direct page | Found through |
| --- | --- | --- |
| Instagram, Facebook | often a sign-in wall | the page when public; otherwise web search (106) |
| X (Twitter), LinkedIn | always a sign-in wall | web search |
| Threads, TikTok, Snapchat, YouTube, Telegram, Pinterest | public page | the page, and web search |
| Google accounts | no public profile page | the YouTube channel; the address's Gravatar and keys |

## What it never does

* sign in, create or use accounts, or use cookies from someone's session;
* read posts, friends, followers or anything else a network shows only to signed-in users;
* call a network's internal (undocumented) interfaces, as tools that unmask Google accounts do with
  a signed-in session;
* check phone numbers against WhatsApp or Telegram (that needs an account and adding the number as a
  contact).

Public pages change and networks block automated visitors from time to time. A refusal or a sign-in
page is recorded as such; but a network can also answer with a page that looks like "not found", so
*not found* here is never proof that the account does not exist.
