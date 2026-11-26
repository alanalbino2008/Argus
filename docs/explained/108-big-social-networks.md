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

## Snapchat and Telegram in more depth (1.110.0)

* **Snapchat**: the profile Snapchat embeds in its page is read (name, bio, website, picture and
  subscriber count of public profiles). The page's preview text ("… is on Snapchat!") and preview
  image (a screenshot of the page) are never taken for a bio or a profile picture.
* **Telegram channels**: when a username is a public channel, its recent posts (as
  `t.me/s/<channel>` shows them to anyone) are read: subscriber count, the dates of its last 20 posts
  and the hours (UTC) it posts at, the links and the @mentions in them. Links to the person's
  accounts on other networks become candidates ("linked in their Telegram channel"); links to other
  channels' posts (mostly forwarded news) do not. Forwarded posts are not counted as theirs. A
  person's own account has no such page, and private groups and chats are never reachable.
* **Web search** also looks on Telegram (`site:t.me`) for the name or username.
