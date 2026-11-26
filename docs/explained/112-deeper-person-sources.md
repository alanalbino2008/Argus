# 112. Deeper sources about a person

Five more ways a person search finds what is theirs. All of them feed the same candidates, scoring
and review as everything else on the People tab.

## 1. The same picture elsewhere (`reverse_image`)

When you confirm an account, its profile picture's address is kept with the known details, and the
next search asks **TinEye** where else that picture appears (your own TinEye key, or Argus Connect
credits). Accounts using the same picture become candidates graded *strong* ("uses the same picture"),
even under another name; other pages using it are listed as pages to check.

This matches the same picture (resized or recompressed), never a face. A photo you uploaded as a
known detail is kept only as a fingerprint, so it cannot be sent to TinEye; use **Reverse image search**
on the case for it.

## 2. Deleted and renamed accounts (`archived_accounts`)

For each username, the Internet Archive is asked whether it kept copies of that profile on X (Twitter),
Instagram, Facebook, TikTok, Reddit, YouTube, Tumblr, Pinterest, Medium, Flickr, SoundCloud,
DeviantArt, Twitch, VK, LiveJournal, Myspace, Telegram and GitHub. Each one with copies becomes a
candidate with the months it was archived ("archived 2014-03 to 2017-06"), even if the account no
longer exists. The archived copies are then read (see 107) for the names, bios and links they showed.
They are graded *possible*: someone else may have used the handle there.

## 3. Their website, in depth

A known website is now also searched for:

* **related sites** sharing its analytics, advertising or tag IDs, certificates or dedicated servers
  (`infrastructure_pivot`, from the archived home page);
* **its old pages** (`site_history`): the archived "about", "bio", "CV", "resume", "contact" and "team"
  pages, which often listed email addresses and accounts that have since been removed.

## 4. Documents (`person_documents`)

CVs, PDFs and Word documents found by the web search for a name or username are read:

* the hidden author, company and creation date in the file;
* the email addresses and social links in its text.

The Internet Archive's copy is read when there is one. Otherwise the document is fetched from the
site, except in anonymous cases. A document becomes a page to check, scored by the author's name, the
town it mentions, and the employer.

## 5. Records in their name

The name search now includes UK **insolvency notices** (The Gazette) and US **court cases**
(CourtListener, needs a free key). Each notice or case is a separate record to check. It is graded
*possible*, because a name alone is weak, and counts more when it mentions the known town. Notices and
cases are often about namesakes; confirm only what you have checked.
