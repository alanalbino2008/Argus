# 38 — Website Crawling (Plain-English Guide)

> Purpose: explain how Argus reads a whole website, what it looks for, and the rules it follows.
> Useful for questions like:
> * "who is behind this fake charity or scam shop?"
> * "does Argus hammer websites or ignore their wishes?"
> * "will it wander off and scan other people's sites?"

## 1. Why this matters

A suspicious website rarely says who runs it on the home page. The clues are deeper in:

* a personal Gmail address on the terms page;
* a phone number in the footer of the delivery page;
* a Bitcoin address on the donation page;
* a link to the owner's real Instagram;
* a PDF annual report whose hidden "author" field holds a real name;
* an analytics ID shared with the same people's other websites.

Clicking through every page by hand takes hours, and something is always missed. Argus now reads
the whole site and lists what it finds, with the page each item came from.

## 2. What it finds

| What | Details |
|---|---|
| **Email addresses** | including disguised ones like "jane [at] hope [dot] org". Addresses outside the site's own domain (a personal Gmail, say) are marked: they often lead to the person behind the site |
| **Phone numbers** | those with a country code, so they can be looked up |
| **Crypto wallets** | each checked against its checksum, so typos and look-alikes aren't reported |
| **Social media accounts** | X, Facebook, Instagram, LinkedIn, YouTube, TikTok, Telegram, GitHub, WhatsApp, Bluesky, Patreon, GoFundMe, PayPal and more. "Share this page" buttons are ignored: they aren't the owner's accounts |
| **Documents** | PDFs, Word and Excel files and so on. Up to ten on the site itself are opened to read their hidden author, company and creation date |
| **Analytics and advertising IDs** | Google Analytics, Tag Manager, AdSense, Meta pixel. Sites that share one are usually run by the same people |
| **Other websites it links to** | listed by name, with how often |

## 3. The rules it follows

* **It obeys robots.txt.** Website owners use this file to say which pages crawlers shouldn't
  visit. Argus follows the rules written for it, or else those for every crawler, and counts the
  pages it skipped. When a rule says "stay out" and another says "this part is fine", the more
  specific one wins, the way search engines do it.
* **It stays on the site.** It follows links within the website only. Other websites are named
  but **never visited or scanned**: following them could mean probing someone you have no reason
  to investigate.
* **It is gentle.** It pauses between pages (half a second by default), stops at a set number of
  pages (40 by default), and reads at most 600 KB per page.
* **It reads only what matters.** It skips images, videos, scripts, archives, and login, admin,
  cart and checkout pages.
* **It is "active".** Reading a site means visiting it, so:
  * it is skipped in passive-only scans and anonymous cases, which promise never to touch the
    subject's own systems;
  * in other cases it goes through the case's route.

## 4. In the website playbook

The **Website background** playbook now:

1. looks up who registered the site, its history and related sites (without visiting it);
2. reads the whole site;
3. preserves the home page and the contact, about, team and legal pages as evidence;
4. writes down what stands out:
   * outside email addresses and published wallets are *worth checking*;
   * documents that name an author or company are *worth checking*;
   * analytics IDs are listed so they can be compared with other sites.

## 5. In the graph

Clicking a website shows a **"Website read"** panel:

* how many pages were read;
* how many were skipped because of robots.txt;
* the analytics IDs;
* the sites it links to;
* the full list of pages.

Everything the crawler found shows **where it was found**: the page it came from.

## 6. What a reviewer can check

* `argus/modules/discovery/site_crawler.py`:
  * the robots.txt reader (`RobotRules`);
  * what a page publishes (`page_facts`);
  * social account links (`social_account`);
  * the crawl itself, with its limits.
* `argus/intel/playbooks.py`: the website playbook and its findings.
* `argus/web/js/views/graphview.js`: the "Website read" panel.
* `tests/test_crawler.py`:
  * social links and share buttons;
  * robots.txt rules;
  * disguised emails;
  * a whole site read within its bounds (robots.txt obeyed, other sites never fetched, redirects
    followed on the site only);
  * the page limit;
  * document authors;
  * the playbook's findings.
