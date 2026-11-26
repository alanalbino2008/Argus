# 105. From a name to the identifiers they probably use

Investigators guess: someone called Jane Doe born in 1984 is likely to be `janedoe`, `jane.doe` or
`jdoe84` somewhere, and `jane.doe@gmail.com` is worth checking. Argus now makes those guesses and
**keeps only the ones something public confirms** (`name_guesser`, run with every name search):

| Guess | Checked against | Kept when |
| --- | --- | --- |
| Up to 8 likely usernames (with the year of birth if known) | GitHub, GitLab and Keybase public profiles | the account shows the same name |
| Up to 48 likely addresses at the person's own domains (their websites, their non-webmail addresses) and the big providers | Gravatar | a public profile exists for the address (stronger if it shows the same name) |
| The name itself | PGP keyservers | a published key carries the same name; its addresses are kept |

Everything kept is marked *guessed from the name* and scored like any other candidate.

## Public Git history (`git_identity`)

Every Git commit records its author's name, email address and local time with its UTC offset, and
public repositories publish them.

* From an **email address**: GitHub's public commit search finds the accounts that committed with it.
* From a **username**: the commits in their own (non-forked) repositories give the addresses they
  commit with (GitHub's private `noreply` addresses are skipped), and the time offsets of those
  commits give their usual time zone (see 107).

A GitHub token (`ARGUS_GITHUB_TOKEN`) raises GitHub's limit from 60 to 5,000 requests an hour; without
one, large searches may stop early.

## What it does not do

It never signs in, never tries a sign-up or password-reset page to learn whether an account exists
(that misuses those systems and often alerts the person), and never sends anything to the person or
their mail provider.
