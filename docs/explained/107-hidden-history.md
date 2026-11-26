# 107. What profiles used to say, and when people are awake

## Archived copies of profiles (`profile_history`)

For each profile found with reasonable confidence (and each known profile link), Argus asks the
Internet Archive for its copies and reads the oldest and the newest:

* when the profile was first and last archived, and how many versions exist;
* the **name** it showed: an earlier name is recorded, and an archived copy showing the person's
  known name counts in the profile's favour;
* the links it carried to other social accounts: an account linked once, even if it was later
  unlinked or deleted, becomes a candidate ("linked in an archived copy, 2015-01-01").

Only the archive is contacted.

## Time zones

Commits carry the author's local UTC offset (105). The usual offset is recorded on the GitHub
profile, and:

* known details gain a **usual time zone** (a UTC offset such as `+01:00`), typed in or learned from
  the first confirmed account that has one;
* a candidate working in the same time zone (within an hour) gains an agreement; one three hours or
  more away gains a contradiction, which helps tell namesakes on other continents apart.

Known profile links are now searched themselves too (their archived copies and public page), not
only by their handle.
