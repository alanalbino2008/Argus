// Ranking for the command palette: what you type against page names, investigations, cases and actions.
// Pure (no DOM), so it is unit-tested with Node (tests/js/fuzzy.test.mjs).
//
// Every word you type must match. A word scores best at the very start of the text, then at the start of
// a word inside it ("paths" in "Attack paths"), then anywhere ("cme" in "acme"). A word that is not a
// substring may still match the *label's* letters in order, close together ("rnsm" for "Ransomware"),
// scoring lowest, so an abbreviation or a typo still finds the page. That fallback never looks at the
// hidden keywords: across a long keyword list almost any few letters appear in order somewhere, which would
// put unrelated actions on top.

const BOUNDARY = /[\s\-_./·:@]/;

/** The letters of ``word`` appear in ``text`` in order, within a span not much longer than the word. */
function compactSubsequence(text, word) {
  const limit = word.length * 2 + 2;
  for (let start = text.indexOf(word[0]); start >= 0; start = text.indexOf(word[0], start + 1)) {
    let i = 1;
    let at = start;
    while (i < word.length) {
      at = text.indexOf(word[i], at + 1);
      if (at < 0 || at - start + 1 > limit) break;
      i += 1;
    }
    if (i === word.length) return true;
  }
  return false;
}

/** How well ``text`` matches ``query`` (0 = not at all); the letters-in-order fallback only uses ``label``.
 *  An empty query matches everything equally. */
export function score(text, query, label = text) {
  const words = String(query || "").trim().toLowerCase().split(/\s+/).filter(Boolean);
  if (!words.length) return 1;
  const t = String(text || "").toLowerCase();
  const l = String(label || "").toLowerCase();
  let total = 0;
  for (const word of words) {
    const at = t.indexOf(word);
    if (at === 0) total += 10;
    else if (at > 0) total += BOUNDARY.test(t[at - 1]) ? 6 : 3;
    else if (word.length > 1 && compactSubsequence(l, word)) total += 1;
    else return 0;
  }
  return total;
}

/** ``items`` that match ``query``, best first; ties keep their original order (so groups stay together). */
export function rank(items, query, limit = 50) {
  return items
    .map((item, index) => ({ item, index, s: score(`${item.label} ${item.keywords || ""}`, query, item.label) }))
    .filter((x) => x.s > 0)
    .sort((a, b) => b.s - a.s || a.index - b.index)
    .slice(0, limit)
    .map((x) => x.item);
}
