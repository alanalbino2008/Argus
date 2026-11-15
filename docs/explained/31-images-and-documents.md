# 31 — Images & Documents (Plain-English Guide)

> Purpose: explain what photos and documents silently reveal, how Argus reads it safely, and how
> investigators use it to check where and when a photo was taken. Useful for questions like:
> * "what is EXIF metadata?"
> * "can you tell if a photo was edited?"
> * "how do shadows prove what time a photo was taken?"
> * "how do you protect a source who sends you a document?"

## 1. Why this matters

Files carry more than they show. A phone photo usually records the camera, the exact time and the
GPS position where it was taken. A Word file records who wrote it, who last edited it, the company
it was registered to and how many minutes were spent editing it. A PDF records the software that
made it, and whether it was changed afterwards.

For an investigator this is evidence: a "leaked memo" written by the person it claims to expose,
or a "photo from the protest" taken a year earlier, 300 miles away. For a source it is a danger:
journalists have exposed their own sources by publishing documents with this information still
inside. Argus handles both sides.

## 2. Inspecting a file

Every photo, PDF and Word, Excel or PowerPoint file in a case has an **Inspect** button. Argus
reads the file on its server and shows:

* **Everything it contains**, grouped:
  * File: name, size, real type, SHA-256 and MD5;
  * Camera and settings;
  * Dates;
  * Location;
  * People: authors, editors, comment authors, user names;
  * Software;
  * Embedded text.
* **Findings**: what stands out, in plain words, each marked *warning*, *notice* or *info*.

Inspecting never changes the evidence. It is written to the evidence's chain of custody, like
viewing or downloading.

## 3. What the findings mean

| Finding | What it suggests |
|---|---|
| The real type differs from the name ("invoice.pdf" that is a PNG) | Someone may have disguised the file |
| Saved by editing software (Photoshop, Snapseed…) | Not as the camera took it; often harmless (cropping, brightness) |
| Changed after it was taken | Edited or re-saved later |
| The camera clock and the GPS disagree | Clocks drift a little; a big gap can mean the date was changed |
| **The camera's preview shows a different picture** | Cameras store a small preview inside the photo. Editing programs often update the main image but not the preview. If they differ, the image was very likely changed |
| AI-generator settings, or an "AI-generated" label | Stable Diffusion and ComfyUI write the prompt into the file; publishers label AI images with an IPTC code |
| Content Credentials (C2PA) | A signed record of how the image was made, checkable at contentcredentials.org |
| No camera details or date | Normal for anything saved from social media or chat apps, which remove them. **Says nothing about authenticity either way** |
| A PDF saved several times | Each save is appended to the file, so earlier versions may still be inside |
| PDF JavaScript, attachments or links | Can run code, hide files, or tell the author who opened it and when |
| Written by A, last edited by B | More than one person handled it |
| Tracked changes, comments | Deleted text and reviewers' notes may still be readable |
| A user name in a file path (`C:\Users\jsmith\…`) | Leaks who made it, often unnoticed |

**Findings are leads, not verdicts.** A missing finding does not prove a photo is real, and a
present one does not prove deception. They tell an investigator where to look harder.

## 4. Where and when: checking the shadows

If a photo records its position, Argus shows it with a link to OpenStreetMap, and buttons to add
the place to the case and the time to the timeline.

Investigators check a photo's claimed time by its **shadows**. At any place and moment the sun
is in a predictable direction and at a predictable height. Shadows point the opposite way, and an
upright object's shadow is `1 ÷ tan(height)` times as long as the object. Argus calculates this
with the US National Oceanic and Atmospheric Administration's solar position algorithm (accurate
well within a degree):

> The sun was in the S (179°), 62° above the horizon. Shadows pointed N (359°) and were about
> 0.5 times as long as the object casting them.

If the photo's shadows are long and point east, it wasn't taken at noon in June in London. The
calculator also works without metadata: type in the place and time a photo *claims* to show. The
tests check the results against published values for London (summer and winter) and Sydney.

## 5. Error level analysis

JPEG images lose a little detail each time they are saved. **Error level analysis** re-saves the
image once more and shows, brightened, how much each area changed. An area pasted in after the
last save often re-compresses differently and stands out. So do sharp edges, text and fine
detail, so it is a guide for where to look, **never proof**. Argus says so beside the result. A
test pastes a block into a saved JPEG and checks it stands out.

## 6. Reverse image search

Finding where else an image appears, especially the earliest copy, is often the quickest way to
debunk a recycled photo. Argus offers Google Lens, Bing, Yandex and TinEye:

* if the image was captured from a public address, the links search by that address;
* otherwise they open each engine's upload page, with a warning to upload the **copy without
  metadata**, never the original.

These sites are outside Argus: they see the image and the investigator's own connection.

## 7. Protecting sources: the copy without metadata

**Copy without metadata** produces the picture alone: no camera, GPS, dates, author names, colour
profile or embedded text. The image is turned the right way up first, because the orientation
setting is removed too. The evidence itself is untouched; the copy is a download, recorded in the
custody log. The tests check that the camera name, the GPS and a PNG's author no longer appear
anywhere in the cleaned file's bytes, while the picture looks the same.

## 8. Reading hostile files safely

A file under investigation may have been made to attack whoever opens it. Argus:

* refuses images over 60 megapixels before decoding them ("decompression bombs": a tiny file that
  expands to gigabytes);
* checks each Office file part's declared size before reading it ("zip bombs"), and reads the XML
  with `defusedxml`, which refuses the entity tricks that make a few bytes expand into gigabytes;
* reads PDFs without running anything they contain, and reports their scripts instead;
* bounds-checks every offset when it finds the camera preview inside a JPEG;
* runs each inspection off the main server loop, with a time limit.

Tests feed it an image bomb, an XML entity bomb, an oversized document part, a broken JPEG and a
broken PDF, and check each is reported as unreadable, never a crash.

## 9. What a reviewer can check

* `argus/evidence/inspect.py`: type detection, EXIF/GPS/XMP, the thumbnail check, AI and C2PA
  markers, PDF and Office readers, error level analysis, the clean copy, reverse search.
* `argus/intel/sun.py`: the solar position algorithm.
* `argus/api/inspect_routes.py`: the endpoints and custody logging.
* `tests/test_inspect.py`.
