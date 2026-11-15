"""Images and documents: metadata, signs of editing, clean copies, error levels and the sun."""

from __future__ import annotations

import io
import struct
import zipfile
from datetime import datetime, timedelta, timezone

import pytest
from PIL import Image, ImageDraw, ImageStat

from argus.evidence.inspect import clean_copy, detect_type, error_level, inspect_file, jpeg_thumbnail, reverse_search
from argus.intel.sun import compass, sun_position


def picture(variant: int = 0, size=(400, 300)) -> Image.Image:
    img = Image.new("RGB", size, "white")
    draw = ImageDraw.Draw(img)
    if variant == 0:
        draw.ellipse((50, 50, 250, 250), fill="navy")
        draw.rectangle((260, 40, 380, 280), fill="orange")
    else:
        draw.rectangle((0, 0, 200, 300), fill="black")
        draw.ellipse((220, 20, 390, 190), fill="red")
    return img


def photo(*, software: str | None = None, gps=True, offset="+01:00", changed="2024:06:21 13:00:00",
          thumbnail: Image.Image | None = None, img: Image.Image | None = None) -> bytes:  # fmt: skip
    exif = Image.Exif()
    exif[0x010F], exif[0x0110] = "Canon", "Canon EOS R6"
    if software:
        exif[0x0131] = software
    exif[0x0132] = changed
    sub = exif.get_ifd(0x8769)
    sub[0x9003] = "2024:06:21 13:00:00"
    if offset:
        sub[0x9011] = offset
    sub[0xA431] = "012345678"
    if gps:
        g = exif.get_ifd(0x8825)
        g[1], g[2], g[3], g[4] = "N", (51.0, 30.0, 2.52), "W", (0.0, 7.0, 28.56)
        g[7], g[0x1D] = (12.0, 0.0, 0.0), "2024:06:21"
    out = io.BytesIO()
    (img or picture()).save(out, "JPEG", exif=exif, quality=92)
    data = out.getvalue()
    return with_thumbnail(data, thumbnail) if thumbnail is not None else data


def with_thumbnail(jpeg: bytes, thumb_img: Image.Image) -> bytes:
    """Replace the EXIF block with one whose IFD1 holds ``thumb_img`` (as cameras write it)."""
    t = io.BytesIO()
    thumb_img.resize((160, 120)).save(t, "JPEG")
    thumb = t.getvalue()
    # TIFF header, IFD0 with one entry (Make), IFD1 with offset/length of the thumbnail.
    make = b"Canon\x00"
    ifd0_at, ifd1_at = 8, 8 + 2 + 12 + 4
    data_at = ifd1_at + 2 + 2 * 12 + 4
    thumb_at = data_at + len(make)
    tiff = b"II*\x00" + struct.pack("<I", ifd0_at)
    tiff += struct.pack("<H", 1) + struct.pack("<HHII", 0x010F, 2, len(make), data_at) + struct.pack("<I", ifd1_at)
    tiff += (
        struct.pack("<H", 2)
        + struct.pack("<HHII", 0x0201, 4, 1, thumb_at)
        + struct.pack("<HHII", 0x0202, 4, 1, len(thumb))
    )
    tiff += struct.pack("<I", 0) + make + thumb
    app1 = b"Exif\x00\x00" + tiff
    segment = b"\xff\xe1" + struct.pack(">H", len(app1) + 2) + app1
    # Drop the existing APP1 (if any) and insert ours after SOI.
    pos, body = 2, jpeg[2:]
    if jpeg[2:4] == b"\xff\xe1":
        size = struct.unpack(">H", jpeg[4:6])[0]
        body = jpeg[2 + 2 + size :]
    return jpeg[:pos] + segment + body


def kinds(report):
    return [f["level"] for f in report["findings"]]


def text(report):
    return " ".join(f["text"] for f in report["findings"])


def field(report, group, label):
    return next(
        (f["value"] for g in report["groups"] if g["group"] == group for f in g["fields"] if f["label"] == label), None
    )


# ---------------------------------------------------------------------------- photos
def test_a_photo_reveals_camera_time_and_place():
    report = inspect_file("IMG_0001.jpg", "image/jpeg", photo())
    assert report["kind"] == "image" and report["type_label"] == "JPEG image"
    assert (
        field(report, "Camera", "Model") == "Canon EOS R6"
        and field(report, "Camera", "Camera serial number") == "012345678"
    )
    assert report["gps"]["latitude"] == 51.5007 and report["gps"]["longitude"] == -0.1246
    assert "openstreetmap.org" in report["gps"]["map_url"] and report["gps"]["time_utc"].startswith("2024-06-21T12:00")
    assert report["taken_at"] == {"value": "2024-06-21T13:00:00+01:00", "time_zone_known": True}
    assert report["sun"]["sun_direction"] == "S" and 60 < report["sun"]["elevation"] < 64
    assert "where it was taken" in text(report)
    assert report["cleanable"] and report["error_level"] and report["image"]["perceptual_hash"]


def test_signs_of_editing_are_explained():
    edited = inspect_file("p.jpg", "image/jpeg", photo(software="Adobe Photoshop 25.0", changed="2024:06:23 10:00:00"))
    assert "editing software (Adobe Photoshop 25.0)" in text(edited)
    assert "after it was taken" in text(edited)
    honest = inspect_file("p.jpg", "image/jpeg", photo())
    assert "editing software" not in text(honest) and "after it was taken" not in text(honest)
    drift = inspect_file("p.jpg", "image/jpeg", photo(offset="+03:00"))  # 13:00+03 = 10:00 UTC, GPS says 12:00
    assert "disagree by 120 minutes" in text(drift)
    no_zone = inspect_file("p.jpg", "image/jpeg", photo(offset=None))
    assert field(no_zone, "Dates", "Camera time zone (from GPS)") == "UTC+1"


def test_a_preview_that_shows_another_picture_is_flagged():
    same = photo(thumbnail=picture(0))
    assert jpeg_thumbnail(same) is not None
    assert "different picture" not in text(inspect_file("a.jpg", "image/jpeg", same))
    swapped = photo(thumbnail=picture(1))  # the camera saw one scene; the image now shows another
    report = inspect_file("a.jpg", "image/jpeg", swapped)
    assert "warning" in kinds(report) and "embedded preview shows a different picture" in text(report)
    assert jpeg_thumbnail(b"\xff\xd8\xff\xe1\x00\x10Exif\x00\x00II*\x00\xff\xff\xff\xff") is None  # hostile offsets


def test_ai_generated_images_are_recognised():
    from PIL.PngImagePlugin import PngInfo

    info = PngInfo()
    info.add_text("parameters", "a protest in Paris, photorealistic, Steps: 30, Sampler: Euler a")
    out = io.BytesIO()
    picture().save(out, "PNG", pnginfo=info)
    report = inspect_file("protest.png", "image/png", out.getvalue())
    assert "generated by AI" in text(report) and "Steps: 30" in field(report, "Embedded text", "parameters")

    xmp = (b'<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF><rdf:Description '
           b'Iptc4xmpExt:DigitalSourceType="http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia"/>'
           b"</rdf:RDF></x:xmpmeta>")  # fmt: skip
    labelled = inspect_file("x.jpg", "image/jpeg", photo(gps=False) + xmp)
    assert "made or changed by AI" in text(labelled)


def test_images_from_the_web_say_so_and_disguises_are_caught():
    plain = io.BytesIO()
    picture().save(plain, "JPEG")
    report = inspect_file("download.jpg", "image/jpeg", plain.getvalue())
    assert "Social networks and messaging apps remove them" in text(report) and report["gps"] is None
    png = io.BytesIO()
    picture().save(png, "PNG")
    disguised = inspect_file("invoice.pdf", "application/pdf", png.getvalue())
    assert "really a PNG image" in text(disguised)
    assert detect_type(b"\x00\x00\x00\x18ftypheic....") == "image/heic"
    heic = inspect_file("IMG.HEIC", "image/heic", b"\x00\x00\x00\x18ftypheic" + b"\x00" * 64)
    assert "HEIC" in text(heic)


def test_hostile_images_are_refused_safely():
    bomb = io.BytesIO()
    Image.new("1", (12000, 12000)).save(bomb, "PNG")  # tiny file, 144 million pixels
    report = inspect_file("bomb.png", "image/png", bomb.getvalue())
    assert "too large to open safely" in text(report)
    broken = inspect_file("broken.jpg", "image/jpeg", b"\xff\xd8\xff\xe0" + b"\x00" * 200)
    assert "could not be read" in text(broken)


def test_a_clean_copy_keeps_the_picture_and_nothing_else():
    original = photo(software="Adobe Photoshop 25.0")
    clean, media, ext = clean_copy(original)
    assert media == "image/jpeg" and ext == "jpg"
    report = inspect_file("clean.jpg", "image/jpeg", clean)
    assert report["gps"] is None and field(report, "Camera", "Model") is None and b"Canon" not in clean
    assert Image.open(io.BytesIO(clean)).size == (400, 300)
    from argus.intel.avatars import distance

    assert (
        distance(
            report["image"]["perceptual_hash"],
            inspect_file("o.jpg", "image/jpeg", original)["image"]["perceptual_hash"],
        )
        <= 2
    )

    from PIL.PngImagePlugin import PngInfo

    info = PngInfo()
    info.add_text("Author", "Jane Source")
    png = io.BytesIO()
    picture().save(png, "PNG", pnginfo=info)
    clean_png, media, _ = clean_copy(png.getvalue())
    assert media == "image/png" and b"Jane Source" not in clean_png


def test_error_level_analysis_highlights_a_pasted_area():
    base = io.BytesIO()
    picture().save(base, "JPEG", quality=70)
    edited = Image.open(io.BytesIO(base.getvalue())).convert("RGB")
    ImageDraw.Draw(edited).rectangle((20, 200, 120, 290), fill=(10, 200, 30))  # pasted after the first save
    out = io.BytesIO()
    edited.save(out, "JPEG", quality=95)
    ela = Image.open(io.BytesIO(error_level(out.getvalue()))).convert("L")
    inside = ImageStat.Stat(ela.crop((30, 210, 110, 280))).mean[0]
    outside = ImageStat.Stat(ela.crop((300, 0, 400, 30))).mean[0]
    assert ela.size == (400, 300) and inside > outside
    png = io.BytesIO()
    picture().save(png, "PNG")
    with pytest.raises(ValueError, match="JPEG"):
        error_level(png.getvalue())


def test_reverse_search_links():
    by_address = reverse_search("https://example.com/a b.jpg")
    assert [e["engine"] for e in by_address] == ["Google Lens", "Bing Visual Search", "Yandex Images", "TinEye"]
    assert all(e["mode"] == "address" and "example.com%2Fa%20b.jpg" in e["url"] for e in by_address)
    assert all(e["mode"] == "upload" for e in reverse_search(None))


# ---------------------------------------------------------------------------- documents
def office(files: dict[str, str], kind: str = "word") -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr(f"{kind}/placeholder.xml", "<x/>")
        for name, body in files.items():
            z.writestr(name, body)
    return out.getvalue()


CORE = """<?xml version="1.0"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
 xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/"><dc:title>Q3 payments</dc:title>
 <dc:creator>Jane Roe</dc:creator><cp:lastModifiedBy>J. Smith</cp:lastModifiedBy><cp:revision>14</cp:revision>
 <dcterms:created>2024-03-01T09:00:00Z</dcterms:created><dcterms:modified>2024-03-04T17:12:00Z</dcterms:modified></cp:coreProperties>"""
APP = """<?xml version="1.0"?><Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">
 <Application>Microsoft Office Word</Application><Company>Acme Shell Ltd</Company><TotalTime>3</TotalTime>
 <Template>C:\\Users\\jsmith\\AppData\\Roaming\\Microsoft\\Templates\\Normal.dotm</Template></Properties>"""
W = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'


def test_a_word_file_names_its_authors_editors_and_secrets():
    data = office({
        "docProps/core.xml": CORE, "docProps/app.xml": APP,
        "word/comments.xml": f'<w:comments {W}><w:comment w:author="J. Smith"/><w:comment w:author="Legal"/></w:comments>',
        "word/document.xml": f'<w:document {W}><w:body><w:del w:author="J. Smith"><w:r><w:delText>paid to Fenwick</w:delText>'
                             f'</w:r></w:del></w:body></w:document>',
        "word/embeddings/oleObject1.bin": "x",
    })  # fmt: skip
    assert detect_type(data).endswith("wordprocessingml.document")
    report = inspect_file("memo.docx", "application/octet-stream", data)
    assert report["kind"] == "office" and report["type_label"] == "Word document"
    assert field(report, "People", "Author") == "Jane Roe" and field(report, "People", "Last edited by") == "J. Smith"
    assert (
        field(report, "People", "Company") == "Acme Shell Ltd"
        and field(report, "Document", "Editing time (minutes)") == "3"
    )
    assert field(report, "People", "User name in a file path") == "jsmith"
    found = text(report)
    assert "last edited by “J. Smith”" in found and "2 comment(s) by J. Smith, Legal" in found
    assert "1 tracked change(s) by J. Smith" in found and "embedded inside" in found


def test_documents_cannot_attack_the_parser():
    bomb = '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]><x>&b;</x>'
    report = inspect_file("x.docx", "", office({"docProps/core.xml": bomb}))
    assert "could not be read" in text(report)  # entities refused, not expanded
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("word/document.xml", "<x/>")
        z.writestr("docProps/core.xml", "<a>" + "a" * (6 * 1024 * 1024) + "</a>")  # beyond the cap
    assert "could not be read" in text(inspect_file("big.docx", "", out.getvalue()))


def pdf(info: dict[str, str], *, javascript=False, saves=1) -> bytes:
    from pypdf import PdfWriter
    from pypdf.generic import DictionaryObject, NameObject, TextStringObject

    writer = PdfWriter()
    writer.add_blank_page(200, 200)
    writer.add_metadata({f"/{k}": v for k, v in info.items()})
    if javascript:
        action = DictionaryObject({NameObject("/S"): NameObject("/JavaScript"),
                                   NameObject("/JS"): TextStringObject("app.alert('hi');")})  # fmt: skip
        writer._root_object[NameObject("/OpenAction")] = writer._add_object(action)
    writer._root_object[NameObject("/Lang")] = TextStringObject("en")
    out = io.BytesIO()
    writer.write(out)
    data = out.getvalue()
    for _ in range(saves - 1):
        data += b"\n%%EOF\n"
    return data


def test_a_pdf_shows_its_history_and_dangers():
    data = pdf({"Author": "Jane Roe", "Creator": "Microsoft Word", "Producer": "macOS Quartz PDFContext",
                "CreationDate": "D:20240301090000Z", "ModDate": "D:20240305120000Z",
                "Title": "/Users/jroe/Desktop/leak.docx"}, javascript=True, saves=3)  # fmt: skip
    report = inspect_file("leak.pdf", "application/pdf", data)
    assert report["kind"] == "pdf" and field(report, "Document", "Author") == "Jane Roe"
    assert field(report, "Document", "Made with") == "Microsoft Word" and field(report, "Document", "Pages") == "1"
    assert field(report, "Dates", "Created") == "2024-03-01 09:00:00"
    found = text(report)
    assert "contains JavaScript" in found and "saved 3 times" in found and "Modified (2024-03-05" in found
    assert "user name: “jroe”" in found
    assert "could not be read" in text(inspect_file("bad.pdf", "application/pdf", b"%PDF-1.7\n garbage"))


# ---------------------------------------------------------------------------- the sun
def test_the_sun_matches_published_positions():
    noon = sun_position(51.5007, -0.1246, datetime(2024, 6, 21, 12, 0, tzinfo=timezone.utc))
    assert abs(noon["azimuth"] - 179) < 1.5 and abs(noon["elevation"] - 62) < 0.5  # NOAA calculator
    assert noon["shadow_direction"] == "N" and 0.5 < noon["shadow_ratio"] < 0.56
    winter = sun_position(51.5007, -0.1246, datetime(2024, 12, 21, 12, 0, tzinfo=timezone.utc))
    assert 14.5 < winter["elevation"] < 15.5 and winter["shadow_ratio"] > 3.5  # long winter shadows
    sydney = sun_position(-33.86, 151.21, datetime(2024, 12, 21, 13, 0, tzinfo=timezone(timedelta(hours=11))))
    assert (
        sydney["sun_direction"] in ("N", "NNW", "NW") and sydney["elevation"] > 70
    )  # southern summer: sun to the north
    night = sun_position(51.5, -0.12, datetime(2024, 1, 1, tzinfo=timezone.utc))
    assert night["sun_up"] is False and night["shadow_ratio"] is None and "night" in night["summary"]
    assert compass(359) == "N" and compass(225) == "SW"
    with pytest.raises(ValueError, match="latitude"):
        sun_position(91, 0, datetime(2024, 1, 1, tzinfo=timezone.utc))
    with pytest.raises(ValueError, match="time zone"):
        sun_position(0, 0, datetime(2024, 1, 1))


# ---------------------------------------------------------------------------- through the API
@pytest.fixture
def client(make_client):
    c = make_client(monitors_enabled="false", notifications_enabled="false", report_schedules_enabled="false",
                    allow_private_targets="true", capture_browser="off")  # fmt: skip
    c.post("/api/demo")
    return c


def test_inspecting_evidence_through_the_api(client):
    case = client.post("/api/cases", json={"title": "Protest photo", "confirmed": True,
                                           "purpose": "Verifying a photo sent by a reader"}).json()  # fmt: skip
    upload = client.post(f"/api/cases/{case['id']}/uploads", files={"file": ("IMG_0001.jpg", photo(), "image/jpeg")},
                         data={"note": "From a reader by email"}).json()  # fmt: skip
    base = f"/api/evidence/{upload['id']}/files/IMG_0001.jpg"
    report = client.get(f"{base}/inspect").json()
    assert report["gps"]["latitude"] == 51.5007 and report["sun"]["shadow_direction"] == "N"
    assert all(e["mode"] == "upload" for e in report["reverse_search"])  # not a public image: upload pages only

    clean = client.get(f"{base}/clean")
    assert clean.status_code == 200 and b"Canon" not in clean.content
    assert clean.headers["content-disposition"].startswith('attachment; filename="IMG_0001-clean.jpg"')
    ela = client.get(f"{base}/error-level")
    assert ela.status_code == 200 and ela.content.startswith(b"\x89PNG")

    custody = [c["action"] for c in client.get(f"/api/evidence/{upload['id']}").json()["custody"]]
    assert {"inspected", "exported a copy without metadata", "analysed (error level)"} <= set(custody)
    assert client.post(f"/api/evidence/{upload['id']}/verify").json()["intact"]  # the original is untouched

    doc = client.post(f"/api/cases/{case['id']}/uploads", files={"file": ("memo.docx", office({"docProps/core.xml": CORE}),
                      "application/octet-stream")}).json()  # fmt: skip
    assert client.get(f"/api/evidence/{doc['id']}/files/memo.docx/clean").status_code == 422
    assert client.get(f"/api/evidence/{doc['id']}/files/memo.docx/inspect").json()["kind"] == "office"
    assert client.get(f"/api/evidence/{doc['id']}/files/nope.txt/inspect").status_code == 404

    sun = client.get(
        "/api/tools/sun", params={"lat": 51.5007, "lon": -0.1246, "at": "2024-06-21T13:00:00+01:00"}
    ).json()
    assert sun["shadow_direction"] == "N"
    assert client.get("/api/tools/sun", params={"lat": 95, "lon": 0, "at": "2024-06-21T13:00:00Z"}).status_code == 422


def test_a_captured_image_can_be_searched_by_its_address(client, monkeypatch):
    from argus.evidence import capture as cap

    async def fake_capture(url, settings, route=None):
        files = {"response.bin": ("image/jpeg", photo(gps=False)), "headers.json": ("application/json", b"{}")}
        manifest, digest = cap.build({"kind": "web_capture", "url": url, "final_url": url}, files)
        return cap.Capture(manifest, digest, files, None, [])

    monkeypatch.setattr("argus.api.case_routes.capture_url", fake_capture)
    case = client.post("/api/cases", json={"title": "Viral image", "confirmed": True,
                                           "purpose": "Tracing where a viral image first appeared"}).json()  # fmt: skip
    ev = client.post(f"/api/cases/{case['id']}/captures", json={"url": "https://cdn.example.com/viral.jpg"}).json()
    report = client.get(f"/api/evidence/{ev['id']}/files/response.bin/inspect").json()
    assert all(e["mode"] == "address" and "cdn.example.com" in e["url"] for e in report["reverse_search"])


def test_the_python_client_covers_inspection(client):
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "clients" / "python"))
    from argus_client import ArgusClient

    argus = ArgusClient(http=client)
    case = argus.create_case("Photo check", purpose="Checking where a viral photo was taken")
    ev = client.post(f"/api/cases/{case['id']}/uploads", files={"file": ("p.jpg", photo(), "image/jpeg")}).json()
    assert argus.inspect_evidence(ev["id"], "p.jpg")["gps"]["latitude"] == 51.5007
    assert b"Canon" not in argus.clean_copy(ev["id"], "p.jpg")
    assert argus.sun(51.5, -0.12, "2024-06-21T12:00:00Z")["shadow_direction"] == "N"
