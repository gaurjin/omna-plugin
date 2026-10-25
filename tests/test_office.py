"""Word and Excel files are masked inside and stay Word and Excel files (MASTER #160).

The files are built here by hand so every byte is known. All values are fake.
Stand-ins are matched by pattern, never typed whole (see CLAUDE.md, "Token
literals: two pieces").
"""

from __future__ import annotations

import io
import re
import zipfile

from omna_plugin import office
from omna_plugin.engine import MaskingSession
from omna_plugin.pipeline import Pipeline

EMAIL = "jane.doe@example.com"
EMAIL2 = "bob.smith@example.org"
TOKEN = "ghp_" + "fgYFNmLOZlhOWtmhi0EwWcTCEsLvKQdOrH3k"
SSN = "123-45-6789"
STAND_IN = re.compile(r"\[[A-Z_]+_\d+\]")

W = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'
MC = ('xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006" '
      'xmlns:w14="http://schemas.microsoft.com/office/word/2010/wordml" mc:Ignorable="w14"')

DOCUMENT = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
    f'<w:document {W} {MC}><w:body>'
    # the email split over two runs, the second one bold
    '<w:p w14:paraId="1A2B3C4D"><w:r><w:t xml:space="preserve">Write to jane.doe@</w:t></w:r>'
    '<w:r><w:rPr><w:b/></w:rPr><w:t>example.com</w:t></w:r><w:r><w:t xml:space="preserve"> today.</w:t></w:r></w:p>'
    # a tab separates a label from a value
    f'<w:p><w:r><w:t>SSN</w:t></w:r><w:r><w:tab/></w:r><w:r><w:t>{SSN}</w:t></w:r></w:p>'
    # an ampersand must stay escaped; nothing to mask here
    '<w:p><w:r><w:t>Smith &amp; Sons, Q3 plan</w:t></w:r></w:p>'
    # tracked change by a named author
    f'<w:p><w:ins w:id="1" w:author="{EMAIL2}" w:date="2026-10-25T00:00:00Z"><w:r><w:t>key {TOKEN}</w:t></w:r></w:ins></w:p>'
    '<w:sectPr/></w:body></w:document>'
)
HEADER = f'<?xml version="1.0" encoding="UTF-8"?><w:hdr {W}><w:p><w:r><w:t>Contact {EMAIL2}</w:t></w:r></w:p></w:hdr>'
STYLES = f'<?xml version="1.0" encoding="UTF-8"?><w:styles {W}><w:style w:styleId="Normal"/></w:styles>'
CORE = ('<?xml version="1.0" encoding="UTF-8"?><cp:coreProperties '
        'xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
        'xmlns:dc="http://purl.org/dc/elements/1.1/">'
        f'<dc:creator>{EMAIL}</dc:creator><dc:title>Plan</dc:title></cp:coreProperties>')
PNG = b"\x89PNG\r\n\x1a\n" + bytes(range(256))


def zip_of(parts: dict[str, bytes | str], stored: tuple[str, ...] = ()) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, body in parts.items():
            data = body.encode("utf-8") if isinstance(body, str) else body
            z.writestr(name, data, compress_type=zipfile.ZIP_STORED if name in stored else zipfile.ZIP_DEFLATED)
    return buf.getvalue()


def docx() -> bytes:
    return zip_of({
        "[Content_Types].xml": '<?xml version="1.0"?><Types/>',
        "word/document.xml": DOCUMENT,
        "word/header1.xml": HEADER,
        "word/styles.xml": STYLES,
        "word/media/image1.png": PNG,
        "docProps/core.xml": CORE,
    }, stored=("word/media/image1.png",))


SHARED = ('<?xml version="1.0" encoding="UTF-8"?><sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="4" uniqueCount="4">'
          '<si><t>Email</t></si>'
          f'<si><t>{EMAIL}</t></si>'
          # rich text: the email split over two formatted runs, plus a phonetic guide
          '<si><r><t>bob.smith@</t></r><r><rPr><b/></rPr><t>example.org</t></r><rPh sb="0" eb="1"><t>ボブ</t></rPh></si>'
          '<si><t>Total</t></si></sst>')
SHEET = ('<?xml version="1.0" encoding="UTF-8"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>'
         '<row r="1"><c r="A1" t="s"><v>0</v></c><c r="B1" t="s"><v>3</v></c></row>'
         '<row r="2"><c r="A2" t="s"><v>1</v></c><c r="B2" s="1"><v>42</v></c></row>'
         '<row r="3"><c r="A3" t="s"><v>2</v></c><c r="B3"><f>SUM(B2:B2)</f><v>42</v></c></row>'
         f'<row r="4"><c r="A4" t="inlineStr"><is><t>ssn {SSN}</t></is></c><c r="B4"><v>4155550134</v></c></row>'
         '</sheetData></worksheet>')


def xlsx() -> bytes:
    return zip_of({
        "[Content_Types].xml": '<?xml version="1.0"?><Types/>',
        "xl/workbook.xml": '<?xml version="1.0"?><workbook/>',
        "xl/sharedStrings.xml": SHARED,
        "xl/worksheets/sheet1.xml": SHEET,
        "xl/styles.xml": '<?xml version="1.0"?><styleSheet/>',
    })


def pipeline() -> Pipeline:
    return Pipeline(MaskingSession())


def parts(data: bytes) -> dict[str, bytes]:
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        return {i.filename: z.read(i) for i in z.infolist()}


def infos(data: bytes) -> list[tuple[str, int]]:
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        return [(i.filename, i.compress_type) for i in z.infolist()]


def test_kind_is_decided_by_the_bytes():
    assert office.kind(docx()) == "docx"
    assert office.kind(xlsx()) == "xlsx"
    assert office.kind(b"PK\x03\x04not really a zip") is None
    assert office.kind(zip_of({"a.txt": "hi"})) is None
    assert office.kind(PNG) is None


def test_word_file_stays_a_word_file_and_nothing_real_is_left(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    original = docx()
    masked, stats = pipeline().mask_file(original, "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
    assert masked != original
    assert office.kind(masked) == "docx"
    out = parts(masked)
    everything = b"".join(out.values()).decode("utf-8", "replace")
    for real in (EMAIL, EMAIL2, TOKEN, SSN, "jane.doe@"):
        assert real not in everything, real
    assert stats.pii >= 3 and stats.secrets >= 1
    # same parts, same order, same compression; untouched parts byte-identical
    assert infos(masked) == infos(original)
    before = parts(original)
    for name in ("[Content_Types].xml", "word/styles.xml", "word/media/image1.png"):
        assert out[name] == before[name], name


def test_word_markup_around_the_text_is_kept_byte_for_byte(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    doc = parts(pipeline().mask_file(docx(), "")[0])["word/document.xml"].decode()
    # Word refuses a file whose mc:Ignorable prefixes are not declared: the
    # opening tag must come through exactly.
    assert f'<w:document {W} {MC}>' in doc
    assert '<w14:paraId' not in doc and 'w14:paraId="1A2B3C4D"' in doc
    # the split email: the stand-in sits in the first run, the bold run is empty,
    # and the paragraph still reads correctly
    first = re.search(r'<w:p w14:paraId="1A2B3C4D">(.*?)</w:p>', doc).group(1)
    texts = re.findall(r"<w:t[^>]*>([^<]*)</w:t>", first)
    assert re.fullmatch(r"Write to \[EMAIL_\d+\] today\.", "".join(texts)), texts
    assert "<w:b/>" in first
    # the tab is still there, the label is not masked, the escaped & stays escaped
    assert "<w:t>SSN</w:t></w:r><w:r><w:tab/></w:r>" in doc
    assert "Smith &amp; Sons, Q3 plan" in doc
    # the variable name stays with the secret, and the author is masked
    assert re.search(r"<w:t>key \[[A-Z_]+_\d+\]</w:t>", doc)
    assert re.search(r'w:author="\[EMAIL_\d+\]"', doc)


def test_word_header_and_document_properties_are_masked(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    out = parts(pipeline().mask_file(docx(), "")[0])
    assert re.search(rb"Contact \[EMAIL_\d+\]", out["word/header1.xml"])
    assert re.search(rb"<dc:creator>\[EMAIL_\d+\]</dc:creator>", out["docProps/core.xml"])
    assert b"<dc:title>Plan</dc:title>" in out["docProps/core.xml"]


def test_same_value_gets_the_same_stand_in_in_every_part(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    out = parts(pipeline().mask_file(docx(), "")[0])
    header = re.search(rb"Contact (\[EMAIL_\d+\])", out["word/header1.xml"]).group(1)
    author = re.search(rb'w:author="(\[EMAIL_\d+\])"', out["word/document.xml"]).group(1)
    assert header == author


def test_excel_file_stays_an_excel_file(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    original = xlsx()
    masked, stats = pipeline().mask_file(original, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
    assert office.kind(masked) == "xlsx"
    assert infos(masked) == infos(original)
    out = parts(masked)
    shared = out["xl/sharedStrings.xml"].decode()
    sheet = out["xl/worksheets/sheet1.xml"].decode()
    for real in (EMAIL, "bob.smith@", SSN):
        assert real not in shared + sheet, real
    assert "<si><t>Email</t></si>" in shared and "<si><t>Total</t></si>" in shared
    # the phonetic guide is not the person's text and is left alone
    assert '<rPh sb="0" eb="1"><t>ボブ</t></rPh>' in shared
    # rich text keeps both formatted runs
    assert re.search(r"<si><r><t>\[EMAIL_\d+\]</t></r><r><rPr><b/></rPr><t></t></r>", shared), shared
    assert re.search(r'<c r="A4" t="inlineStr"><is><t>ssn \[[A-Z_]+_\d+\]</t></is></c>', sheet)
    # plain numbers and formula cells are untouched
    assert '<c r="B2" s="1"><v>42</v></c>' in sheet
    assert '<c r="B3"><f>SUM(B2:B2)</f><v>42</v></c>' in sheet
    assert out["xl/styles.xml"] == parts(original)["xl/styles.xml"]
    assert stats.pii >= 3


def test_a_phone_number_stored_as_a_number_becomes_a_text_cell(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    sheet = parts(pipeline().mask_file(xlsx(), "")[0])["xl/worksheets/sheet1.xml"].decode()
    assert "4155550134" not in sheet
    assert re.search(r'<c r="B4" t="inlineStr"><is><t>\[PHONE_\d+\]</t></is></c>', sheet), sheet


def test_nothing_to_mask_gives_back_the_very_same_bytes(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    clean = zip_of({"word/document.xml": f'<w:document {W}><w:body><w:p><w:r><w:t>Hello there</w:t></w:r></w:p></w:body></w:document>'})
    masked, stats = pipeline().mask_file(clean, "")
    assert masked is clean or masked == clean
    assert stats.pii == 0 and stats.secrets == 0


def test_a_broken_office_file_goes_through_as_before(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    good = docx()
    broken = good[: len(good) // 2]
    masked, stats = pipeline().mask_file(broken, "")
    assert masked == broken
    assert stats.pii == 0


def test_a_value_with_spaces_at_its_edge_keeps_them(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    doc = (f'<w:document {W}><w:body><w:p><w:r><w:t>Mail</w:t></w:r>'
           f'<w:r><w:t xml:space="preserve"> {EMAIL} </w:t></w:r><w:r><w:t>now</w:t></w:r></w:p></w:body></w:document>')
    out = parts(pipeline().mask_file(zip_of({"word/document.xml": doc}), "")[0])["word/document.xml"].decode()
    assert re.search(r'<w:t xml:space="preserve"> \[EMAIL_\d+\] </w:t>', out), out


def test_spread_always_joins_back_to_the_masked_text():
    cases = [
        (["Write to jane.doe@", "example.com", " today."], "Write to [EMAIL_" "1] today."),
        (["a", "b", "c"], "abc"),
        (["Call ", "555-", "0134", " now"], "Call [PHONE_" "1] now"),
        (["x"], "y"),
        (["key ", "abc"], "key "),
    ]
    for pieces, masked in cases:
        out = office._spread(pieces, masked)
        assert "".join(out) == masked, (pieces, out)
        assert len(out) == len(pieces)


# --- OpenDocument (LibreOffice) and RTF, MASTER #160 step 3 ---

ODF_NS = ('xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" '
          'xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" '
          'xmlns:table="urn:oasis:names:tc:opendocument:xmlns:table:1.0" '
          'xmlns:calcext="urn:org:documentfoundation:names:experimental:calc:xmlns:calcext:1.0"')
ODT_CONTENT = ('<?xml version="1.0" encoding="UTF-8"?>'
               f'<office:document-content {ODF_NS}><office:body><office:text>'
               # the email split by a bold span, and a space element
               '<text:p text:style-name="P1">Write to jane.doe@<text:span text:style-name="B">example.com</text:span><text:s/>today.</text:p>'
               f'<text:h text:outline-level="1">SSN {SSN}</text:h>'
               '<text:p>Smith &amp; Sons<text:tab/>Q3 plan</text:p>'
               '</office:text></office:body></office:document-content>')
ODT_STYLES = (f'<?xml version="1.0" encoding="UTF-8"?><office:document-styles {ODF_NS}><office:master-styles>'
              f'<text:p>Footer {EMAIL2}</text:p></office:master-styles></office:document-styles>')
ODF_META = ('<?xml version="1.0" encoding="UTF-8"?><office:document-meta xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" '
            'xmlns:meta="urn:oasis:names:tc:opendocument:xmlns:meta:1.0" xmlns:dc="http://purl.org/dc/elements/1.1/">'
            f'<office:meta><meta:initial-creator>{EMAIL}</meta:initial-creator><dc:title>Plan</dc:title></office:meta></office:document-meta>')
ODS_CONTENT = ('<?xml version="1.0" encoding="UTF-8"?>'
               f'<office:document-content {ODF_NS}><office:body><office:spreadsheet><table:table table:name="Sheet1">'
               f'<table:table-row><table:table-cell office:value-type="string" calcext:value-type="string"><text:p>{EMAIL}</text:p></table:table-cell>'
               '<table:table-cell office:value-type="float" office:value="4155550134" calcext:value-type="float"><text:p>4155550134</text:p></table:table-cell>'
               '<table:table-cell office:value-type="float" office:value="42" calcext:value-type="float"><text:p>42</text:p></table:table-cell>'
               '<table:table-cell table:formula="of:=[.B1]" office:value-type="float" office:value="4155550134"><text:p>4155550134</text:p></table:table-cell>'
               '</table:table-row></table:table></office:spreadsheet></office:body></office:document-content>')


def odf(mime: str, content: str) -> bytes:
    # The OpenDocument rule: "mimetype" first and stored (not compressed).
    return zip_of({"mimetype": mime, "content.xml": content, "styles.xml": ODT_STYLES, "meta.xml": ODF_META,
                   "Pictures/p.png": PNG}, stored=("mimetype", "Pictures/p.png"))


def test_opendocument_text_stays_odt_and_nothing_real_is_left(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    original = odf("application/vnd.oasis.opendocument.text", ODT_CONTENT)
    assert office.kind(original) == "odt"
    masked, stats = pipeline().mask_file(original, "application/vnd.oasis.opendocument.text")
    assert office.kind(masked) == "odt"
    assert infos(masked) == infos(original)          # mimetype still first and stored
    assert infos(masked)[0] == ("mimetype", zipfile.ZIP_STORED)
    out = parts(masked)
    everything = b"".join(out.values()).decode("utf-8", "replace")
    for real in (EMAIL, EMAIL2, SSN, "jane.doe@"):
        assert real not in everything, real
    content = out["content.xml"].decode()
    p1 = re.search(r'<text:p text:style-name="P1">(.*?)</text:p>', content).group(1)
    assert re.fullmatch(r'Write to \[EMAIL_\d+\]<text:span text:style-name="B"></text:span><text:s/>today\.', p1), p1
    assert "Smith &amp; Sons<text:tab/>Q3 plan" in content
    assert re.search(rb"Footer \[EMAIL_\d+\]", out["styles.xml"])
    assert re.search(rb"<meta:initial-creator>\[EMAIL_\d+\]</meta:initial-creator>", out["meta.xml"])
    assert b"<dc:title>Plan</dc:title>" in out["meta.xml"]
    assert out["Pictures/p.png"] == PNG
    assert stats.pii >= 3


def test_opendocument_spreadsheet_number_cell_becomes_text(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    original = odf("application/vnd.oasis.opendocument.spreadsheet", ODS_CONTENT)
    assert office.kind(original) == "ods"
    content = parts(pipeline().mask_file(original, "")[0])["content.xml"].decode()
    assert EMAIL not in content
    # the phone stored as a number: now a text cell holding the stand-in, the number gone
    assert re.search(r'<table:table-cell office:value-type="string" calcext:value-type="string"><text:p>\[PHONE_\d+\]</text:p></table:table-cell>', content), content
    assert 'office:value="4155550134"' in content and content.count("4155550134") == 1   # only the formula cell's cached value
    assert '<table:table-cell office:value-type="float" office:value="42" calcext:value-type="float"><text:p>42</text:p>' in content


def test_rtf_is_masked_and_stays_rtf(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    rtf = (r"{\rtf1\ansi\deff0 {\fonttbl {\f0 Helvetica;}}" "\n"
           r"\f0\fs24 Customer (test only): " + EMAIL + r"\par" "\n"
           r"Phone 555-123-4567\par" "\n}").encode()
    masked, stats = pipeline().mask_file(rtf, "application/rtf")
    assert masked.startswith(rb"{\rtf1\ansi\deff0 {\fonttbl {\f0 Helvetica;}}")
    assert EMAIL.encode() not in masked and b"555-123-4567" not in masked
    assert masked.rstrip().endswith(b"}") and stats.pii >= 2


def test_files_the_curl_command_cannot_mask_are_labelled(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    pptx = zip_of({"[Content_Types].xml": "<Types/>", "ppt/presentation.xml": "<p/>"})
    cases = {b"%PDF-1.7\n" + EMAIL.encode(): "pdf",
             b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 50: "old-office",
             PNG: "image", b"\xff\xd8\xff\xe0" + b"\x00" * 20: "image", pptx: "pptx"}
    for data, kind in cases.items():
        masked, stats = pipeline().mask_file(data, "")
        assert masked == data and stats.not_masked == kind, kind
    plain, stats = pipeline().mask_file(b"hello there\n", "text/plain")
    assert stats.not_masked == ""


def test_rtf_value_split_by_formatting_and_mac_paragraphs(tmp_path, monkeypatch):
    # Exactly what macOS TextEdit writes when half the address is bold: the
    # address split by \f1\b, paragraphs ended by a backslash + line break.
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    rtf = ("{\\rtf1\\ansi\\ansicpg1252\\cocoartf2907\n{\\fonttbl\\f0\\froman\\fcharset0 Times-Roman;\\f1\\froman\\fcharset0 Times-Bold;}\n"
           "{\\colortbl;\\red255\\green255\\blue255;}\n{\\*\\expandedcolortbl;;}\n\\pard\\pardeftab720\n\n"
           "\\f0\\fs24 \\cf0 Customer record (test only)\\\nEmail: jane.doe@\n\\f1\\b example.com\\\n\n"
           "\\f0\\b0 Phone: 555-123-4567\\\nJos\\'e9 M\\u252?ller, 123-45-6789\\\n}").encode("latin-1")
    masked, stats = pipeline().mask_file(rtf, "")
    text = masked.decode("latin-1")
    for real in ("jane.doe@", "example.com", "555-123-4567", "123-45-6789"):
        assert real not in text, real
    assert re.search(r"Email: \[EMAIL_\d+\]\n\\f1\\b \\\n", text), text
    assert re.search(r"\\f0\\b0 Phone: \[PHONE_\d+\]\\\n", text), text
    assert "{\\fonttbl\\f0\\froman\\fcharset0 Times-Roman;" in text          # header tables untouched
    # accents survive: the rewritten piece reads "José Müller" (RTF may spell a letter two valid ways)
    assert any("José Müller, " in t for u in office._rtf_units(text) for _, _, t in u)
    assert office.mask_rtf(rtf, lambda t: t) == rtf                         # nothing to mask -> same bytes


def test_unchanged_parts_are_copied_byte_for_byte_even_compressed(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    original = docx()
    masked, _ = pipeline().mask_file(original, "")
    with zipfile.ZipFile(io.BytesIO(original)) as a, zipfile.ZipFile(io.BytesIO(masked)) as b:
        assert b.testzip() is None
        for name in ("word/styles.xml", "word/media/image1.png", "[Content_Types].xml"):
            assert office._raw_entry(masked, b.getinfo(name)) == office._raw_entry(original, a.getinfo(name)), name
            assert b.getinfo(name).date_time == a.getinfo(name).date_time
