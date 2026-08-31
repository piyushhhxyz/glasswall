from pii_redactor.docx_io import Document, apply


def test_flatten_joins_runs_split_mid_name(make_docx):
    path = make_docx(["Ravi Mohan Sharma"], split_runs=True)
    para = Document(path).paragraphs()[0]
    assert len(para.nodes) > 1, "fixture should be multi-run"
    assert para.text == "Ravi Mohan Sharma"


def test_replacement_spanning_runs_round_trips(make_docx, tmp_path):
    path = make_docx(["Ravi Mohan Sharma is a director"], split_runs=True)
    doc = Document(path)
    para = doc.paragraphs()[0]
    apply(para, [(0, 17, "Aaron Whitfield")])
    out = doc.save(tmp_path / "out.docx")
    assert Document(out).paragraphs()[0].text == "Aaron Whitfield is a director"


def test_multiple_edits_in_one_paragraph(make_docx, tmp_path):
    path = make_docx(["Call Rohan Dey on 9876543210 today"], split_runs=True)
    doc = Document(path)
    para = doc.paragraphs()[0]
    apply(para, [(5, 14, "Peter Parker"), (18, 28, "1112223334")])
    out = doc.save(tmp_path / "out.docx")
    assert Document(out).paragraphs()[0].text == "Call Peter Parker on 1112223334 today"


def test_untouched_paragraph_is_left_alone(make_docx, tmp_path):
    path = make_docx(["nothing to redact here"])
    doc = Document(path)
    out = doc.save(tmp_path / "out.docx")
    assert Document(out).paragraphs()[0].text == "nothing to redact here"


def test_package_parts_are_preserved(make_docx, tmp_path):
    import zipfile
    path = make_docx(["Ravi Sharma"], split_runs=True)
    out = Document(path).save(tmp_path / "out.docx")
    assert set(zipfile.ZipFile(path).namelist()) == set(zipfile.ZipFile(out).namelist())
