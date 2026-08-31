from pii_redactor.docx_io import Document
from pii_redactor.model import PiiType
from pii_redactor.pipeline import redact
from pii_redactor.policy import Policy

SAMPLE = [
    "Contact Person: Rashi Patil",
    "Rashi Patil is our Company Secretary and Compliance Officer.",
    "Email: rashhi.patil@acmewidgets.com Telephone: +91 20 45053237",
    "Acme Widgets Limited is regulated by the Securities and Exchange Board of India.",
    "Up to 26,704,570 Equity Shares of face value of Rs 5 each.",
]


def test_end_to_end_replaces_pii_and_keeps_the_rest(make_docx, tmp_path):
    result = redact(make_docx(SAMPLE, split_runs=True), tmp_path / "out.docx")
    text = "\n".join(p.text for p in Document(result.output).paragraphs())

    for secret in ["Rashi", "Patil", "rashhi.patil", "acmewidgets", "45053237", "Acme Widgets"]:
        assert secret not in text, f"{secret} leaked"
    # Institutions and financial substance are deliberately out of scope.
    assert "Securities and Exchange Board of India" in text
    assert "26,704,570 Equity Shares" in text


def test_the_same_person_gets_the_same_surrogate_everywhere(make_docx, tmp_path):
    result = redact(make_docx(SAMPLE, split_runs=True), tmp_path / "out.docx")
    people = {d.replacement for d in result.detections if d.span.type is PiiType.PERSON}
    assert len(people) == 1, people


def test_runs_are_reproducible(make_docx, tmp_path):
    source = make_docx(SAMPLE, split_runs=True)
    a = redact(source, tmp_path / "a.docx")
    b = redact(source, tmp_path / "b.docx")
    assert [d.replacement for d in a.detections] == [d.replacement for d in b.detections]


def test_policy_can_disable_a_type(make_docx, tmp_path):
    policy = Policy(enabled={PiiType.EMAIL})
    result = redact(make_docx(SAMPLE, split_runs=True), tmp_path / "out.docx", policy=policy)
    assert {d.span.type for d in result.detections} == {PiiType.EMAIL}
