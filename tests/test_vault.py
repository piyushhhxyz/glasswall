import pytest

from pii_redactor.detectors import luhn, verhoeff
from pii_redactor.model import PiiType as T
from pii_redactor.vault import Vault, _brand_key


@pytest.fixture
def vault():
    return Vault(surnames={"sharma", "kulkarni"},
                 org_keys=[_brand_key("Acme Industries"), _brand_key("Bluecrest Capital")])


def test_same_input_same_surrogate(vault):
    assert vault.person("Ravi Sharma") == vault.person("Ravi Sharma")


def test_deterministic_across_instances():
    a, b = Vault(surnames={"sharma"}), Vault(surnames={"sharma"})
    assert a.person("Ravi Sharma") == b.person("Ravi Sharma")


def test_secret_changes_the_mapping():
    a = Vault(surnames={"sharma"}).person("Ravi Sharma")
    b = Vault(secret=b"other", surnames={"sharma"}).person("Ravi Sharma")
    assert a != b


def test_family_surname_is_shared(vault):
    first, second = vault.person("Ravi Sharma"), vault.person("Vikram Sharma")
    assert first.split()[-1] == second.split()[-1], "family structure must survive"
    assert first.split()[0] != second.split()[0]


def test_bare_surname_matches_the_full_name(vault):
    assert vault.person("Sharma") == vault.person("Ravi Sharma").split()[-1]


def test_case_style_is_preserved(vault):
    assert vault.person("RAVI SHARMA") == vault.person("Ravi Sharma").upper()


def test_surrogates_are_injective(vault):
    names = ["Ravi Sharma", "Vikram Sharma", "Rohit Sharma", "Indu Jacob", "Ram Tiwari"]
    assert len({vault.person(n) for n in names}) == len(names)


def test_organisation_and_its_domain_share_a_brand(vault):
    org = vault.org("Acme Industries Limited")
    url = vault.url("www.acmeindustries.com")
    assert org.split()[0].lower() in url


def test_domain_typo_folds_onto_the_same_brand(vault):
    correct = vault.email("a@acmeindustries.com").split("@")[1]
    typo = vault.email("b@acmeindsutries.com").split("@")[1]
    assert correct == typo


def test_legal_suffix_survives(vault):
    assert vault.org("Waterloo Industrial Park VI Private Limited").endswith("Private Limited")


def test_phone_keeps_shape_and_country_code(vault):
    out = vault.phone("+ 91 20 45053237")
    assert out.startswith("+ 91 ") and out != "+ 91 20 45053237"
    assert [c.isdigit() for c in out] == [c.isdigit() for c in "+ 91 20 45053237"]


def test_numeric_surrogates_satisfy_their_own_validators(vault):
    assert luhn(vault.credit_card("4539 1488 0343 6467"))
    assert verhoeff(vault.aadhaar("2345 6789 0123"))
    assert all(0 <= int(o) <= 255 for o in vault.ip("192.168.11.7").split("."))


def test_din_keeps_eight_digits(vault):
    assert vault.din("00135070").isdigit() and len(vault.din("00135070")) == 8
