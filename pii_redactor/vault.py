"""Deterministic, injective surrogate generation.

Three properties matter more than realism, because the output is training data
for RL environments rather than a document for a human to skim:

* **Consistent** -- one real entity maps to exactly one surrogate, everywhere,
  across runs. Keyed by HMAC over a canonical form, so `RAVI MOHAN SHARMA`,
  `Ravi Sharma` and a bare `Sharma` all land on the same fake identity.
* **Injective** -- two different entities never collapse onto the same surrogate.
  Collisions are resolved by linear probing, so relational structure ("these two
  signatories are different people") survives redaction.
* **Structure-preserving** -- surnames map as a unit, so the promoter family stays
  a family; formats survive, so a phone still looks like a phone and a CIN still
  parses as a CIN. An agent trained on the output learns the same shape of task.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass, field

from .model import PiiType

DEFAULT_SECRET = b"pii-redactor/v1"

GIVEN_NAMES = [
    "Aaron", "Beatrice", "Caleb", "Delia", "Elias", "Farah", "Gideon", "Helena", "Isaac",
    "Juno", "Kieran", "Liora", "Malcolm", "Nadia", "Oscar", "Priya", "Quentin", "Rosalind",
    "Silas", "Tamsin", "Ulric", "Verity", "Wendell", "Xanthe", "Yusuf", "Zora", "Amara",
    "Bram", "Cecily", "Dorian", "Esme", "Felix", "Greta", "Hugo", "Ingrid", "Jasper",
    "Karina", "Leonel", "Mira", "Noor", "Otto", "Pearl", "Rafael", "Sonia", "Tobias",
    "Ursula", "Viktor", "Wilhelmina", "Yara", "Zane",
    "Anders", "Bianca", "Cyrus", "Danika", "Emmett", "Fionn", "Galen", "Hester",
    "Ilias", "Josephine", "Kasper", "Lucian", "Marisol", "Nikolai", "Odette", "Piers",
    "Rhiannon", "Soren", "Thea", "Umberto", "Vivienne", "Wren", "Xavier", "Yolanda",
    "Zerlina", "Alaric", "Brigid", "Casimir", "Dagny", "Evander", "Freya", "Gaspard",
    "Hollis", "Isolde", "Jerome", "Katarina", "Lorcan", "Magnus", "Nerissa", "Osric",
    "Paloma", "Roscoe", "Saoirse", "Thaddeus", "Ulrika", "Valentin", "Winifred",
]
SURNAMES = [
    "Whitfield", "Marchetti", "Okonkwo", "Lindqvist", "Ferreira", "Nakamura", "Delacroix",
    "Vasquez", "Thornbury", "Ashworth", "Bellamy", "Castellan", "Draycott", "Ellingham",
    "Fairholm", "Grimsby", "Hollingsworth", "Ivanescu", "Jarnvid", "Kensington", "Lockhart",
    "Merriweather", "Norbury", "Oakhurst", "Pemberton", "Quillon", "Ravensworth", "Stallard",
    "Tremaine", "Underhill", "Vandermeer", "Wexford", "Yarrowby", "Zabriskie", "Ashgrove",
    "Brackenridge", "Colefax", "Duxbury", "Everleigh", "Fenwick",
    "Garrowby", "Hathersage", "Inglethorpe", "Jerningham", "Kirkbride", "Langmere",
    "Mortlake", "Netherwood", "Orlingbury", "Pallister", "Quenington", "Rothbury",
    "Selworthy", "Tarrington", "Ulverston", "Vanbrugh", "Warkworth", "Yelverton",
    "Zouchbury", "Alderney", "Bickerstaff", "Cathcart", "Dunwoodie", "Ellersby",
    "Fothergill", "Gainsborough", "Haverfield", "Illingworth", "Jephcott", "Kilbride",
    "Lanthorne", "Mainwaring", "Northcote", "Ormerod", "Prendergast", "Rackham",
    "Sandiford", "Thorneycroft", "Umfraville", "Verinder", "Wollaston", "Yatesbury",
]
ORG_CORES = [
    "Northwind", "Ravenscroft", "Blue Harbour", "Ironvale", "Silverbeck", "Kestrel",
    "Alderstone", "Meridian Works", "Copperline", "Windermere", "Falconridge", "Stonebridge",
    "Larkspur", "Highmoor", "Thistledown", "Brightwater", "Ambervale", "Fernhollow",
    "Greyfriars", "Oakenshield", "Redstone", "Saltmarsh", "Tallowick", "Umberfield",
    "Verdantis", "Westerly", "Yewbank", "Zephyrus", "Cobblestone", "Duskmere",
]
ORG_QUALIFIERS = ["Components", "Systems", "Holdings", "Industries", "Logistics", "Partners",
                  "Metals", "Dynamics", "Assembly", "Networks", "Foundry", "Traders"]
_ORG_BRANDS = [f"{core} {q}" for core in ORG_CORES for q in ORG_QUALIFIERS]

PLACES = [
    "Ashcombe", "Bellhaven", "Cranmoor", "Dellwick", "Elmsford", "Fairhollow", "Grangeby",
    "Harrowdene", "Ilminster", "Jarrowfield", "Kelsbury", "Lynwood", "Marbury", "Netherby",
    "Oldstead", "Penhurst", "Quenby", "Rushmere", "Stanbrook", "Thurloe", "Uppingham",
    "Vellacourt", "Wardley", "Yeoville", "Zennor", "Ambleside", "Brackley", "Corsham",
    "Dunwich", "Erdington", "Fordwich", "Gorsley", "Hambledon", "Inkberrow", "Jevington",
]

STREETS = ["Alder Street", "Bramble Lane", "Cedar Rise", "Dunmore Road", "Elmfield Way",
           "Fenlow Avenue", "Garrick Road", "Hazelmere Path", "Ironmonger Row", "Juniper Close"]
LOCALITIES = ["Ashvale", "Brookmere", "Calderton", "Dunhaven", "Eastmoor", "Fairbourne",
              "Glenmoor", "Havenwood", "Inglewood", "Jessamine Park"]
CITIES = ["Marlborough", "Northgate", "Oakbury", "Pinehurst", "Quarrytown", "Redhaven"]
REGIONS = ["Westmarch", "Eastvale", "Northshire", "Southcliff"]
LOCALPART_WORDS = ["contact", "info", "desk", "office", "queries", "support", "relations"]


def _index(secret: bytes, namespace: str, key: str, modulus: int) -> int:
    digest = hmac.new(secret, f"{namespace}\x00{key}".encode(), hashlib.sha256).digest()
    return int.from_bytes(digest[:8], "big") % modulus


def _match_case(source: str, replacement: str) -> str:
    if source.isupper():
        return replacement.upper()
    if source.islower():
        return replacement.lower()
    return replacement


def canonical(text: str) -> str:
    """Fold the surface variation that dirty extraction introduces."""
    return re.sub(r"[^a-z0-9]+", " ", text.lower()).strip()


def _brand_key(text: str) -> str:
    """Collapse a company name to a domain-comparable token: `Acme Industries` -> `acmeindustries`."""
    return re.sub(r"[^a-z0-9]+", "", text.lower())


def _reshape(template: str, digits: str) -> str:
    """Write `digits` back into the punctuation layout of `template`."""
    out, i = [], 0
    for ch in template:
        if ch.isdigit():
            out.append(digits[i] if i < len(digits) else "0")
            i += 1
        else:
            out.append(ch)
    return "".join(out)


def _luhn_ok(d: str) -> bool:
    total, parity = 0, len(d) % 2
    for i, ch in enumerate(d):
        n = int(ch)
        if i % 2 == parity:
            n = n * 2 - 9 if n * 2 > 9 else n * 2
        total += n
    return total % 10 == 0


def _verhoeff_ok(d: str) -> bool:
    from .detectors import verhoeff
    return verhoeff(d)


def _edit_distance(a: str, b: str) -> int:
    if abs(len(a) - len(b)) > 2:
        return 99
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


@dataclass
class Vault:
    """Assigns and remembers surrogates. `mapping` doubles as the audit log."""

    secret: bytes = DEFAULT_SECRET
    surnames: set[str] = field(default_factory=set)
    mapping: dict[tuple[str, str], str] = field(default_factory=dict)
    org_keys: list[str] = field(default_factory=list)
    _taken: dict[str, set[str]] = field(default_factory=dict)
    _domains: list[str] = field(default_factory=list)

    # -- core allocation ---------------------------------------------------- #

    def _allocate(self, namespace: str, key: str, pool: list[str]) -> str:
        """Pick a pool entry for `key`, probing forward to stay injective."""
        cached = self.mapping.get((namespace, key))
        if cached is not None:
            return cached
        used = self._taken.setdefault(namespace, set())
        start = _index(self.secret, namespace, key, len(pool))
        for offset in range(len(pool)):
            candidate = pool[(start + offset) % len(pool)]
            if candidate not in used:
                break
        else:  # pool exhausted: suffix a stable discriminator
            candidate = f"{pool[start]}-{_index(self.secret, namespace + '#', key, 9999):04d}"
        used.add(candidate)
        self.mapping[(namespace, key)] = candidate
        return candidate

    def _digits(self, key: str, length: int, first: str = "") -> str:
        raw = hmac.new(self.secret, key.encode(), hashlib.sha256).hexdigest()
        digits = "".join(c for c in str(int(raw[:24], 16)))
        return (first + digits.ljust(length, "0"))[:length]

    # -- per-type surrogates ------------------------------------------------ #

    def person(self, text: str) -> str:
        """Map name *tokens*, so every surface variant stays mutually consistent."""
        parts = re.split(r"(\W+)", text)
        out = []
        for part in parts:
            low = part.lower().strip(".")
            if not part.isalpha() or len(part) < 3:
                out.append(part)
                continue
            if low in {"mr", "mrs", "ms", "dr", "shri", "smt", "sri", "prof"}:
                out.append(part)
                continue
            pool = SURNAMES if low in self.surnames else GIVEN_NAMES
            namespace = "surname" if low in self.surnames else "given"
            out.append(_match_case(part, self._allocate(namespace, low, pool)))
        return "".join(out)

    _SUFFIX = re.compile(
        r"\s+(Private\s+Limited|Family\s+Trust|Limited|Ltd\.?|LLP|Inc\.?|Corporation|Corp\.?|Trust|Co\.?)$",
        re.I,
    )

    def org(self, text: str) -> str:
        suffix_match = self._SUFFIX.search(text.strip())
        suffix = suffix_match.group(0) if suffix_match else ""
        core_key = _brand_key(text[: suffix_match.start()] if suffix_match else text)
        return _match_case(text, f"{self._org_brand(core_key)}{suffix}")

    def _org_brand(self, core_key: str) -> str:
        """Allocate from the core x qualifier product, so ~360 brands are available."""
        return self._allocate("org", core_key, _ORG_BRANDS)

    def domain(self, text: str) -> str:
        """Fold near-duplicate domains (typos, injected spaces) onto one surrogate."""
        clean = re.sub(r"\s+", "", text).lower().lstrip(".")
        host, _, tld = clean.rpartition(".")
        # Fold typos onto the first spelling we saw ("acmeindsutries" -> "acmeindustries").
        for known in self._domains:
            if _edit_distance(host, known) <= 2:
                host = known
                break
        else:
            self._domains.append(host)
        brand = self._org_brand(self._brand_of(host))
        return f"{brand.lower().replace(' ', '-')}.{tld or 'example'}"

    def _brand_of(self, host: str) -> str:
        """Tie a domain to the organisation it belongs to, so both share a surrogate.

        `org_keys` are suffix-stripped brand keys, matching what `org()` allocates on --
        "Acme Industries Limited" and "acmeindustries.com" therefore agree. Longest
        match wins, so "kshinfra" cannot capture a domain belonging to "ksh".
        """
        for key in sorted(self.org_keys, key=len, reverse=True):
            if key and (key.startswith(host) or host.startswith(key)):
                return key
        return host

    def email(self, text: str) -> str:
        local, _, domain = re.sub(r"\s+", "", text).partition("@")
        tokens = re.split(r"([._\-])", local)
        rebuilt = []
        for token in tokens:
            if token in "._-" or not token:
                rebuilt.append(token)
            elif token.lower() in self.surnames or len(token) > 2 and token.isalpha():
                rebuilt.append(_match_case(token, self.person(token) if token.isalpha() else token))
            else:
                rebuilt.append(self._allocate("localpart", token.lower(), LOCALPART_WORDS))
        return f"{''.join(rebuilt)}@{self.domain(domain)}"

    _EMBEDDED_HOST = re.compile(r"\b[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}\b")

    def url(self, text: str) -> str:
        m = re.match(r"(https?://)?(www\s*\.\s*)?(.+?)(/.*)?$", text.strip(), re.S)
        scheme, www, host, path = m.group(1) or "", m.group(2) or "", m.group(3), m.group(4) or ""
        # Query strings smuggle real hosts through: ".../s/abc?domain=bluecrest.com".
        path = self._EMBEDDED_HOST.sub(lambda h: self.domain(h.group(0)), path)
        return f"{scheme}{'www.' if www else ''}{self.domain(host)}{path}"

    def ip(self, text: str) -> str:
        if ":" in text:
            return self.generic_id(text, "IPV6")
        key = f"ip:{canonical(text)}"
        octets = [str(_index(self.secret, f"oct{i}", key, 254) + 1) for i in range(4)]
        return ".".join(octets)

    def credit_card(self, text: str) -> str:
        """Emit a Luhn-valid surrogate so downstream validators still fire."""
        digits = re.sub(r"\D", "", text)
        body = self._digits(f"cc:{canonical(text)}", len(digits) - 1, first="4")
        for check in "0123456789":
            if _luhn_ok(body + check):
                break
        return _reshape(text, body + check)

    def aadhaar(self, text: str) -> str:
        """Emit a Verhoeff-valid surrogate for the same reason."""
        body = self._digits(f"aadhaar:{canonical(text)}", 11, first="7")
        for check in "0123456789":
            if _verhoeff_ok(body + check):
                break
        return _reshape(text, body + check)

    def phone(self, text: str) -> str:
        """Keep the country code and the exact punctuation; replace subscriber digits."""
        key = canonical(text)
        pool = self._digits(f"phone:{key}", 12)
        out, taken = [], 0
        digits = re.sub(r"\D", "", text)
        cc_len = 2 if digits.startswith("91") else 0
        position = 0
        for ch in text:
            if ch.isdigit():
                if position < cc_len:
                    out.append(ch)
                else:
                    out.append(pool[taken % len(pool)])
                    taken += 1
                position += 1
            else:
                out.append(ch)
        return "".join(out)

    def address(self, text: str) -> str:
        key = canonical(text)
        n = _index(self.secret, "addr", key, 9000) + 100
        street = STREETS[_index(self.secret, "street", key, len(STREETS))]
        locality = LOCALITIES[_index(self.secret, "loc", key, len(LOCALITIES))]
        city = CITIES[_index(self.secret, "city", key, len(CITIES))]
        region = REGIONS[_index(self.secret, "region", key, len(REGIONS))]
        pin = self._digits(f"pin:{key}", 6, first="4")
        built = f"{n % 900 + 1}, {street}, {locality}, {city} – {pin[:3]} {pin[3:]}, {region}, Elbonia"
        return _match_case(text, built) if text.isupper() else built

    def id_document(self, text: str) -> str:
        """A field lifted off an ID scan. Numbers keep their shape; words become names."""
        stripped = text.strip()
        # Anything carrying a digit is an identifier -- a PAN, an Aadhaar, a date --
        # and must go through the shape-preserving path. `person()` only rewrites
        # alphabetic tokens, so it would hand "ABCDE1234F" straight back.
        if any(c.isdigit() for c in stripped):
            return self.generic_id(stripped, "IDDOC")
        return self.person(stripped) if any(c.isalpha() for c in stripped) else stripped

    def place(self, text: str) -> str:
        """A single locality word, mapped consistently wherever it appears."""
        return _match_case(text, self._allocate("place", canonical(text), PLACES))

    def sebi_regn(self, text: str) -> str:
        """Keep the `IN<category><9 digits>` shape so the value still parses as one."""
        category = SURNAMES[_index(self.secret, "sebicat", text, len(SURNAMES))][0]
        return f"IN{category}{self._digits('sebi:' + canonical(text), 9)}"

    def din(self, text: str) -> str:
        return self._digits(f"din:{canonical(text)}", 8, first="0")

    def cin(self, text: str) -> str:
        d = self._digits(f"cin:{canonical(text)}", 15)
        return f"{text[0]}{d[:5]}XX{d[5:9]}PLC{d[9:15]}"

    def pan(self, text: str) -> str:
        letters = "".join(SURNAMES[_index(self.secret, f"pan{i}", text, len(SURNAMES))][0] for i in range(5))
        return f"{letters}{self._digits('pan:' + text, 4)}Z"

    def generic_id(self, text: str, kind: str) -> str:
        """Format-preserving fallback: keep the shape, swap the payload."""
        out, key = [], f"{kind}:{canonical(text)}"
        pool = self._digits(key, 20)
        letters = "".join(SURNAMES[_index(self.secret, f"{kind}{i}", text, len(SURNAMES))][0] for i in range(8))
        di = li = 0
        for ch in text:
            if ch.isdigit():
                out.append(pool[di % len(pool)]); di += 1
            elif ch.isalpha():
                out.append(_match_case(ch, letters[li % len(letters)])); li += 1
            else:
                out.append(ch)
        return "".join(out)

    def date(self, text: str) -> str:
        """Shift a date by a stable offset; keeps chronology roughly intact."""
        shift = _index(self.secret, "dob", canonical(text), 900) - 450
        def bump(m):
            value = int(m.group(0))
            return str(value + shift // 365) if len(m.group(0)) == 4 else str((value + shift) % 28 + 1)
        return re.sub(r"\d+", bump, text)

    # -- dispatch ----------------------------------------------------------- #

    def surrogate(self, pii_type: PiiType, text: str) -> str:
        handler = {
            PiiType.PERSON: self.person,
            PiiType.ORG: self.org,
            PiiType.EMAIL: self.email,
            PiiType.URL: self.url,
            PiiType.PHONE: self.phone,
            PiiType.ADDRESS: self.address,
            PiiType.DIN: self.din,
            PiiType.CIN: self.cin,
            PiiType.PAN: self.pan,
            PiiType.DOB: self.date,
            PiiType.IP: self.ip,
            PiiType.CREDIT_CARD: self.credit_card,
            PiiType.AADHAAR: self.aadhaar,
            PiiType.LOCATION: self.place,
            PiiType.ID_DOCUMENT: self.id_document,
            PiiType.REG_NUMBER: lambda t: self.generic_id(t, "REG"),
            PiiType.SEBI_REGN: self.sebi_regn,
        }.get(pii_type)
        if handler:
            return handler(text)
        return self.generic_id(text, pii_type.value)
