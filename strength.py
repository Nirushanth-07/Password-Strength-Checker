"""Password strength analysis engine.

Pure logic with no UI code; shared by the grey terminal GUI and the CLI.

Checks performed:
  * composition   - length and character classes (lower/upper/digit/symbol/unicode)
  * pool entropy  - E = L * log2(R), the classic brute-force estimate
  * shannon       - entropy of the actual character distribution
  * patterns      - common passwords, dictionary words (incl. leetspeak),
                    sequences, repeats, keyboard walks, dates and years
  * effective     - pattern-aware entropy: the cheapest way an attacker could
                    cover the password with patterns + brute force
  * crack time    - estimated for online and offline attack scenarios
  * breaches      - Have I Been Pwned, via k-anonymity (only 5 hash chars sent)
"""

import hashlib
import math
import re
from collections import Counter
from dataclasses import dataclass
from urllib.request import Request, urlopen

from wordlists import COMMON_PASSWORDS, COMMON_WORDS

BANNER = r"""
*************************************
*        PASSWORD CHECKER v2.0      *
*************************************
                 _
               _|_|_
               (o o)
           ooO--(_)--Ooo
"""

HIBP_URL = "https://api.pwnedpasswords.com/range/"

MIN_LENGTH = 8           # NIST SP 800-63B minimum
RECOMMENDED_LENGTH = 12

# Upper bound (bits) of each tier -- same thresholds as v1.0, now applied to
# the pattern-aware effective entropy instead of the raw pool entropy.
TIERS = [
    (32, "Very Weak", "bad"),
    (56, "Weak", "bad"),
    (81, "Medium", "warn"),
    (112, "Strong", "good"),
    (math.inf, "Excellent", "good"),
]

ATTACK_SCENARIOS = [
    ("online, throttled (100/hour)", 100 / 3600),
    ("online, unthrottled (10/sec)", 10),
    ("offline, slow hash (10k/sec)", 1e4),
    ("offline, fast hash (10B/sec)", 1e10),
]

POOL_SIZES = {"lowercase": 26, "uppercase": 26, "digits": 10, "symbols": 33, "unicode": 100}

DICT_RANKS = {}
for _rank, _word in enumerate(COMMON_PASSWORDS + COMMON_WORDS, start=1):
    DICT_RANKS.setdefault(_word, _rank)

# Two leetspeak normalisations, since "1" and "|" can stand for "i" or "l".
LEET_I = str.maketrans("4@31!|0$57+", "aaeiiiosstt")
LEET_L = str.maketrans("4@31!|0$57+", "aaelilosstt")

KEYBOARD_ROWS = ["`1234567890-=", "qwertyuiop[]\\", "asdfghjkl;'", "zxcvbnm,./"]
ROW_OFFSETS = [0.0, 1.5, 1.75, 2.25]  # physical stagger of each row, in key widths
SHIFTED = str.maketrans('~!@#$%^&*()_+{}|:"<>?', "`1234567890-=[]\\;',./")
KEY_POS = {
    key: (row, col + ROW_OFFSETS[row])
    for row, keys in enumerate(KEYBOARD_ROWS)
    for col, key in enumerate(keys)
}

DAY_MONTH_YEAR_RE = re.compile(r"(?<!\d)(\d{1,2})[-/._]?(\d{1,2})[-/._]?((?:19|20)\d{2})(?!\d)")
YEAR_MONTH_DAY_RE = re.compile(r"(?<!\d)((?:19|20)\d{2})[-/._]?(\d{1,2})[-/._]?(\d{1,2})(?!\d)")
YEAR_RE = re.compile(r"(?:19|20)\d{2}")
REPEAT_RE = re.compile(r"(.+?)\1+", re.DOTALL)

MAX_DICT_SCAN = 64  # dictionary scan is O(n^2); cap it for very long inputs


@dataclass
class Match:
    kind: str
    start: int
    end: int  # exclusive
    token: str
    bits: float
    detail: str


@dataclass
class Analysis:
    length: int
    classes: dict
    pool_size: int
    pool_entropy: float
    shannon_per_char: float
    unique_chars: int
    effective_entropy: float
    patterns: list
    is_common: bool
    crack_times: list
    score: int
    tier: str
    tier_style: str
    warnings: list
    suggestions: list


# ---------------------------------------------------------------- composition

def character_classes(text):
    return {
        "lowercase": any("a" <= c <= "z" for c in text),
        "uppercase": any("A" <= c <= "Z" for c in text),
        "digits": any("0" <= c <= "9" for c in text),
        "symbols": any(c.isascii() and not c.isalnum() for c in text),
        "unicode": any(not c.isascii() for c in text),
    }


def pool_size(text):
    return sum(POOL_SIZES[name] for name, found in character_classes(text).items() if found)


def shannon_entropy(text):
    """Bits per character, based on how often each character actually occurs."""
    n = len(text)
    if not n:
        return 0.0
    return -sum(k / n * math.log2(k / n) for k in Counter(text).values())


# ------------------------------------------------------------------- patterns

def _case_bits(token):
    letters = [c for c in token if c.isalpha()]
    if not letters or all(c.islower() for c in letters):
        return 0.0
    if all(c.isupper() for c in letters):
        return 1.0
    if letters[0].isupper() and all(c.islower() for c in letters[1:]):
        return 1.0
    return 2.0


def dictionary_matches(password):
    matches = []
    n = min(len(password), MAX_DICT_SCAN)
    for i in range(n):
        for j in range(i + 3, n + 1):
            whole = i == 0 and j == len(password)
            if j - i < 4 and not whole:
                continue
            token = password[i:j]
            lower = token.lower()
            best = None
            for candidate in {lower, lower.translate(LEET_I), lower.translate(LEET_L)}:
                rank = DICT_RANKS.get(candidate)
                if rank is not None and (best is None or rank < best[0]):
                    best = (rank, candidate != lower)
            if best is None:
                continue
            rank, leet = best
            is_password = rank <= len(COMMON_PASSWORDS)
            detail = f"common password #{rank}" if is_password else "dictionary word"
            if leet:
                detail += " (leetspeak)"
            bits = math.log2(rank + 1) + _case_bits(token) + (1.0 if leet else 0.0)
            matches.append(Match("dictionary", i, j, token, bits, detail))
    return matches


def _seq_class(c):
    if "a" <= c <= "z":
        return "lower"
    if "A" <= c <= "Z":
        return "upper"
    if "0" <= c <= "9":
        return "digit"
    return None


def sequence_matches(password):
    """Runs like abc, 987, XYZ."""
    matches = []
    n = len(password)
    i = 0
    while i < n - 2:
        cls = _seq_class(password[i])
        delta = ord(password[i + 1]) - ord(password[i])
        if cls is None or delta not in (1, -1) or _seq_class(password[i + 1]) != cls:
            i += 1
            continue
        j = i + 1
        while (j + 1 < n and _seq_class(password[j + 1]) == cls
               and ord(password[j + 1]) - ord(password[j]) == delta):
            j += 1
        if j - i + 1 < 3:
            i += 1
            continue
        token = password[i:j + 1]
        space = 10 if cls == "digit" else 26
        bits = math.log2(space) + math.log2(len(token)) + (1.0 if delta < 0 else 0.0)
        direction = "descending" if delta < 0 else "ascending"
        matches.append(Match("sequence", i, j + 1, token, bits, f"{direction} sequence"))
        i = j
    return matches


def repeat_matches(password):
    """Repeated characters or chunks like aaaa, abcabc."""
    matches = []
    for i in range(len(password)):
        m = REPEAT_RE.match(password, i)
        if not m or len(m.group(0)) < 3:
            continue
        token, base = m.group(0), m.group(1)
        count = len(token) // len(base)
        bits = len(base) * math.log2(pool_size(base)) + math.log2(count)
        matches.append(Match("repeat", m.start(), m.end(), token, bits, f"chunk of {len(base)} repeated {count}x"))
    return matches


def _adjacent(a, b):
    pa, pb = KEY_POS.get(a), KEY_POS.get(b)
    if pa is None or pb is None or a == b:
        return False
    dy, dx = abs(pa[0] - pb[0]), abs(pa[1] - pb[1])
    return (dy == 0 and dx == 1) or (dy == 1 and dx <= 0.75)


def _direction(a, b):
    (ya, xa), (yb, xb) = KEY_POS[a], KEY_POS[b]
    return yb - ya, (xb > xa) - (xb < xa)


def keyboard_matches(password):
    """Walks across adjacent keys like qwerty, asdf, 1qaz, zxcvbn."""
    norm = password.lower().translate(SHIFTED)
    matches = []
    n = len(norm)
    i = 0
    while i < n - 1:
        j = i
        while j + 1 < n and _adjacent(norm[j], norm[j + 1]):
            j += 1
        if j - i + 1 < 4:
            i += 1
            continue
        token = password[i:j + 1]
        directions = [_direction(norm[k], norm[k + 1]) for k in range(i, j)]
        turns = sum(1 for a, b in zip(directions, directions[1:]) if a != b)
        shifted = token != norm[i:j + 1]
        bits = math.log2(len(KEY_POS) * 2) + turns * 3 + math.log2(len(token)) + (1.0 if shifted else 0.0)
        detail = "keyboard walk" if turns == 0 else f"keyboard walk, {turns} turn(s)"
        matches.append(Match("keyboard", i, j + 1, token, bits, detail))
        i = j
    return matches


def date_matches(password):
    matches = []
    for m in DAY_MONTH_YEAR_RE.finditer(password):
        a, b = int(m.group(1)), int(m.group(2))
        if 1 <= a <= 31 and 1 <= b <= 31 and min(a, b) <= 12:
            matches.append(Match("date", m.start(), m.end(), m.group(0), math.log2(31 * 12 * 120), "calendar date"))
    for m in YEAR_MONTH_DAY_RE.finditer(password):
        a, b = int(m.group(2)), int(m.group(3))
        if 1 <= a <= 31 and 1 <= b <= 31 and min(a, b) <= 12:
            matches.append(Match("date", m.start(), m.end(), m.group(0), math.log2(31 * 12 * 120), "calendar date"))
    for m in YEAR_RE.finditer(password):
        matches.append(Match("date", m.start(), m.end(), m.group(0), math.log2(120), "year"))
    return matches


def find_patterns(password):
    return (dictionary_matches(password) + sequence_matches(password) + repeat_matches(password)
            + keyboard_matches(password) + date_matches(password))


def effective_entropy(password, matches, char_bits):
    """Minimum bits needed to cover the password with patterns or brute-forced chars.

    Returns (bits, patterns actually used on that cheapest path).
    """
    n = len(password)
    best = [0.0] + [math.inf] * n
    back = [None] * (n + 1)
    by_end = {}
    for m in matches:
        by_end.setdefault(m.end, []).append(m)
    for i in range(1, n + 1):
        best[i] = best[i - 1] + char_bits
        for m in by_end.get(i, ()):
            cost = best[m.start] + m.bits
            if cost < best[i]:
                best[i], back[i] = cost, m
    used = []
    i = n
    while i > 0:
        if back[i] is None:
            i -= 1
        else:
            used.append(back[i])
            i = back[i].start
    used.reverse()
    return best[n], used


# ------------------------------------------------------------------ crack time

def crack_seconds(bits, guesses_per_second):
    # On average an attacker finds the password after searching half the space.
    return 2 ** min(bits, 1000) / 2 / guesses_per_second


def format_duration(seconds):
    if seconds < 1:
        return "instantly"
    units = [("second", 60), ("minute", 60), ("hour", 24), ("day", 30.44), ("month", 12)]
    value = seconds
    for name, size in units:
        if value < size:
            value = round(value)
            return f"{value} {name}{'s' if value != 1 else ''}"
        value /= size
    years = value
    if years >= 1e10:
        return "longer than the age of the universe"
    if years >= 1e6:
        return f"{years / 1e6:,.0f} million years"
    years = round(years)
    return f"{years:,} year{'s' if years != 1 else ''}"


# -------------------------------------------------------------------- analysis

def _tier_for(bits):
    for index, (limit, name, style) in enumerate(TIERS):
        if bits < limit:
            return index
    return len(TIERS) - 1


def analyze(password):
    length = len(password)
    classes = character_classes(password)
    pool = pool_size(password)
    char_bits = math.log2(pool) if pool else 0.0
    pool_bits = length * char_bits

    matches = find_patterns(password)
    bits, used = effective_entropy(password, matches, char_bits)
    bits = min(bits, pool_bits)
    kinds = {m.kind for m in used}

    lower = password.lower()
    is_common = any(
        DICT_RANKS.get(candidate, math.inf) <= len(COMMON_PASSWORDS)
        for candidate in (lower, lower.translate(LEET_I), lower.translate(LEET_L))
    )

    tier_index = _tier_for(bits)
    score = round(min(bits, 112) / 112 * 100)
    if length < MIN_LENGTH:
        tier_index = min(tier_index, 1)
        score = min(score, 30)
    if is_common:
        tier_index = 0
        score = min(score, 5)
    _, tier, tier_style = TIERS[tier_index]

    warnings, suggestions = [], []
    if is_common:
        warnings.append("This is one of the most commonly used passwords.")
    if length < MIN_LENGTH:
        warnings.append(f"Shorter than {MIN_LENGTH} characters (NIST minimum).")
        suggestions.append(f"Use at least {RECOMMENDED_LENGTH} characters; length beats complexity.")
    elif length < RECOMMENDED_LENGTH:
        suggestions.append(f"Go for {RECOMMENDED_LENGTH}+ characters, or a passphrase of 4+ random words.")
    if "dictionary" in kinds and not is_common:
        warnings.append("Contains common words or names.")
    if any("leetspeak" in m.detail for m in used):
        warnings.append("Leetspeak swaps (p@ssw0rd) are the first thing crackers try.")
    if "sequence" in kinds:
        warnings.append("Contains a sequence like abc or 123.")
    if "repeat" in kinds:
        warnings.append("Contains repeated characters or chunks.")
    if "keyboard" in kinds:
        warnings.append("Contains a keyboard pattern like qwerty or 1qaz.")
    if "date" in kinds:
        warnings.append("Contains a date or year, which are easy to guess.")
    if length >= 6 and len(set(password)) <= length / 2:
        warnings.append(f"Low variety: only {len(set(password))} unique characters.")
    missing = [name for name in ("lowercase", "uppercase", "digits", "symbols") if not classes[name]]
    if missing and bits < TIERS[2][0]:
        suggestions.append("Add more character types: " + ", ".join(missing) + ".")
    if kinds:
        suggestions.append("Replace predictable parts with random words or characters.")
    suggestions.append("Use a password manager, keep it unique per site, and enable 2FA.")

    crack_times = [(label, crack_seconds(bits, rate)) for label, rate in ATTACK_SCENARIOS]

    return Analysis(
        length=length,
        classes=classes,
        pool_size=pool,
        pool_entropy=pool_bits,
        shannon_per_char=shannon_entropy(password),
        unique_chars=len(set(password)),
        effective_entropy=bits,
        patterns=used,
        is_common=is_common,
        crack_times=crack_times,
        score=score,
        tier=tier,
        tier_style=tier_style,
        warnings=warnings,
        suggestions=suggestions,
    )


# -------------------------------------------------------------------- breaches

def check_breach(password, timeout=8):
    """Query Have I Been Pwned using k-anonymity.

    Only the first 5 hex chars of the SHA-1 hash leave this machine.
    Returns (count, error): count is 0 if not found, None if the lookup failed.
    """
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]
    request = Request(HIBP_URL + prefix, headers={
        "User-Agent": "Password-Strength-Checker",
        "Add-Padding": "true",  # pads the response so its size leaks nothing
    })
    try:
        with urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8")
    except OSError as e:
        return None, str(getattr(e, "reason", e))
    for line in body.splitlines():
        hash_suffix, _, count = line.partition(":")
        if hash_suffix.strip() == suffix:
            return int(count), None
    return 0, None


# ---------------------------------------------------------------------- report

REPORT_WIDTH = 64
BAR_CELLS = 32


def _section(title):
    return [(f"── {title} " + "─" * max(REPORT_WIDTH - len(title) - 4, 0), "head")]


def _row(label, value, style=None, note=""):
    line = [(f"  {label} ".ljust(34, "."), "dim"), (f" {value}", style)]
    if note:
        line.append((f"  {note}", "dim"))
    return line


def _time_style(seconds):
    if seconds < 86400:
        return "bad"
    if seconds < 100 * 365 * 86400:
        return "warn"
    return "good"


def build_report(analysis, breach=None, reveal=False, breach_hint="not checked"):
    """Render an Analysis as lines of (text, style) segments.

    breach: None (not checked), "checking", or the (count, error) tuple from check_breach.
    reveal: show matched password fragments instead of their positions.
    Styles: None, "dim", "head", "title", "good", "warn", "bad".
    """
    a = analysis
    tier, tier_style, score = a.tier, a.tier_style, a.score
    breached = isinstance(breach, tuple) and breach[0]
    if breached:
        tier, tier_style, score = TIERS[0][1], "bad", min(score, 5)

    filled = round(score / 100 * BAR_CELLS)
    lines = [
        [(" VERDICT ", "title"), ("  ", None), (tier.upper(), tier_style)],
        [("█" * filled, tier_style), ("░" * (BAR_CELLS - filled), "dim"), (f"  {score}/100", tier_style)],
        [],
    ]

    lines.append(_section("Composition"))
    if a.length >= RECOMMENDED_LENGTH:
        length_style, length_note = "good", "✔ 12+ recommended"
    elif a.length >= MIN_LENGTH:
        length_style, length_note = "warn", "! 12+ recommended"
    else:
        length_style, length_note = "bad", "✖ below 8 minimum"
    lines.append(_row("length", str(a.length), length_style, length_note))
    for name in ("lowercase", "uppercase", "digits", "symbols"):
        found = a.classes[name]
        lines.append(_row(name, "✔ found" if found else "✖ not found", "good" if found else "bad"))
    if a.classes["unicode"]:
        lines.append(_row("unicode", "✔ found", "good"))
    lines.append([])

    lines.append(_section("Entropy"))
    lines.append(_row("pool entropy  L×log2(R)", f"{a.pool_entropy:.1f} bits", None, f"R={a.pool_size}"))
    lines.append(_row("shannon entropy", f"{a.shannon_per_char:.2f} bits/char", None,
                      f"{a.unique_chars} unique chars"))
    lines.append(_row("effective entropy", f"{a.effective_entropy:.1f} bits", tier_style, "after pattern analysis"))
    lines.append([])

    lines.append(_section("Patterns"))
    if not a.patterns:
        lines.append([("  ✔ no predictable patterns detected", "good")])
    for m in a.patterns:
        where = f'"{m.token}"' if reveal else f"chars {m.start + 1}-{m.end}"
        lines.append([("  ✖ ", "bad"), (f"{m.kind:<11}", "warn"), (f"{where}  ", None),
                      (f"{m.detail}, ~{m.bits:.1f} bits", "dim")])
    lines.append([])

    lines.append(_section("Estimated time to crack"))
    for label, seconds in a.crack_times:
        lines.append(_row(label, format_duration(seconds), _time_style(seconds)))
    lines.append([])

    lines.append(_section("Breach check (Have I Been Pwned)"))
    if breach is None:
        lines.append([(f"  {breach_hint}", "dim")])
    elif breach == "checking":
        lines.append([("  querying api.pwnedpasswords.com ...", "warn")])
    else:
        count, error = breach
        if error:
            lines.append([(f"  ! lookup failed: {error}", "warn")])
        elif count:
            lines.append([(f"  ✖ seen {count:,} times in data breaches. Do not use it!", "bad")])
        else:
            lines.append([("  ✔ not found in any known data breach", "good")])
    lines.append([])

    warnings = list(a.warnings)
    if breached:
        warnings.insert(0, "Appears in known data breaches; attackers already have it.")
    if warnings or a.suggestions:
        lines.append(_section("Feedback"))
        lines.extend([("  ✖ ", "bad"), (w, None)] for w in warnings)
        lines.extend([("  » ", "warn"), (s, "dim")] for s in a.suggestions)
    return lines
